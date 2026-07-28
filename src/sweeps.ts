/**
 * Phase 5 — scheduled sweeps.
 *
 * Shape: cron tick → find due sweeps → open a run → enqueue ONE message per
 * account. Never one giant job. Each queue message processes a single account
 * and, if that account has more work than fits in one invocation, re-enqueues
 * itself carrying a cursor. That gives resumability without a Durable Object
 * and keeps every invocation comfortably inside CPU limits.
 *
 * Sweeps in this phase are READ-ONLY: they observe and record findings. Nothing
 * here sends, deletes, or reshares. Write-capable sweeps are a deliberate
 * later decision, not an accident of this design.
 */

import { Env, json, err, now, randomId, audit } from './util';
import { TokenManager } from './vault';
import { clientFor, gmailSearch, driveRecent } from './google';
import { resolveAccounts } from './fanout';
import type { Principal } from './users';

const DRIVE = 'https://www.googleapis.com/drive/v3';

export type SweepKind = 'mail_digest' | 'drive_digest' | 'share_audit';

export const SWEEP_KINDS: Record<SweepKind, { label: string; surface: 'gmail' | 'drive'; describe: string }> = {
  mail_digest: {
    label: 'Mail digest',
    surface: 'gmail',
    describe: 'Messages matching a Gmail query, per mailbox',
  },
  drive_digest: {
    label: 'Drive digest',
    surface: 'drive',
    describe: 'Recently modified files, per Drive',
  },
  share_audit: {
    label: 'Stale share audit',
    surface: 'drive',
    describe: 'Files readable by anyone with the link',
  },
};

export interface SweepMessage {
  run_id: string;
  sweep_id: string;
  account_id: string;
  kind: SweepKind;
  config: Record<string, any>;
  cursor?: string | null;
  page: number;
}

/* ------------------------------------------------------------------ */
/* CRUD                                                                */
/* ------------------------------------------------------------------ */

export async function listSweeps(env: Env, allowed: string[] | null): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT s.*, (SELECT COUNT(*) FROM sweep_runs r WHERE r.sweep_id = s.sweep_id) AS runs
       FROM sweeps s ORDER BY s.created_at DESC`
  ).all<any>();
  const runs = await env.DB.prepare(
    `SELECT * FROM sweep_runs ORDER BY started_at DESC LIMIT 20`
  ).all<any>();
  return json({
    kinds: Object.entries(SWEEP_KINDS).map(([id, v]) => ({ id, ...v })),
    sweeps: (results ?? []).map((s) => ({ ...s, config: safeParse(s.config) })),
    recent_runs: runs.results ?? [],
  });
}

const safeParse = (s: string) => {
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
};

export async function createSweep(
  request: Request,
  env: Env,
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as any;
  const kind: SweepKind = b.kind;
  if (!SWEEP_KINDS[kind]) return err(`kind must be one of ${Object.keys(SWEEP_KINDS).join(', ')}`, 400);
  if (typeof b.name !== 'string' || !b.name) return err('name is required', 400);

  const interval = Math.max(15, parseInt(b.interval_minutes ?? '60', 10));
  const config = {
    interval_minutes: interval,
    query: b.query ?? (kind === 'mail_digest' ? 'in:inbox newer_than:1d' : null),
    limit: Math.min(50, parseInt(b.limit ?? '20', 10)),
    max_pages: Math.min(5, parseInt(b.max_pages ?? '2', 10)),
  };

  const id = randomId('swp', 12);
  const ts = now();
  await env.DB.prepare(
    `INSERT INTO sweeps (sweep_id, name, kind, cron, account_filter, config, enabled, last_run_at, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`
  )
    .bind(
      id,
      b.name,
      kind,
      `every ${interval}m`,
      allowed != null ? allowed.join(',') || 'none' : b.account_filter ?? '*',
      JSON.stringify(config),
      b.enabled === false ? 0 : 1,
      ts,
      ts
    )
    .run();

  await audit(env, { actor: me.email, action: 'sweep.create', target: b.name, detail: { id, kind } });
  return json({ ok: true, sweep_id: id, kind, config }, 201);
}

export async function deleteSweep(env: Env, id: string, actor: string): Promise<Response> {
  await env.DB.prepare(`DELETE FROM sweeps WHERE sweep_id = ?`).bind(id).run();
  await audit(env, { actor, action: 'sweep.delete', target: id });
  return json({ ok: true });
}

export async function sweepFindings(
  env: Env,
  runId: string,
  allowed: string[] | null
): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT * FROM sweep_findings WHERE run_id = ? ORDER BY id DESC LIMIT 300`
  )
    .bind(runId)
    .all<any>();
  const set = allowed == null ? null : new Set(allowed);
  const findings = (results ?? []).filter((f) => set == null || set.has(f.account_id));
  return json({ run_id: runId, count: findings.length, findings });
}

/* ------------------------------------------------------------------ */
/* dispatch                                                            */
/* ------------------------------------------------------------------ */

export async function startRun(
  env: Env,
  sweepId: string,
  trigger: string,
  allowed: string[] | null = null
): Promise<any> {
  const sweep = await env.DB.prepare(`SELECT * FROM sweeps WHERE sweep_id = ?`)
    .bind(sweepId)
    .first<any>();
  if (!sweep) throw Object.assign(new Error('unknown sweep'), { status: 404 });

  const config = safeParse(sweep.config);
  const surface = SWEEP_KINDS[sweep.kind as SweepKind].surface;
  const accounts = await resolveAccounts(env, sweep.account_filter, surface, allowed);

  const runId = randomId('run', 12);
  const ts = now();
  await env.DB.prepare(
    `INSERT INTO sweep_runs (run_id, sweep_id, started_at, finished_at, status,
                             accounts_total, accounts_ok, accounts_failed, items_processed, error)
     VALUES (?, ?, ?, NULL, 'running', ?, 0, 0, 0, NULL)`
  )
    .bind(runId, sweepId, ts, accounts.length)
    .run();
  await env.DB.prepare(`UPDATE sweeps SET last_run_at = ?, updated_at = ? WHERE sweep_id = ?`)
    .bind(ts, ts, sweepId)
    .run();

  if (!accounts.length) {
    await env.DB.prepare(
      `UPDATE sweep_runs SET status='completed', finished_at=? WHERE run_id=?`
    )
      .bind(ts, runId)
      .run();
    return { run_id: runId, accounts: 0, note: 'no accounts matched the filter' };
  }

  // One message per account. Never one giant job.
  await env.SWEEP_QUEUE.sendBatch(
    accounts.map((a) => ({
      body: {
        run_id: runId,
        sweep_id: sweepId,
        account_id: a.account_id,
        kind: sweep.kind,
        config,
        cursor: null,
        page: 1,
      } as SweepMessage,
    }))
  );

  await audit(env, {
    actor: trigger,
    action: 'sweep.run',
    target: sweep.name,
    detail: { run_id: runId, accounts: accounts.length },
  });

  return { run_id: runId, accounts: accounts.length, kind: sweep.kind };
}

/** Cron tick — run every sweep whose interval has elapsed. */
export async function runDueSweeps(env: Env): Promise<void> {
  const { results } = await env.DB.prepare(`SELECT * FROM sweeps WHERE enabled = 1`).all<any>();
  const ts = now();
  for (const s of results ?? []) {
    const cfg = safeParse(s.config);
    const interval = (cfg.interval_minutes ?? 60) * 60;
    if (s.last_run_at && s.last_run_at + interval > ts) continue;
    try {
      await startRun(env, s.sweep_id, 'cron');
    } catch (e) {
      console.error('sweep_dispatch_failed', s.sweep_id, String(e));
    }
  }
}

/* ------------------------------------------------------------------ */
/* queue consumer — one account per message                            */
/* ------------------------------------------------------------------ */

async function recordFindings(
  env: Env,
  runId: string,
  accountId: string,
  items: Array<{ kind: string; title: string; url?: string | null; detail?: unknown }>
) {
  if (!items.length) return;
  const ts = now();
  const stmt = env.DB.prepare(
    `INSERT INTO sweep_findings (run_id, account_id, kind, title, url, detail, ts)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  );
  await env.DB.batch(
    items.map((i) =>
      stmt.bind(runId, accountId, i.kind, i.title, i.url ?? null, JSON.stringify(i.detail ?? null), ts)
    )
  );
}

export async function processSweepMessage(env: Env, msg: SweepMessage): Promise<void> {
  const tm = new TokenManager(env);
  const client = clientFor(env, tm, msg.account_id);
  const cfg = msg.config ?? {};
  const limit = Math.min(50, cfg.limit ?? 20);

  let items: Array<{ kind: string; title: string; url?: string | null; detail?: unknown }> = [];
  let nextCursor: string | null = null;

  if (msg.kind === 'mail_digest') {
    const hits = await gmailSearch(client, cfg.query || 'in:inbox newer_than:1d', limit);
    items = hits.map((h) => ({
      kind: 'mail',
      title: h.subject,
      url: h.webUrl,
      detail: { from: h.from, date: h.date, snippet: h.snippet.slice(0, 200) },
    }));
  } else if (msg.kind === 'drive_digest') {
    const files = await driveRecent(client, limit);
    items = files.map((f) => ({
      kind: 'file',
      title: f.name,
      url: f.webUrl,
      detail: { mimeType: f.mimeType, modifiedTime: f.modifiedTime, owners: f.owners },
    }));
  } else if (msg.kind === 'share_audit') {
    const pageParam = msg.cursor ? `&pageToken=${encodeURIComponent(msg.cursor)}` : '';
    const res = await client.getJson<any>(
      `${DRIVE}/files?q=${encodeURIComponent("visibility = 'anyoneWithLink' and trashed = false")}` +
        `&pageSize=${limit}${pageParam}&supportsAllDrives=true&includeItemsFromAllDrives=true` +
        `&fields=${encodeURIComponent('nextPageToken,files(id,name,mimeType,modifiedTime,webViewLink)')}`
    );
    items = (res.files ?? []).map((f: any) => ({
      kind: 'public_file',
      title: f.name,
      url: f.webViewLink,
      detail: { id: f.id, mimeType: f.mimeType, modifiedTime: f.modifiedTime },
    }));
    if (res.nextPageToken && msg.page < (cfg.max_pages ?? 2)) nextCursor = res.nextPageToken;
  }

  await recordFindings(env, msg.run_id, msg.account_id, items);

  await env.DB.prepare(
    `UPDATE sweep_runs SET items_processed = items_processed + ? WHERE run_id = ?`
  )
    .bind(items.length, msg.run_id)
    .run();

  // Self-continuation: more pages for this account, same run.
  if (nextCursor) {
    await env.SWEEP_QUEUE.send({ ...msg, cursor: nextCursor, page: msg.page + 1 } as SweepMessage);
    return;
  }

  await env.DB.prepare(`UPDATE sweep_runs SET accounts_ok = accounts_ok + 1 WHERE run_id = ?`)
    .bind(msg.run_id)
    .run();
  await maybeFinish(env, msg.run_id);
}

export async function failSweepMessage(env: Env, msg: SweepMessage, error: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE sweep_runs SET accounts_failed = accounts_failed + 1, error = COALESCE(error,'') || ? WHERE run_id = ?`
  )
    .bind(`[${msg.account_id}] ${error.slice(0, 160)}; `, msg.run_id)
    .run();
  await audit(env, {
    actor: 'sweep',
    account_id: msg.account_id,
    action: 'sweep.account',
    outcome: 'failed',
    detail: { run_id: msg.run_id, error: error.slice(0, 300) },
  });
  await maybeFinish(env, msg.run_id);
}

async function maybeFinish(env: Env, runId: string): Promise<void> {
  const r = await env.DB.prepare(
    `SELECT accounts_total, accounts_ok, accounts_failed FROM sweep_runs WHERE run_id = ?`
  )
    .bind(runId)
    .first<any>();
  if (!r) return;
  if (r.accounts_ok + r.accounts_failed >= r.accounts_total) {
    await env.DB.prepare(
      `UPDATE sweep_runs SET status = ?, finished_at = ? WHERE run_id = ? AND finished_at IS NULL`
    )
      .bind(r.accounts_failed ? 'completed_with_errors' : 'completed', now(), runId)
      .run();
  }
}

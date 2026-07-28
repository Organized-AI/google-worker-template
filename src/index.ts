/**
 * google-orchestrator — multi-account Google fan-out on Cloudflare Workers.
 *
 * Phases 0-6: foundation, token vault + consent, account registry,
 * read/search fan-out, write actions (dry-run by default), scheduled sweeps,
 * per-user identity with role and per-account scoping.
 */

import {
  Env,
  json,
  err,
  now,
  randomId,
  audit,
  principal,
  makeSession,
  sessionCookieHeader,
  clearCookieHeader,
  b64url,
  SessionPayload,
} from './util';
import { TokenManager, ReauthRequired, VaultError } from './vault';
import {
  CAPS,
  GOOGLE_AUTH_URL,
  GOOGLE_TOKEN_URL,
  USERINFO_URL,
  scopesForCaps,
  capsFromScopes,
  clientFor,
  gmailSearch,
  gmailProfile,
  driveSearch,
  driveRecent,
  driveAbout,
} from './google';
import { fanout, resolveAccounts } from './fanout';
import { handleMailWrite, handleDriveCopy, handleDrivePermissions } from './writes';
import {
  listSweeps,
  createSweep,
  deleteSweep,
  startRun,
  runDueSweeps,
  processSweepMessage,
  failSweepMessage,
  sweepFindings,
  SweepMessage,
} from './sweeps';
import {
  Principal,
  atLeast,
  isOwnerOnlyRoute,
  isWriteRoute,
  loadUser,
  allowedAccounts,
  recordLogin,
  listUsers,
  upsertUser,
  setUserStatus,
  deleteUser,
  setGrant,
} from './users';

const te = new TextEncoder();
const SIGNIN_SCOPES = ['openid', 'email', 'profile'];

async function pkce(): Promise<{ verifier: string; challenge: string }> {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const verifier = b64url(bytes);
  const digest = await crypto.subtle.digest('SHA-256', te.encode(verifier));
  return { verifier, challenge: b64url(digest) };
}

function missingSecrets(env: Env): string[] {
  const need: Array<[string, unknown]> = [
    ['GOOGLE_CLIENT_ID', env.GOOGLE_CLIENT_ID],
    ['GOOGLE_CLIENT_SECRET', env.GOOGLE_CLIENT_SECRET],
    ['VAULT_MASTER_KEY', env.VAULT_MASTER_KEY],
    ['SESSION_SECRET', env.SESSION_SECRET],
    ['DASH_PASSWORD', env.DASH_PASSWORD],
  ];
  return need.filter(([, v]) => !v).map(([k]) => k);
}

const asPrincipal = (s: SessionPayload): Principal => ({
  email: s.email,
  role: s.role,
  name: s.name,
  via: s.via,
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      /* ---------------- public ---------------- */

      if (path === '/health') return await handleHealth(env);
      if (path === '/oauth/callback') return await handleCallback(request, env, url);
      if (path === '/auth/google') return await handleSignInStart(env, url);

      if (path === '/api/login' && method === 'POST') return await handleBreakGlass(request, env);
      if (path === '/api/logout') {
        return new Response(JSON.stringify({ ok: true }), {
          headers: { 'content-type': 'application/json', 'set-cookie': clearCookieHeader() },
        });
      }
      if (path === '/api/session') {
        const s = await principal(request, env);
        return json({
          authed: !!s,
          user: s ? { email: s.email, role: s.role, name: s.name, via: s.via } : null,
          configured: missingSecrets(env).length === 0,
          missing: missingSecrets(env),
        });
      }

      /* ---------------- gated ---------------- */

      if (path.startsWith('/api/') || path.startsWith('/oauth/')) {
        const s = await principal(request, env);
        if (!s) return err('not authenticated', 401);
        const me = asPrincipal(s);

        if (isOwnerOnlyRoute(path, method) && !atLeast(me, 'owner')) {
          return err('owner role required for this action', 403, { your_role: me.role });
        }
        if (isWriteRoute(path, method) && !atLeast(me, 'operator')) {
          return err('operator role required for this action', 403, { your_role: me.role });
        }

        const allowed = await allowedAccounts(env, me);
        return await routeAuthed(request, env, url, path, method, me, allowed);
      }

      /* ---------------- dashboard assets ---------------- */
      return await env.ASSETS.fetch(request);
    } catch (e: any) {
      if (e instanceof ReauthRequired) return err(e.message, 401, { code: 'reauth_required' });
      if (e instanceof VaultError) return err(e.message, e.status, { code: e.code });
      if (e?.status) return err(String(e.message), e.status);
      console.error('unhandled', String(e?.stack ?? e));
      return err('internal error', 500, String(e?.message ?? e));
    }
  },

  async scheduled(_e: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runDueSweeps(env));
  },

  async queue(batch: MessageBatch<SweepMessage>, env: Env): Promise<void> {
    for (const msg of batch.messages) {
      try {
        await processSweepMessage(env, msg.body);
        msg.ack();
      } catch (e: any) {
        const reason = String(e?.message ?? e);
        if (msg.attempts >= 3) {
          await failSweepMessage(env, msg.body, reason);
          msg.ack();
        } else {
          msg.retry();
        }
      }
    }
  },
};

/* ------------------------------------------------------------------ */
/* authed router                                                       */
/* ------------------------------------------------------------------ */

async function routeAuthed(
  request: Request,
  env: Env,
  url: URL,
  path: string,
  method: string,
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  if (path === '/api/caps') {
    return json({
      caps: Object.entries(CAPS).map(([id, v]) => ({
        id,
        label: v.label,
        class: v.klass,
        scopes: v.scopes,
      })),
    });
  }

  if (path === '/oauth/start') return await handleConnectStart(env, url);

  /* users — owner only, already enforced upstream */
  if (path === '/api/users' && method === 'GET') return await listUsers(env);
  if (path === '/api/users' && method === 'POST') return await upsertUser(request, env, me.email);
  if (path === '/api/users/grant' && method === 'POST') return await setGrant(request, env, me.email);
  if (path.startsWith('/api/users/')) {
    const email = decodeURIComponent(path.split('/')[3] ?? '');
    if (method === 'DELETE') return await deleteUser(env, email, me.email);
    if (method === 'PATCH') {
      const b = (await request.json().catch(() => ({}))) as any;
      return await setUserStatus(env, email, b.status === 'suspended' ? 'suspended' : 'active', me.email);
    }
  }

  if (path === '/api/accounts' && method === 'GET') return await listAccounts(env, allowed);
  if (path.startsWith('/api/accounts/')) return await accountItem(request, env, path, me);

  if (path === '/api/search') return await handleSearch(env, url, me, allowed);
  if (path === '/api/mail/threads') return await handleMailThreads(env, url, allowed);
  if (path === '/api/drive/files') return await handleDriveFiles(env, url, allowed);
  if (path === '/api/audit') return await handleAudit(env, url, allowed);

  if (path === '/api/mail/draft' && method === 'POST')
    return await handleMailWrite(request, env, 'draft', me, allowed);
  if (path === '/api/mail/send' && method === 'POST')
    return await handleMailWrite(request, env, 'send', me, allowed);
  if (path === '/api/drive/copy' && method === 'POST')
    return await handleDriveCopy(request, env, me, allowed);
  if (path === '/api/drive/permissions' && method === 'POST')
    return await handleDrivePermissions(request, env, me, allowed);

  if (path === '/api/sweeps' && method === 'GET') return await listSweeps(env, allowed);
  if (path === '/api/sweeps' && method === 'POST')
    return await createSweep(request, env, me, allowed);
  if (path.startsWith('/api/sweeps/')) {
    const parts = path.split('/');
    const id = decodeURIComponent(parts[3] ?? '');
    if (parts[4] === 'run' && method === 'POST') {
      const res = await startRun(env, id, me.email, allowed);
      return json({ ok: true, ...res });
    }
    if (parts[4] === 'findings') return await sweepFindings(env, id, allowed);
    if (method === 'DELETE') return await deleteSweep(env, id, me.email);
    return err('unknown sweep route', 404);
  }

  return err('unknown route', 404);
}

/* ------------------------------------------------------------------ */
/* health                                                              */
/* ------------------------------------------------------------------ */

async function handleHealth(env: Env): Promise<Response> {
  const checks: Record<string, unknown> = {};
  let healthy = true;

  try {
    const r = await env.DB.prepare(
      `SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'`
    ).first<{ n: number }>();
    checks.d1 = { bound: true, tables: r?.n ?? 0 };
  } catch (e) {
    checks.d1 = { bound: false, error: String(e) };
    healthy = false;
  }

  try {
    await env.CACHE.put('health', String(now()), { expirationTtl: 60 });
    checks.kv = { bound: true, readback: (await env.CACHE.get('health')) !== null };
  } catch (e) {
    checks.kv = { bound: false, error: String(e) };
    healthy = false;
  }

  checks.assets = { bound: typeof env.ASSETS?.fetch === 'function' };
  checks.queue = { bound: typeof env.SWEEP_QUEUE?.send === 'function' };

  const missing = missingSecrets(env);
  checks.secrets = { configured: missing.length === 0, missing };
  if (missing.length) healthy = false;

  try {
    const { results } = await env.DB.prepare(
      `SELECT status, COUNT(*) AS n FROM accounts GROUP BY status`
    ).all<any>();
    checks.accounts = results ?? [];
    const u = await env.DB.prepare(
      `SELECT role, COUNT(*) AS n FROM users WHERE status='active' GROUP BY role`
    ).all<any>();
    checks.users = u.results ?? [];
    const stale = await env.DB.prepare(`SELECT COUNT(*) AS n FROM tokens WHERE updated_at < ?`)
      .bind(now() - 6 * 86400)
      .first<{ n: number }>();
    checks.token_age_warning =
      (stale?.n ?? 0) > 0
        ? `${stale!.n} account(s) have not refreshed in 6+ days — if the OAuth app is in Testing status these tokens are about to expire`
        : null;
  } catch {
    /* empty */
  }

  return json(
    {
      status: healthy ? 'ok' : 'degraded',
      service: 'google-orchestrator',
      phase: '0-6 (vault, registry, fan-out, writes, sweeps, multi-user)',
      environment: env.ENVIRONMENT,
      ts: now(),
      checks,
    },
    healthy ? 200 : 503
  );
}

/* ------------------------------------------------------------------ */
/* sign-in                                                             */
/* ------------------------------------------------------------------ */

async function handleSignInStart(env: Env, url: URL): Promise<Response> {
  if (!env.GOOGLE_CLIENT_ID) return err('GOOGLE_CLIENT_ID not set', 503);
  const state = crypto.randomUUID();
  const { verifier, challenge } = await pkce();

  await env.DB.prepare(
    `INSERT INTO oauth_state (state, account_id, requested_scopes, pkce_verifier, expires_at, consumed_at, created_at, purpose)
     VALUES (?, NULL, ?, ?, ?, NULL, ?, 'signin')`
  )
    .bind(state, SIGNIN_SCOPES.join(' '), verifier, now() + 600, now())
    .run();

  const auth = new URL(GOOGLE_AUTH_URL);
  auth.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  auth.searchParams.set('redirect_uri', `${url.origin}/oauth/callback`);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('scope', SIGNIN_SCOPES.join(' '));
  auth.searchParams.set('state', state);
  auth.searchParams.set('prompt', 'select_account');
  auth.searchParams.set('code_challenge', challenge);
  auth.searchParams.set('code_challenge_method', 'S256');
  return Response.redirect(auth.toString(), 302);
}

/** Break-glass: the shared password authenticates as the owner, nothing else. */
async function handleBreakGlass(request: Request, env: Env): Promise<Response> {
  if (!env.DASH_PASSWORD || !env.SESSION_SECRET) {
    return err('dashboard not configured', 503);
  }
  const body = (await request.json().catch(() => ({}))) as any;
  const supplied = String(body?.password ?? '');

  const a = te.encode(supplied);
  const b = te.encode(env.DASH_PASSWORD);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  if (diff !== 0) {
    await audit(env, { actor: 'breakglass', action: 'dashboard.login', outcome: 'denied' });
    return err('invalid password', 401);
  }

  const owner = await env.DB.prepare(
    `SELECT email, name FROM users WHERE role='owner' AND status='active' ORDER BY created_at LIMIT 1`
  ).first<any>();
  const email = owner?.email ?? 'breakglass@local';

  const token = await makeSession(env, {
    email,
    role: 'owner',
    name: owner?.name ?? 'break-glass',
    via: 'breakglass',
  });
  await audit(env, { actor: email, action: 'dashboard.login', outcome: 'ok', detail: { via: 'breakglass' } });
  return new Response(JSON.stringify({ ok: true, email, via: 'breakglass' }), {
    headers: { 'content-type': 'application/json', 'set-cookie': sessionCookieHeader(token) },
  });
}

/* ------------------------------------------------------------------ */
/* oauth — one callback, two purposes                                  */
/* ------------------------------------------------------------------ */

async function handleConnectStart(env: Env, url: URL): Promise<Response> {
  if (!env.GOOGLE_CLIENT_ID) return err('GOOGLE_CLIENT_ID not set', 503);

  const caps = (url.searchParams.get('caps') ?? 'mail.read,drive.read')
    .split(',')
    .map((s) => s.trim())
    .filter((c) => c in CAPS);
  if (!caps.length) return err('no valid caps requested', 400);

  const label = url.searchParams.get('label') ?? null;
  const accountId = url.searchParams.get('account_id') ?? randomId('acct');
  const scopes = scopesForCaps(caps);
  const state = crypto.randomUUID();
  const { verifier, challenge } = await pkce();

  await env.DB.prepare(
    `INSERT INTO oauth_state (state, account_id, requested_scopes, pkce_verifier, expires_at, consumed_at, created_at, purpose)
     VALUES (?, ?, ?, ?, ?, NULL, ?, 'connect')`
  )
    .bind(state, accountId, scopes.join(' '), verifier, now() + 600, now())
    .run();

  if (label) await env.CACHE.put(`label:${accountId}`, label, { expirationTtl: 900 });

  const auth = new URL(GOOGLE_AUTH_URL);
  auth.searchParams.set('client_id', env.GOOGLE_CLIENT_ID);
  auth.searchParams.set('redirect_uri', `${url.origin}/oauth/callback`);
  auth.searchParams.set('response_type', 'code');
  auth.searchParams.set('scope', scopes.join(' '));
  auth.searchParams.set('state', state);
  auth.searchParams.set('access_type', 'offline');
  auth.searchParams.set('prompt', 'consent');
  auth.searchParams.set('include_granted_scopes', 'true');
  auth.searchParams.set('code_challenge', challenge);
  auth.searchParams.set('code_challenge_method', 'S256');
  return Response.redirect(auth.toString(), 302);
}

async function handleCallback(request: Request, env: Env, url: URL): Promise<Response> {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const oauthError = url.searchParams.get('error');

  if (oauthError) return page('Consent declined', `Google returned: ${oauthError}`, false);
  if (!code || !state) return page('Invalid callback', 'Missing code or state.', false);

  const row = await env.DB.prepare(
    `SELECT state, account_id, requested_scopes, pkce_verifier, expires_at, consumed_at, purpose
       FROM oauth_state WHERE state = ?`
  )
    .bind(state)
    .first<any>();

  if (!row) return page('Invalid state', 'This link is not recognised.', false);
  if (row.consumed_at) return page('Replayed state', 'This link was already used.', false);
  if (row.expires_at < now()) return page('Expired state', 'Start again.', false);

  const consumed = await env.DB.prepare(
    `UPDATE oauth_state SET consumed_at = ? WHERE state = ? AND consumed_at IS NULL`
  )
    .bind(now(), state)
    .run();
  if (!consumed.meta.changes) return page('Replayed state', 'This link was already used.', false);

  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID!,
      client_secret: env.GOOGLE_CLIENT_SECRET!,
      code,
      grant_type: 'authorization_code',
      redirect_uri: `${url.origin}/oauth/callback`,
      code_verifier: row.pkce_verifier,
    }),
  });
  const tok = (await tokenRes.json()) as any;
  if (!tokenRes.ok) {
    return page('Token exchange failed', String(tok?.error_description ?? tok?.error ?? ''), false);
  }

  const infoRes = await fetch(USERINFO_URL, {
    headers: { authorization: `Bearer ${tok.access_token}` },
  });
  const info = (await infoRes.json()) as any;
  const email: string = String(info?.email ?? '').toLowerCase();
  if (!email) return page('Sign-in failed', 'Google did not return an email address.', false);

  /* ---- sign-in ---- */
  if (row.purpose === 'signin') {
    const user = await loadUser(env, email);
    if (!user) {
      await audit(env, { actor: email, action: 'dashboard.login', outcome: 'denied' });
      return page(
        'Not authorised',
        `<b>${email}</b> is not on the access list for this orchestrator. Ask the owner to add you.`,
        false
      );
    }
    await recordLogin(env, email, info?.name);
    const token = await makeSession(env, {
      email,
      role: user.role,
      name: info?.name ?? user.name,
      via: 'google',
    });
    await audit(env, {
      actor: email,
      action: 'dashboard.login',
      outcome: 'ok',
      detail: { via: 'google', role: user.role },
    });
    return new Response(null, {
      status: 302,
      headers: { location: '/', 'set-cookie': sessionCookieHeader(token) },
    });
  }

  /* ---- connect a Google account to the vault ---- */
  const domain: string = email.includes('@') ? email.split('@')[1] : '';
  const accountId: string = row.account_id;
  const grantedScopes: string = tok.scope ?? row.requested_scopes;
  const caps = capsFromScopes(grantedScopes);
  const label = (await env.CACHE.get(`label:${accountId}`)) ?? null;
  const ts = now();

  await env.DB.prepare(
    `INSERT INTO accounts (account_id, email, domain, label, kind, status, scopes,
                           gmail_enabled, drive_enabled, last_ok_at, last_error, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, NULL, ?, ?)
     ON CONFLICT(email) DO UPDATE SET
       label = COALESCE(excluded.label, accounts.label),
       scopes = excluded.scopes, status = 'active',
       gmail_enabled = excluded.gmail_enabled, drive_enabled = excluded.drive_enabled,
       last_ok_at = excluded.last_ok_at, last_error = NULL, updated_at = excluded.updated_at`
  )
    .bind(
      accountId,
      email,
      domain,
      label,
      domain === 'gmail.com' ? 'personal' : 'workspace',
      grantedScopes,
      caps.some((c) => c.startsWith('mail.')) ? 1 : 0,
      caps.some((c) => c.startsWith('drive.')) ? 1 : 0,
      ts,
      ts,
      ts
    )
    .run();

  const existing = await env.DB.prepare(`SELECT account_id FROM accounts WHERE email = ?`)
    .bind(email)
    .first<{ account_id: string }>();
  const finalId = existing?.account_id ?? accountId;

  const tm = new TokenManager(env);
  await tm.store(finalId, tok.refresh_token, grantedScopes, tok.expires_in ?? 3600);
  await env.CACHE.delete(`label:${accountId}`);

  await audit(env, {
    actor: 'oauth',
    account_id: finalId,
    action: 'account.connect',
    target: email,
    outcome: 'ok',
    detail: { caps },
  });

  return page(
    'Account connected',
    `${email} is now in the vault as <code>${finalId}</code> with: ${caps.join(', ') || 'basic access'}.`,
    true
  );
}

function page(title: string, message: string, ok: boolean): Response {
  const accent = ok ? '#4ade80' : '#f87171';
  return new Response(
    `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>
<style>body{background:#07090c;color:#d7e2ec;font:14px/1.6 ui-monospace,Menlo,monospace;
display:grid;place-items:center;height:100vh;margin:0}
.c{border:1px solid #1c2733;border-left:3px solid ${accent};background:#0f151c;padding:28px 32px;max-width:560px;border-radius:0 6px 6px 0}
h1{font-size:17px;margin:0 0 10px;color:${accent}}p{margin:0;color:#b6c4d2}
code{background:#0c1015;border:1px solid #1c2733;padding:1px 6px;border-radius:3px;color:#38bdf8}
a{color:#38bdf8;display:inline-block;margin-top:18px}</style></head>
<body><div class="c"><h1>${title}</h1><p>${message}</p><a href="/">← dashboard</a></div></body></html>`,
    { status: ok ? 200 : 400, headers: { 'content-type': 'text/html; charset=utf-8' } }
  );
}

/* ------------------------------------------------------------------ */
/* accounts                                                            */
/* ------------------------------------------------------------------ */

async function listAccounts(env: Env, allowed: string[] | null): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT a.account_id, a.email, a.domain, a.label, a.kind, a.status, a.scopes,
            a.gmail_enabled, a.drive_enabled, a.last_ok_at, a.last_error,
            a.created_at, t.expires_at, t.rotated_at, t.updated_at AS token_updated_at
       FROM accounts a LEFT JOIN tokens t ON t.account_id = a.account_id
      ORDER BY a.email`
  ).all<any>();

  const set = allowed == null ? null : new Set(allowed);
  const accounts = (results ?? [])
    .filter((a) => set == null || set.has(a.account_id))
    .map((a) => ({
      ...a,
      scopes: undefined,
      caps: capsFromScopes(a.scopes ?? ''),
      token_age_days: a.token_updated_at ? Math.floor((now() - a.token_updated_at) / 86400) : null,
    }));

  return json({ count: accounts.length, scoped: allowed != null, accounts });
}

async function accountItem(
  request: Request,
  env: Env,
  path: string,
  me: Principal
): Promise<Response> {
  const id = decodeURIComponent(path.split('/')[3] ?? '');
  if (!id) return err('missing account id', 400);

  if (request.method === 'DELETE') {
    const tm = new TokenManager(env);
    const res = await tm.revoke(id);
    await env.DB.prepare(`DELETE FROM user_accounts WHERE account_id = ?`).bind(id).run();
    await audit(env, { actor: me.email, account_id: id, action: 'account.revoke', outcome: 'ok', detail: res });
    return json({ ok: true, ...res });
  }

  if (request.method === 'PATCH') {
    const body = (await request.json().catch(() => ({}))) as any;
    const sets: string[] = [];
    const binds: unknown[] = [];
    if (typeof body.label === 'string') {
      sets.push('label = ?');
      binds.push(body.label);
    }
    if (body.status === 'active' || body.status === 'paused') {
      sets.push('status = ?');
      binds.push(body.status);
    }
    if (typeof body.gmail_enabled === 'boolean') {
      sets.push('gmail_enabled = ?');
      binds.push(body.gmail_enabled ? 1 : 0);
    }
    if (typeof body.drive_enabled === 'boolean') {
      sets.push('drive_enabled = ?');
      binds.push(body.drive_enabled ? 1 : 0);
    }
    if (!sets.length) return err('nothing to update', 400);
    sets.push('updated_at = ?');
    binds.push(now(), id);
    await env.DB.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE account_id = ?`)
      .bind(...binds)
      .run();
    await audit(env, { actor: me.email, account_id: id, action: 'account.update', outcome: 'ok', detail: body });
    return json({ ok: true });
  }

  return err('method not allowed', 405);
}

/* ------------------------------------------------------------------ */
/* read fan-out                                                        */
/* ------------------------------------------------------------------ */

const fanoutResponse = (payload: Record<string, unknown>, partial: boolean) =>
  json(payload, partial ? 207 : 200);

async function handleSearch(
  env: Env,
  url: URL,
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  const q = url.searchParams.get('q');
  if (!q) return err('q is required', 400);
  const limit = Math.min(10, parseInt(url.searchParams.get('limit') || '5', 10));
  const surfaces = (url.searchParams.get('surfaces') ?? 'mail,drive').split(',');

  const accounts = await resolveAccounts(env, url.searchParams.get('accounts'), undefined, allowed);
  if (!accounts.length)
    return json({ query: q, accounts_queried: 0, hits: 0, results: [], errors: [] });

  const tm = new TokenManager(env);
  const result = await fanout(env, accounts, async (account) => {
    const client = clientFor(env, tm, account.account_id);
    const out: any[] = [];
    if (surfaces.includes('mail')) out.push(...(await gmailSearch(client, q, limit)));
    if (surfaces.includes('drive')) out.push(...(await driveSearch(client, q, limit)));
    return out;
  });

  const results = result.ok.flatMap(({ account, value }) =>
    value.map((hit) => ({
      ...hit,
      account_id: account.account_id,
      account_email: account.email,
      account_label: account.label,
    }))
  );

  await audit(env, {
    actor: me.email,
    action: 'search',
    target: q,
    outcome: result.partial ? 'partial' : 'ok',
    detail: { accounts: accounts.length, hits: results.length, failed: result.errors.length },
  });

  return fanoutResponse(
    {
      query: q,
      accounts_queried: accounts.length,
      hits: results.length,
      results,
      errors: result.errors.map((e) => ({
        account_id: e.account.account_id,
        email: e.account.email,
        error: e.error,
      })),
    },
    result.partial
  );
}

async function handleMailThreads(env: Env, url: URL, allowed: string[] | null): Promise<Response> {
  const q = url.searchParams.get('q') ?? 'in:inbox newer_than:7d';
  const limit = Math.min(10, parseInt(url.searchParams.get('limit') || '5', 10));
  const accounts = await resolveAccounts(env, url.searchParams.get('accounts'), 'gmail', allowed);
  if (!accounts.length) return json({ accounts_queried: 0, results: [], errors: [] });

  const tm = new TokenManager(env);
  const result = await fanout(env, accounts, async (account) => {
    const client = clientFor(env, tm, account.account_id);
    const [profile, hits] = await Promise.all([
      gmailProfile(client).catch(() => null),
      gmailSearch(client, q, limit),
    ]);
    return { profile, hits };
  });

  return fanoutResponse(
    {
      query: q,
      accounts_queried: accounts.length,
      results: result.ok.map(({ account, value }) => ({
        account_id: account.account_id,
        email: account.email,
        label: account.label,
        total_messages: value.profile?.messagesTotal ?? null,
        hits: value.hits,
      })),
      errors: result.errors.map((e) => ({
        account_id: e.account.account_id,
        email: e.account.email,
        error: e.error,
      })),
    },
    result.partial
  );
}

async function handleDriveFiles(env: Env, url: URL, allowed: string[] | null): Promise<Response> {
  const q = url.searchParams.get('q');
  const limit = Math.min(20, parseInt(url.searchParams.get('limit') || '10', 10));
  const accounts = await resolveAccounts(env, url.searchParams.get('accounts'), 'drive', allowed);
  if (!accounts.length) return json({ accounts_queried: 0, results: [], errors: [] });

  const tm = new TokenManager(env);
  const result = await fanout(env, accounts, async (account) => {
    const client = clientFor(env, tm, account.account_id);
    const [about, files] = await Promise.all([
      driveAbout(client).catch(() => null),
      q ? driveSearch(client, q, limit) : driveRecent(client, limit),
    ]);
    return { about, files };
  });

  return fanoutResponse(
    {
      query: q,
      accounts_queried: accounts.length,
      results: result.ok.map(({ account, value }) => ({
        account_id: account.account_id,
        email: account.email,
        label: account.label,
        quota: value.about?.storageQuota ?? null,
        files: value.files,
      })),
      errors: result.errors.map((e) => ({
        account_id: e.account.account_id,
        email: e.account.email,
        error: e.error,
      })),
    },
    result.partial
  );
}

async function handleAudit(env: Env, url: URL, allowed: string[] | null): Promise<Response> {
  const limit = Math.min(200, parseInt(url.searchParams.get('limit') || '50', 10));
  const { results } = await env.DB.prepare(
    `SELECT id, ts, actor, account_id, action, target, outcome FROM audit_log
      ORDER BY ts DESC, id DESC LIMIT ?`
  )
    .bind(limit)
    .all<any>();
  const set = allowed == null ? null : new Set(allowed);
  const entries = (results ?? []).filter(
    (e) => set == null || !e.account_id || set.has(e.account_id)
  );
  return json({ count: entries.length, entries });
}

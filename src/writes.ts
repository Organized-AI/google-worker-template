/**
 * Phase 4 — write actions.
 *
 * Two rules every handler in this file obeys:
 *   1. The account is always explicit. Nothing is inferred, nothing defaults
 *      to "all". Sending as the wrong client is the worst thing this system
 *      can do, so it must be typed.
 *   2. Dry-run is the default. A mutation only executes when the request body
 *      carries confirm:true. Without it you get back exactly what would have
 *      happened, and an audit row with outcome 'dry_run'.
 *
 * Audit rows are written BEFORE execution and updated after, so a crash
 * mid-flight still leaves evidence of intent.
 */

import { Env, json, err, now, audit } from './util';
import { TokenManager } from './vault';
import { clientFor, GoogleApiClient } from './google';
import type { Principal } from './users';

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
const DRIVE = 'https://www.googleapis.com/drive/v3';
const DRIVE_UPLOAD = 'https://www.googleapis.com/upload/drive/v3';

/** Max bytes we will pull through the Worker for a cross-account copy. */
const CROSS_ACCOUNT_MAX_BYTES = 60 * 1024 * 1024;

function b64urlFromString(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlFromBytes(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)) as any);
  }
  return btoa(bin);
}

async function requireAccount(
  env: Env,
  accountId: unknown,
  surface?: 'gmail' | 'drive',
  allowed?: string[] | null
) {
  if (typeof accountId !== 'string' || !accountId) {
    throw Object.assign(new Error('account_id is required and must be explicit'), { status: 400 });
  }
  const row = await env.DB.prepare(
    `SELECT account_id, email, label, status, gmail_enabled, drive_enabled
       FROM accounts WHERE account_id = ?`
  )
    .bind(accountId)
    .first<any>();
  if (!row) throw Object.assign(new Error(`unknown account ${accountId}`), { status: 404 });
  if (row.status !== 'active')
    throw Object.assign(new Error(`account ${row.email} is ${row.status}`), { status: 409 });
  if (surface === 'gmail' && !row.gmail_enabled)
    throw Object.assign(new Error(`account ${row.email} has no Gmail capability`), { status: 403 });
  if (surface === 'drive' && !row.drive_enabled)
    throw Object.assign(new Error(`account ${row.email} has no Drive capability`), { status: 403 });
  if (allowed != null && !allowed.includes(row.account_id))
    throw Object.assign(
      new Error(`you have not been granted access to ${row.email}`),
      { status: 403 }
    );
  return row;
}

/** Build an RFC 2822 message. Threading headers are preserved when supplied. */
function buildMime(o: {
  from: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  body: string;
  html?: boolean;
  inReplyTo?: string;
  references?: string;
}): string {
  const lines = [
    `From: ${o.from}`,
    `To: ${o.to.join(', ')}`,
    ...(o.cc?.length ? [`Cc: ${o.cc.join(', ')}`] : []),
    ...(o.bcc?.length ? [`Bcc: ${o.bcc.join(', ')}`] : []),
    `Subject: ${o.subject}`,
    ...(o.inReplyTo ? [`In-Reply-To: ${o.inReplyTo}`] : []),
    ...(o.references ? [`References: ${o.references}`] : []),
    'MIME-Version: 1.0',
    `Content-Type: text/${o.html ? 'html' : 'plain'}; charset="UTF-8"`,
    'Content-Transfer-Encoding: 7bit',
    '',
    o.body,
  ];
  return lines.join('\r\n');
}

interface MailBody {
  account_id?: string;
  to?: string | string[];
  cc?: string | string[];
  bcc?: string | string[];
  subject?: string;
  body?: string;
  html?: boolean;
  thread_id?: string;
  in_reply_to?: string;
  references?: string;
  confirm?: boolean;
}

const asArray = (v: unknown): string[] =>
  Array.isArray(v) ? v.map(String) : typeof v === 'string' && v ? v.split(',').map((s) => s.trim()) : [];

/* ------------------------------------------------------------------ */
/* mail: draft + send                                                  */
/* ------------------------------------------------------------------ */

export async function handleMailWrite(
  request: Request,
  env: Env,
  mode: 'draft' | 'send',
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as MailBody;
  const account = await requireAccount(env, b.account_id, 'gmail', allowed);

  const to = asArray(b.to);
  if (!to.length) return err('to is required', 400);
  if (typeof b.subject !== 'string' || !b.subject) return err('subject is required', 400);
  if (typeof b.body !== 'string') return err('body is required', 400);

  const preview = {
    action: `mail.${mode}`,
    from: account.email,
    from_account: account.account_id,
    from_label: account.label,
    to,
    cc: asArray(b.cc),
    bcc: asArray(b.bcc),
    subject: b.subject,
    body_chars: b.body.length,
    html: !!b.html,
    thread_id: b.thread_id ?? null,
  };

  if (!b.confirm) {
    await audit(env, {
      actor: me.email,
      account_id: account.account_id,
      action: `mail.${mode}`,
      target: to.join(','),
      outcome: 'dry_run',
      detail: preview,
    });
    return json({
      dry_run: true,
      confirm_with: 'resend the same body with "confirm": true',
      would: preview,
    });
  }

  await audit(env, {
    actor: me.email,
    account_id: account.account_id,
    action: `mail.${mode}`,
    target: to.join(','),
    outcome: 'attempting',
    detail: preview,
  });

  const mime = buildMime({
    from: account.email,
    to,
    cc: asArray(b.cc),
    bcc: asArray(b.bcc),
    subject: b.subject,
    body: b.body,
    html: b.html,
    inReplyTo: b.in_reply_to,
    references: b.references,
  });
  const raw = b64urlFromString(mime);

  const tm = new TokenManager(env);
  const client = clientFor(env, tm, account.account_id);

  const payload: any =
    mode === 'draft'
      ? { message: { raw, ...(b.thread_id ? { threadId: b.thread_id } : {}) } }
      : { raw, ...(b.thread_id ? { threadId: b.thread_id } : {}) };

  const endpoint = mode === 'draft' ? `${GMAIL}/drafts` : `${GMAIL}/messages/send`;
  const res = await client.postJson<any>(endpoint, payload);

  await audit(env, {
    actor: me.email,
    account_id: account.account_id,
    action: `mail.${mode}`,
    target: to.join(','),
    outcome: 'ok',
    detail: { id: res.id, threadId: res.message?.threadId ?? res.threadId },
  });

  return json({
    ok: true,
    mode,
    from: account.email,
    id: res.id,
    thread_id: res.message?.threadId ?? res.threadId ?? null,
    web_url:
      mode === 'draft'
        ? `https://mail.google.com/mail/u/0/#drafts`
        : `https://mail.google.com/mail/u/0/#sent/${res.threadId ?? ''}`,
  });
}

/* ------------------------------------------------------------------ */
/* drive: copy (same-account and cross-account)                        */
/* ------------------------------------------------------------------ */

export async function handleDriveCopy(
  request: Request,
  env: Env,
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as any;
  const from = await requireAccount(env, b.from_account_id ?? b.account_id, 'drive', allowed);
  const crossAccount = !!b.to_account_id && b.to_account_id !== from.account_id;
  const to = crossAccount ? await requireAccount(env, b.to_account_id, 'drive', allowed) : from;

  if (typeof b.file_id !== 'string' || !b.file_id) return err('file_id is required', 400);

  const tm = new TokenManager(env);
  const src = clientFor(env, tm, from.account_id);

  const meta = await src.getJson<any>(
    `${DRIVE}/files/${b.file_id}?fields=id,name,mimeType,size&supportsAllDrives=true`
  );

  const preview = {
    action: 'drive.copy',
    cross_account: crossAccount,
    from: from.email,
    to: to.email,
    file: { id: meta.id, name: meta.name, mimeType: meta.mimeType, size: meta.size ?? null },
    new_name: b.name ?? meta.name,
    parent_folder_id: b.parent_folder_id ?? null,
  };

  if (!b.confirm) {
    await audit(env, {
      actor: me.email,
      account_id: from.account_id,
      action: 'drive.copy',
      target: meta.name,
      outcome: 'dry_run',
      detail: preview,
    });
    return json({ dry_run: true, confirm_with: 'resend with "confirm": true', would: preview });
  }

  await audit(env, {
    actor: me.email,
    account_id: from.account_id,
    action: 'drive.copy',
    target: meta.name,
    outcome: 'attempting',
    detail: preview,
  });

  /* same account — let Google do it server-side */
  if (!crossAccount) {
    const copied = await src.postJson<any>(
      `${DRIVE}/files/${b.file_id}/copy?supportsAllDrives=true&fields=id,name,webViewLink`,
      {
        ...(b.name ? { name: b.name } : {}),
        ...(b.parent_folder_id ? { parents: [b.parent_folder_id] } : {}),
      }
    );
    await audit(env, {
      actor: me.email,
      account_id: from.account_id,
      action: 'drive.copy',
      target: meta.name,
      outcome: 'ok',
      detail: { new_id: copied.id },
    });
    return json({ ok: true, cross_account: false, file: copied });
  }

  /* cross account — stream through the Worker */
  const size = parseInt(meta.size ?? '0', 10);
  if (size > CROSS_ACCOUNT_MAX_BYTES) {
    return err(
      `file is ${(size / 1048576).toFixed(1)}MB; cross-account copy is capped at ${
        CROSS_ACCOUNT_MAX_BYTES / 1048576
      }MB`,
      413
    );
  }

  const isGoogleDoc = String(meta.mimeType).startsWith('application/vnd.google-apps');
  const exportMime = 'application/pdf';
  const dlUrl = isGoogleDoc
    ? `${DRIVE}/files/${b.file_id}/export?mimeType=${encodeURIComponent(exportMime)}`
    : `${DRIVE}/files/${b.file_id}?alt=media&supportsAllDrives=true`;

  const dl = await src.request(dlUrl);
  if (!dl.ok) return err(`download failed: HTTP ${dl.status}`, 502);
  const bytes = await dl.arrayBuffer();

  const destName = b.name ?? (isGoogleDoc ? `${meta.name}.pdf` : meta.name);
  const destMime = isGoogleDoc ? exportMime : meta.mimeType;

  const boundary = `go-${crypto.randomUUID()}`;
  const metaPart =
    `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n` +
    JSON.stringify({
      name: destName,
      ...(b.parent_folder_id ? { parents: [b.parent_folder_id] } : {}),
    }) +
    `\r\n--${boundary}\r\nContent-Type: ${destMime}\r\nContent-Transfer-Encoding: base64\r\n\r\n`;
  const closing = `\r\n--${boundary}--`;
  const multipartBody = metaPart + b64urlFromBytes(bytes) + closing;

  const dst = clientFor(env, tm, to.account_id);
  const upRes = await dst.request(
    `${DRIVE_UPLOAD}/files?uploadType=multipart&supportsAllDrives=true&fields=id,name,webViewLink`,
    {
      method: 'POST',
      headers: { 'content-type': `multipart/related; boundary=${boundary}` },
      body: multipartBody,
    }
  );
  const created = await upRes.json().catch(() => ({}));
  if (!upRes.ok) return err('upload to destination account failed', 502, created);

  await audit(env, {
    actor: me.email,
    account_id: to.account_id,
    action: 'drive.copy',
    target: destName,
    outcome: 'ok',
    detail: { from: from.email, to: to.email, new_id: (created as any).id, bytes: bytes.byteLength },
  });

  return json({
    ok: true,
    cross_account: true,
    from: from.email,
    to: to.email,
    exported_as: isGoogleDoc ? exportMime : null,
    file: created,
  });
}

/* ------------------------------------------------------------------ */
/* drive: permissions                                                  */
/* ------------------------------------------------------------------ */

export async function handleDrivePermissions(
  request: Request,
  env: Env,
  me: Principal,
  allowed: string[] | null
): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as any;
  const account = await requireAccount(env, b.account_id, 'drive', allowed);
  if (typeof b.file_id !== 'string' || !b.file_id) return err('file_id is required', 400);

  const action = b.action === 'revoke' ? 'revoke' : 'grant';
  const tm = new TokenManager(env);
  const client = clientFor(env, tm, account.account_id);

  const meta = await client.getJson<any>(
    `${DRIVE}/files/${b.file_id}?fields=id,name&supportsAllDrives=true`
  );

  const type = b.type ?? (b.email ? 'user' : 'anyone');
  const role = b.role ?? 'reader';
  const publicLink = type === 'anyone';

  const preview = {
    action: `drive.permissions.${action}`,
    account: account.email,
    file: { id: meta.id, name: meta.name },
    ...(action === 'grant'
      ? { grant_to: b.email ?? '(anyone with the link)', type, role, public_link: publicLink }
      : { permission_id: b.permission_id ?? null, revoke_from: b.email ?? null }),
  };

  if (!b.confirm) {
    await audit(env, {
      actor: me.email,
      account_id: account.account_id,
      action: `drive.permissions.${action}`,
      target: meta.name,
      outcome: 'dry_run',
      detail: preview,
    });
    return json({
      dry_run: true,
      confirm_with: 'resend with "confirm": true',
      ...(publicLink && action === 'grant'
        ? { warning: 'this makes the file readable by anyone with the link' }
        : {}),
      would: preview,
    });
  }

  await audit(env, {
    actor: me.email,
    account_id: account.account_id,
    action: `drive.permissions.${action}`,
    target: meta.name,
    outcome: 'attempting',
    detail: preview,
  });

  if (action === 'grant') {
    const created = await client.postJson<any>(
      `${DRIVE}/files/${b.file_id}/permissions?supportsAllDrives=true&sendNotificationEmail=${
        b.notify === true ? 'true' : 'false'
      }&fields=id,type,role,emailAddress`,
      { type, role, ...(b.email ? { emailAddress: b.email } : {}) }
    );
    await audit(env, {
      actor: me.email,
      account_id: account.account_id,
      action: 'drive.permissions.grant',
      target: meta.name,
      outcome: 'ok',
      detail: created,
    });
    return json({ ok: true, file: meta, permission: created });
  }

  // revoke — resolve permission_id from email when needed
  let permId: string | undefined = b.permission_id;
  if (!permId && b.email) {
    const list = await client.getJson<any>(
      `${DRIVE}/files/${b.file_id}/permissions?supportsAllDrives=true&fields=permissions(id,emailAddress,type,role)`
    );
    permId = (list.permissions ?? []).find(
      (p: any) => p.emailAddress?.toLowerCase() === String(b.email).toLowerCase()
    )?.id;
  }
  if (!permId) return err('permission_id or a matching email is required to revoke', 400);

  const res = await client.request(
    `${DRIVE}/files/${b.file_id}/permissions/${permId}?supportsAllDrives=true`,
    { method: 'DELETE' }
  );
  if (!res.ok && res.status !== 204) return err(`revoke failed: HTTP ${res.status}`, 502);

  await audit(env, {
    actor: me.email,
    account_id: account.account_id,
    action: 'drive.permissions.revoke',
    target: meta.name,
    outcome: 'ok',
    detail: { permission_id: permId },
  });
  return json({ ok: true, file: meta, revoked: permId });
}

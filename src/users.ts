/**
 * Per-user identity and authorisation.
 *
 * Sign-in is Google OAuth against the same client used to connect mailboxes,
 * routed through the same /oauth/callback and distinguished by the `purpose`
 * column on oauth_state. That means no new redirect URI to register.
 *
 * Sign-in requests ONLY openid + email + profile. Those are non-sensitive
 * scopes, so signing in never touches anyone's mail or files and never asks
 * a human to grant anything beyond their identity.
 *
 * Roles:
 *   owner    — everything, including connecting/revoking Google accounts and
 *              managing users
 *   operator — read and write against the accounts they are scoped to, plus
 *              sweeps; cannot connect/revoke accounts or manage users
 *   viewer   — read only
 */

import { Env, json, err, now, audit } from './util';

export type Role = 'owner' | 'operator' | 'viewer';

export interface Principal {
  email: string;
  role: Role;
  name?: string | null;
  via: 'google' | 'breakglass';
}

const RANK: Record<Role, number> = { viewer: 1, operator: 2, owner: 3 };

export function atLeast(p: Principal | null, role: Role): boolean {
  return !!p && RANK[p.role] >= RANK[role];
}

/** Routes only an owner may touch, matched before anything else runs. */
export function isOwnerOnlyRoute(path: string, method: string): boolean {
  if (path === '/oauth/start') return true;
  if (path.startsWith('/api/users')) return true;
  if (path.startsWith('/api/accounts/') && (method === 'DELETE' || method === 'PATCH')) return true;
  return false;
}

/** Routes that mutate Google data — operator or above. */
export function isWriteRoute(path: string, method: string): boolean {
  if (method !== 'POST' && method !== 'DELETE') return false;
  return (
    path.startsWith('/api/mail/') ||
    path.startsWith('/api/drive/') ||
    path.startsWith('/api/sweeps')
  );
}

export async function loadUser(env: Env, email: string): Promise<any | null> {
  return env.DB.prepare(`SELECT * FROM users WHERE email = ? AND status = 'active'`)
    .bind(email.toLowerCase())
    .first<any>();
}

/**
 * The set of account_ids this principal may reach.
 * Returns null when unrestricted — callers treat null as "no filter".
 */
export async function allowedAccounts(env: Env, p: Principal): Promise<string[] | null> {
  if (p.via === 'breakglass' || p.role === 'owner') return null;
  const u = await loadUser(env, p.email);
  if (!u) return [];
  if (u.account_scope === 'all') return null;
  const { results } = await env.DB.prepare(
    `SELECT account_id FROM user_accounts WHERE email = ?`
  )
    .bind(p.email.toLowerCase())
    .all<{ account_id: string }>();
  return (results ?? []).map((r) => r.account_id);
}

export async function recordLogin(env: Env, email: string, name?: string | null): Promise<void> {
  await env.DB.prepare(
    `UPDATE users SET last_login_at = ?, name = COALESCE(?, name), updated_at = ? WHERE email = ?`
  )
    .bind(now(), name ?? null, now(), email.toLowerCase())
    .run();
}

/* ------------------------------------------------------------------ */
/* user management (owner only)                                        */
/* ------------------------------------------------------------------ */

export async function listUsers(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(`SELECT * FROM users ORDER BY created_at`).all<any>();
  const grants = await env.DB.prepare(`SELECT email, account_id FROM user_accounts`).all<any>();
  const byUser: Record<string, string[]> = {};
  for (const g of grants.results ?? []) (byUser[g.email] ??= []).push(g.account_id);

  const accounts = await env.DB.prepare(
    `SELECT account_id, email, label FROM accounts ORDER BY email`
  ).all<any>();

  return json({
    users: (results ?? []).map((u) => ({ ...u, granted_accounts: byUser[u.email] ?? [] })),
    all_accounts: accounts.results ?? [],
    roles: [
      { id: 'viewer', label: 'Read only' },
      { id: 'operator', label: 'Read + write, no account management' },
      { id: 'owner', label: 'Everything' },
    ],
  });
}

export async function upsertUser(request: Request, env: Env, actor: string): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as any;
  const email = String(b.email ?? '').toLowerCase().trim();
  if (!email.includes('@')) return err('a valid email is required', 400);
  const role: Role = ['owner', 'operator', 'viewer'].includes(b.role) ? b.role : 'viewer';
  const scope = b.account_scope === 'all' ? 'all' : 'allowlist';
  const ts = now();

  await env.DB.prepare(
    `INSERT INTO users (email, name, role, status, account_scope, invited_by, last_login_at, created_at, updated_at)
     VALUES (?, ?, ?, 'active', ?, ?, NULL, ?, ?)
     ON CONFLICT(email) DO UPDATE SET
       role = excluded.role,
       account_scope = excluded.account_scope,
       name = COALESCE(excluded.name, users.name),
       updated_at = excluded.updated_at`
  )
    .bind(email, b.name ?? null, role, scope, actor, ts, ts)
    .run();

  await audit(env, { actor, action: 'user.upsert', target: email, detail: { role, scope } });
  return json({ ok: true, email, role, account_scope: scope });
}

export async function setUserStatus(
  env: Env,
  email: string,
  status: 'active' | 'suspended',
  actor: string
): Promise<Response> {
  await env.DB.prepare(`UPDATE users SET status = ?, updated_at = ? WHERE email = ?`)
    .bind(status, now(), email.toLowerCase())
    .run();
  await audit(env, { actor, action: 'user.status', target: email, detail: { status } });
  return json({ ok: true, email, status });
}

export async function deleteUser(env: Env, email: string, actor: string): Promise<Response> {
  if (email.toLowerCase() === actor.toLowerCase()) return err('you cannot remove yourself', 400);
  await env.DB.prepare(`DELETE FROM user_accounts WHERE email = ?`).bind(email.toLowerCase()).run();
  await env.DB.prepare(`DELETE FROM users WHERE email = ?`).bind(email.toLowerCase()).run();
  await audit(env, { actor, action: 'user.delete', target: email });
  return json({ ok: true });
}

/** Grant or revoke one connected Google account for one user. */
export async function setGrant(request: Request, env: Env, actor: string): Promise<Response> {
  const b = (await request.json().catch(() => ({}))) as any;
  const email = String(b.email ?? '').toLowerCase();
  const accountId = String(b.account_id ?? '');
  if (!email || !accountId) return err('email and account_id are required', 400);

  if (b.grant === false) {
    await env.DB.prepare(`DELETE FROM user_accounts WHERE email = ? AND account_id = ?`)
      .bind(email, accountId)
      .run();
    await audit(env, {
      actor,
      account_id: accountId,
      action: 'user.grant.revoke',
      target: email,
    });
    return json({ ok: true, granted: false });
  }

  await env.DB.prepare(
    `INSERT OR REPLACE INTO user_accounts (email, account_id, granted_by, granted_at)
     VALUES (?, ?, ?, ?)`
  )
    .bind(email, accountId, actor, now())
    .run();
  await audit(env, { actor, account_id: accountId, action: 'user.grant', target: email });
  return json({ ok: true, granted: true });
}

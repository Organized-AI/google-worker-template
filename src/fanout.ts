/**
 * Fan-out engine.
 *
 * Two invariants, enforced here so no route can violate them:
 *   - one account failing never fails the request
 *   - every returned item carries the account it came from
 */

import { Env } from './util';

export interface AccountRef {
  account_id: string;
  email: string;
  label: string | null;
  domain: string | null;
}

export interface FanoutResult<T> {
  ok: Array<{ account: AccountRef; value: T }>;
  errors: Array<{ account: AccountRef; error: string; code?: string }>;
  partial: boolean;
}

function timeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timeout after ${ms}ms (${label})`)), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      }
    );
  });
}

export async function fanout<T>(
  env: Env,
  accounts: AccountRef[],
  fn: (account: AccountRef) => Promise<T>
): Promise<FanoutResult<T>> {
  const cap = Math.max(1, parseInt(env.MAX_FANOUT_CONCURRENCY || '6', 10));
  const perAccountMs = Math.max(1000, parseInt(env.PER_ACCOUNT_TIMEOUT_MS || '15000', 10));

  const ok: FanoutResult<T>['ok'] = [];
  const errors: FanoutResult<T>['errors'] = [];

  let cursor = 0;
  async function worker() {
    while (cursor < accounts.length) {
      const account = accounts[cursor++];
      try {
        const value = await timeout(fn(account), perAccountMs, account.email);
        ok.push({ account, value });
      } catch (e: any) {
        errors.push({
          account,
          error: e?.message ? String(e.message) : String(e),
          code: e?.code,
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(cap, accounts.length) }, worker));
  return { ok, errors, partial: errors.length > 0 };
}

/**
 * Resolve an `accounts` query param to a concrete list.
 *   "*"                    → every active account
 *   "acct_x,acct_y"        → those ids
 *   "@clientdomain.com"    → every active account on that domain
 * Capability filter narrows to accounts that have the surface enabled.
 */
export async function resolveAccounts(
  env: Env,
  spec: string | null,
  surface?: 'gmail' | 'drive',
  allowed?: string[] | null
): Promise<AccountRef[]> {
  const want = (spec ?? '*').trim();
  const surfaceClause =
    surface === 'gmail' ? ' AND gmail_enabled = 1' : surface === 'drive' ? ' AND drive_enabled = 1' : '';

  if (want === '*' || want === '') {
    const { results } = await env.DB.prepare(
      `SELECT account_id, email, label, domain FROM accounts
        WHERE status = 'active'${surfaceClause} ORDER BY email`
    ).all<AccountRef>();
    return narrow(results ?? [], allowed);
  }

  if (want.startsWith('@')) {
    const { results } = await env.DB.prepare(
      `SELECT account_id, email, label, domain FROM accounts
        WHERE status = 'active' AND domain = ?${surfaceClause} ORDER BY email`
    )
      .bind(want.slice(1))
      .all<AccountRef>();
    return narrow(results ?? [], allowed);
  }

  const ids = want
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (!ids.length) return [];
  const placeholders = ids.map(() => '?').join(',');
  const { results } = await env.DB.prepare(
    `SELECT account_id, email, label, domain FROM accounts
      WHERE account_id IN (${placeholders})${surfaceClause} ORDER BY email`
  )
    .bind(...ids)
    .all<AccountRef>();
  return narrow(results ?? [], allowed);
}

/** null means unrestricted; an array restricts to exactly those account ids. */
function narrow(rows: AccountRef[], allowed?: string[] | null): AccountRef[] {
  if (allowed == null) return rows;
  const set = new Set(allowed);
  return rows.filter((r) => set.has(r.account_id));
}

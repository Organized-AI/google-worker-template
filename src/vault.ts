/**
 * Token vault.
 *
 * Design rules, all of which exist because the reference implementation
 * (google-marketing-hub-mcp) got them wrong:
 *
 *  1. Refresh tokens are AES-GCM encrypted at rest with a per-account key
 *     derived via HKDF from VAULT_MASTER_KEY salted by account_id.
 *  2. Access tokens live in KV with a TTL, never in D1 — this also avoids
 *     reusing one IV column for two different ciphertexts (nonce reuse under
 *     the same key would break AES-GCM).
 *  3. A rotated refresh_token returned by Google is always persisted.
 *  4. We never write NULL over an existing refresh token.
 *  5. invalid_grant marks the account reauth_required instead of failing silently.
 *
 * No function here ever returns raw token material to a caller outside the Worker.
 */

import { Env, b64, unb64, now, audit } from './util';

const te = new TextEncoder();
const td = new TextDecoder();

const KEY_VERSION = 1;
const HKDF_INFO = 'google-orchestrator/token/v1';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';

export class VaultError extends Error {
  constructor(message: string, public code: string = 'vault_error', public status = 500) {
    super(message);
  }
}

export class ReauthRequired extends Error {
  constructor(public accountId: string) {
    super(`account ${accountId} requires re-consent`);
  }
}

async function deriveKey(master: string, accountId: string): Promise<CryptoKey> {
  const ikm = await crypto.subtle.importKey('raw', te.encode(master), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: te.encode(accountId),
      info: te.encode(HKDF_INFO),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptFor(master: string, accountId: string, plaintext: string) {
  const key = await deriveKey(master, accountId);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(plaintext));
  return { ciphertext: b64(ct), iv: b64(iv) };
}

export async function decryptFor(
  master: string,
  accountId: string,
  ciphertext: string,
  ivB64: string
): Promise<string> {
  const key = await deriveKey(master, accountId);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(ivB64) },
    key,
    unb64(ciphertext)
  );
  return td.decode(pt);
}

interface TokenRow {
  account_id: string;
  refresh_token_enc: string;
  iv: string;
  key_version: number;
  expires_at: number;
  granted_scopes: string;
}

export class TokenManager {
  constructor(private env: Env) {
    if (!env.VAULT_MASTER_KEY) throw new VaultError('VAULT_MASTER_KEY not set', 'no_master_key');
  }

  private get master(): string {
    return this.env.VAULT_MASTER_KEY!;
  }

  /** Store (or replace) the credentials for an account after a successful consent. */
  async store(
    accountId: string,
    refreshToken: string | undefined,
    grantedScopes: string,
    expiresIn: number
  ): Promise<void> {
    const ts = now();

    if (!refreshToken) {
      // Google omits refresh_token when the user re-consents and one already exists.
      // Update scope/expiry only — never null out what we already hold.
      const existing = await this.env.DB.prepare(
        `SELECT account_id FROM tokens WHERE account_id = ?`
      )
        .bind(accountId)
        .first<{ account_id: string }>();
      if (!existing) {
        throw new VaultError(
          'Google returned no refresh_token and none is stored. Re-run consent with prompt=consent.',
          'no_refresh_token',
          400
        );
      }
      await this.env.DB.prepare(
        `UPDATE tokens SET granted_scopes = ?, expires_at = ?, updated_at = ? WHERE account_id = ?`
      )
        .bind(grantedScopes, ts + expiresIn, ts, accountId)
        .run();
      return;
    }

    const { ciphertext, iv } = await encryptFor(this.master, accountId, refreshToken);
    await this.env.DB.prepare(
      `INSERT INTO tokens (account_id, access_token_enc, refresh_token_enc, key_version, iv,
                           expires_at, granted_scopes, rotated_at, created_at, updated_at)
       VALUES (?, NULL, ?, ?, ?, ?, ?, NULL, ?, ?)
       ON CONFLICT(account_id) DO UPDATE SET
         refresh_token_enc = excluded.refresh_token_enc,
         iv                = excluded.iv,
         key_version       = excluded.key_version,
         expires_at        = excluded.expires_at,
         granted_scopes    = excluded.granted_scopes,
         rotated_at        = ?,
         updated_at        = ?`
    )
      .bind(accountId, ciphertext, KEY_VERSION, iv, ts + expiresIn, grantedScopes, ts, ts, ts, ts)
      .run();

    await this.env.CACHE.delete(`at:${accountId}`);
  }

  /** Get a usable access token, refreshing through Google when needed. */
  async getAccessToken(accountId: string): Promise<string> {
    const cached = await this.env.CACHE.get(`at:${accountId}`);
    if (cached) {
      const [iv, ct] = cached.split('.');
      if (iv && ct) {
        try {
          return await decryptFor(this.master, accountId, ct, iv);
        } catch {
          // key rotated or corrupt cache entry — fall through to a refresh
        }
      }
    }
    return this.refresh(accountId);
  }

  async refresh(accountId: string): Promise<string> {
    const row = await this.env.DB.prepare(
      `SELECT account_id, refresh_token_enc, iv, key_version, expires_at, granted_scopes
         FROM tokens WHERE account_id = ?`
    )
      .bind(accountId)
      .first<TokenRow>();

    if (!row) throw new VaultError(`no credentials stored for ${accountId}`, 'no_credentials', 404);

    const refreshToken = await decryptFor(this.master, accountId, row.refresh_token_enc, row.iv);

    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.env.GOOGLE_CLIENT_ID!,
        client_secret: this.env.GOOGLE_CLIENT_SECRET!,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      }),
    });

    const body = (await res.json()) as any;

    if (!res.ok) {
      if (body?.error === 'invalid_grant') {
        await this.env.DB.prepare(
          `UPDATE accounts SET status = 'reauth_required', last_error = ?, updated_at = ? WHERE account_id = ?`
        )
          .bind('invalid_grant: refresh token revoked or expired', now(), accountId)
          .run();
        await audit(this.env, {
          account_id: accountId,
          action: 'token.refresh',
          outcome: 'reauth_required',
          detail: body,
        });
        throw new ReauthRequired(accountId);
      }
      throw new VaultError(`token refresh failed: ${body?.error ?? res.status}`, 'refresh_failed', 502);
    }

    const ts = now();

    // Rotation safety: if Google handed us a new refresh token, persist it.
    if (body.refresh_token && body.refresh_token !== refreshToken) {
      const { ciphertext, iv } = await encryptFor(this.master, accountId, body.refresh_token);
      await this.env.DB.prepare(
        `UPDATE tokens SET refresh_token_enc = ?, iv = ?, key_version = ?, rotated_at = ?, updated_at = ?
          WHERE account_id = ?`
      )
        .bind(ciphertext, iv, KEY_VERSION, ts, ts, accountId)
        .run();
    }

    const expiresIn: number = body.expires_in ?? 3600;
    const skew = parseInt(this.env.TOKEN_REFRESH_SKEW_SECONDS || '300', 10);
    const cacheTtl = Math.max(60, expiresIn - skew);

    const sealed = await encryptFor(this.master, accountId, body.access_token);
    await this.env.CACHE.put(`at:${accountId}`, `${sealed.iv}.${sealed.ciphertext}`, {
      expirationTtl: cacheTtl,
    });

    await this.env.DB.prepare(
      `UPDATE tokens SET expires_at = ?, updated_at = ? WHERE account_id = ?`
    )
      .bind(ts + expiresIn, ts, accountId)
      .run();

    await this.env.DB.prepare(
      `UPDATE accounts SET status = 'active', last_ok_at = ?, last_error = NULL, updated_at = ?
        WHERE account_id = ? AND status != 'paused'`
    )
      .bind(ts, ts, accountId)
      .run();

    return body.access_token as string;
  }

  /** Revoke at Google, then purge locally. Purges even if Google rejects the revoke. */
  async revoke(accountId: string): Promise<{ googleRevoked: boolean }> {
    let googleRevoked = false;
    const row = await this.env.DB.prepare(
      `SELECT account_id, refresh_token_enc, iv, key_version, expires_at, granted_scopes
         FROM tokens WHERE account_id = ?`
    )
      .bind(accountId)
      .first<TokenRow>();

    if (row) {
      try {
        const refreshToken = await decryptFor(this.master, accountId, row.refresh_token_enc, row.iv);
        const res = await fetch(REVOKE_URL, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ token: refreshToken }),
        });
        googleRevoked = res.ok;
      } catch (e) {
        console.error('revoke_failed', String(e));
      }
    }

    await this.env.CACHE.delete(`at:${accountId}`);
    await this.env.DB.prepare(`DELETE FROM tokens WHERE account_id = ?`).bind(accountId).run();
    await this.env.DB.prepare(`DELETE FROM sync_state WHERE account_id = ?`).bind(accountId).run();
    await this.env.DB.prepare(`DELETE FROM accounts WHERE account_id = ?`).bind(accountId).run();

    return { googleRevoked };
  }
}

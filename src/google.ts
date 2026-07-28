/**
 * Per-account authenticated Google client + Gmail/Drive adapters.
 *
 * The client is deliberately API-agnostic: it injects the bearer, retries once
 * on 401 after a forced refresh, and honours Retry-After on 429. Rate-limit
 * state lives in KV (not a module global) because module globals do not survive
 * isolate boundaries and give you a false sense of throttling.
 */

import { Env, now } from './util';
import { TokenManager, ReauthRequired } from './vault';

export const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
export const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
export const USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo';

/**
 * Capability → scope map. Scopes are requested per account, never as one global
 * constant, so a mailbox you only read never grants Drive write.
 *
 *   restricted    = requires CASA security assessment to verify
 *   sensitive     = requires verification, no CASA
 *   non-sensitive = basic verification only
 */
export const CAPS: Record<string, { scopes: string[]; klass: string; label: string }> = {
  'mail.read': {
    scopes: ['https://www.googleapis.com/auth/gmail.readonly'],
    klass: 'restricted',
    label: 'Read & search mail',
  },
  'mail.send': {
    scopes: [
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.compose',
    ],
    klass: 'sensitive+restricted',
    label: 'Draft & send mail',
  },
  'mail.modify': {
    scopes: ['https://www.googleapis.com/auth/gmail.modify'],
    klass: 'restricted',
    label: 'Label, archive, triage',
  },
  'drive.read': {
    scopes: ['https://www.googleapis.com/auth/drive.readonly'],
    klass: 'restricted',
    label: 'Read & search Drive',
  },
  'drive.write': {
    scopes: ['https://www.googleapis.com/auth/drive'],
    klass: 'restricted',
    label: 'Create, move, share files',
  },
  'drive.app': {
    scopes: ['https://www.googleapis.com/auth/drive.file'],
    klass: 'non-sensitive',
    label: 'Only files this app creates',
  },
};

export const BASE_SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email'];

export function scopesForCaps(caps: string[]): string[] {
  const set = new Set(BASE_SCOPES);
  for (const c of caps) {
    const entry = CAPS[c];
    if (entry) entry.scopes.forEach((s) => set.add(s));
  }
  return [...set];
}

export function capsFromScopes(scopeString: string): string[] {
  const granted = new Set(scopeString.split(/\s+/).filter(Boolean));
  return Object.entries(CAPS)
    .filter(([, v]) => v.scopes.every((s) => granted.has(s)))
    .map(([k]) => k);
}

export class GoogleApiError extends Error {
  constructor(message: string, public status: number, public body?: unknown) {
    super(message);
  }
}

export class GoogleApiClient {
  constructor(private env: Env, private tm: TokenManager, public accountId: string) {}

  async request(url: string, init: RequestInit = {}, isRetry = false): Promise<Response> {
    const host = new URL(url).host;
    const backoff = await this.env.CACHE.get(`rl:${host}`);
    if (backoff && parseInt(backoff, 10) > now()) {
      throw new GoogleApiError(`rate limited on ${host} until ${backoff}`, 429);
    }

    const token = await this.tm.getAccessToken(this.accountId);
    const headers = new Headers(init.headers);
    headers.set('authorization', `Bearer ${token}`);
    if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');

    const res = await fetch(url, { ...init, headers });

    if (res.status === 401 && !isRetry) {
      await this.env.CACHE.delete(`at:${this.accountId}`);
      await this.tm.refresh(this.accountId);
      return this.request(url, init, true);
    }

    if (res.status === 429 || res.status === 503) {
      const retryAfter = parseInt(res.headers.get('retry-after') || '30', 10);
      await this.env.CACHE.put(`rl:${host}`, String(now() + retryAfter), {
        expirationTtl: Math.max(60, retryAfter + 10),
      });
      throw new GoogleApiError(`${host} returned ${res.status}, backing off ${retryAfter}s`, res.status);
    }

    return res;
  }

  async getJson<T = any>(url: string): Promise<T> {
    const res = await this.request(url);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new GoogleApiError(
        (body as any)?.error?.message ?? `HTTP ${res.status}`,
        res.status,
        body
      );
    }
    return body as T;
  }

  async postJson<T = any>(url: string, payload: unknown): Promise<T> {
    const res = await this.request(url, { method: 'POST', body: JSON.stringify(payload) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new GoogleApiError(
        (body as any)?.error?.message ?? `HTTP ${res.status}`,
        res.status,
        body
      );
    }
    return body as T;
  }
}

export function clientFor(env: Env, tm: TokenManager, accountId: string): GoogleApiClient {
  return new GoogleApiClient(env, tm, accountId);
}

/* ------------------------------------------------------------------ */
/* Gmail adapter                                                       */
/* ------------------------------------------------------------------ */

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';

export interface MailHit {
  kind: 'mail';
  id: string;
  threadId: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
  webUrl: string;
}

function header(headers: any[], name: string): string {
  const h = headers?.find((x) => x.name?.toLowerCase() === name.toLowerCase());
  return h?.value ?? '';
}

export async function gmailSearch(
  client: GoogleApiClient,
  query: string,
  limit = 5
): Promise<MailHit[]> {
  const list = await client.getJson<{ messages?: Array<{ id: string; threadId: string }> }>(
    `${GMAIL}/messages?q=${encodeURIComponent(query)}&maxResults=${limit}`
  );
  const messages = list.messages ?? [];
  const detailed = await Promise.all(
    messages.map(async (m) => {
      const full = await client.getJson<any>(
        `${GMAIL}/messages/${m.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date`
      );
      const hs = full.payload?.headers ?? [];
      return {
        kind: 'mail' as const,
        id: full.id,
        threadId: full.threadId,
        subject: header(hs, 'Subject') || '(no subject)',
        from: header(hs, 'From'),
        date: header(hs, 'Date'),
        snippet: full.snippet ?? '',
        webUrl: `https://mail.google.com/mail/u/0/#inbox/${full.threadId}`,
      };
    })
  );
  return detailed;
}

export async function gmailProfile(client: GoogleApiClient) {
  return client.getJson<{ emailAddress: string; messagesTotal: number; threadsTotal: number }>(
    `${GMAIL}/profile`
  );
}

export async function gmailLabels(client: GoogleApiClient) {
  return client.getJson<{ labels: Array<{ id: string; name: string; type: string }> }>(
    `${GMAIL}/labels`
  );
}

/* ------------------------------------------------------------------ */
/* Drive adapter                                                       */
/* ------------------------------------------------------------------ */

const DRIVE = 'https://www.googleapis.com/drive/v3';

export interface FileHit {
  kind: 'file';
  id: string;
  name: string;
  mimeType: string;
  modifiedTime: string;
  owners: string;
  webUrl: string;
  size: string | null;
}

export async function driveSearch(
  client: GoogleApiClient,
  query: string,
  limit = 5
): Promise<FileHit[]> {
  const escaped = query.replace(/'/g, "\\'");
  const q = `(name contains '${escaped}' or fullText contains '${escaped}') and trashed = false`;
  const res = await client.getJson<{ files?: any[] }>(
    `${DRIVE}/files?q=${encodeURIComponent(q)}&pageSize=${limit}` +
      `&fields=${encodeURIComponent(
        'files(id,name,mimeType,modifiedTime,size,webViewLink,owners(emailAddress))'
      )}&supportsAllDrives=true&includeItemsFromAllDrives=true`
  );
  return (res.files ?? []).map((f) => ({
    kind: 'file' as const,
    id: f.id,
    name: f.name,
    mimeType: f.mimeType,
    modifiedTime: f.modifiedTime,
    owners: (f.owners ?? []).map((o: any) => o.emailAddress).join(', '),
    webUrl: f.webViewLink ?? `https://drive.google.com/file/d/${f.id}/view`,
    size: f.size ?? null,
  }));
}

export async function driveRecent(client: GoogleApiClient, limit = 10): Promise<FileHit[]> {
  const res = await client.getJson<{ files?: any[] }>(
    `${DRIVE}/files?orderBy=modifiedTime desc&pageSize=${limit}` +
      `&q=${encodeURIComponent('trashed = false')}` +
      `&fields=${encodeURIComponent(
        'files(id,name,mimeType,modifiedTime,size,webViewLink,owners(emailAddress))'
      )}&supportsAllDrives=true&includeItemsFromAllDrives=true`
  );
  return (res.files ?? []).map((f) => ({
    kind: 'file' as const,
    id: f.id,
    name: f.name,
    mimeType: f.mimeType,
    modifiedTime: f.modifiedTime,
    owners: (f.owners ?? []).map((o: any) => o.emailAddress).join(', '),
    webUrl: f.webViewLink ?? `https://drive.google.com/file/d/${f.id}/view`,
    size: f.size ?? null,
  }));
}

export async function driveAbout(client: GoogleApiClient) {
  return client.getJson<{ storageQuota: any; user: any }>(
    `${DRIVE}/about?fields=${encodeURIComponent('storageQuota,user(emailAddress,displayName)')}`
  );
}

export { ReauthRequired };

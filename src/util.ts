/**
 * Small shared helpers: base64, JSON responses, and signed session cookies.
 * No Google logic and no token logic lives here.
 */

export interface Env {
  DB: D1Database;
  CACHE: KVNamespace;
  ASSETS: Fetcher;
  SWEEP_QUEUE: Queue;
  ENVIRONMENT: string;
  MAX_FANOUT_CONCURRENCY: string;
  PER_ACCOUNT_TIMEOUT_MS: string;
  TOKEN_REFRESH_SKEW_SECONDS: string;
  // secrets
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  VAULT_MASTER_KEY?: string;
  SESSION_SECRET?: string;
  DASH_PASSWORD?: string;
}

const te = new TextEncoder();
const td = new TextDecoder();

export const now = () => Math.floor(Date.now() / 1000);

export function b64(input: ArrayBuffer | Uint8Array): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64url(input: ArrayBuffer | Uint8Array): string {
  return b64(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function randomId(prefix: string, len = 24): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[bytes[i] % alphabet.length];
  return `${prefix}_${out}`;
}

export function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra },
  });
}

export function err(message: string, status = 400, detail?: unknown): Response {
  return json({ error: message, detail: detail ?? null }, status);
}

/* ------------------------------------------------------------------ */
/* Session cookies — HMAC-SHA256 signed, no server-side session store. */
/* ------------------------------------------------------------------ */

const COOKIE = 'go_session';

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ]);
}

export interface SessionPayload {
  exp: number;
  email: string;
  role: 'owner' | 'operator' | 'viewer';
  via: 'google' | 'breakglass';
  name?: string | null;
}

export async function makeSession(
  env: Env,
  p: Omit<SessionPayload, 'exp'>,
  ttlSeconds = 60 * 60 * 12
): Promise<string> {
  const payload = b64url(te.encode(JSON.stringify({ ...p, exp: now() + ttlSeconds })));
  const key = await hmacKey(env.SESSION_SECRET!);
  const sig = b64url(await crypto.subtle.sign('HMAC', key, te.encode(payload)));
  return `${payload}.${sig}`;
}

export async function verifySession(env: Env, token: string | null): Promise<SessionPayload | null> {
  if (!token || !env.SESSION_SECRET) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const key = await hmacKey(env.SESSION_SECRET);
  const expected = b64url(await crypto.subtle.sign('HMAC', key, te.encode(payload)));
  if (expected.length !== sig.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const b64std = payload.replace(/-/g, '+').replace(/_/g, '/');
    const data = JSON.parse(td.decode(unb64(b64std + '='.repeat((4 - (b64std.length % 4)) % 4))));
    if (typeof data.exp !== 'number' || data.exp <= now()) return null;
    if (!data.email || !data.role) return null;
    return data as SessionPayload;
  } catch {
    return null;
  }
}

export function readCookie(request: Request, name = COOKIE): string | null {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

export function sessionCookieHeader(value: string, maxAge = 60 * 60 * 12): string {
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

export function clearCookieHeader(): string {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

/** The authenticated principal for this request, or null. */
export async function principal(request: Request, env: Env): Promise<SessionPayload | null> {
  return verifySession(env, readCookie(request));
}

/* ------------------------------------------------------------------ */
/* Audit                                                               */
/* ------------------------------------------------------------------ */

export async function audit(
  env: Env,
  entry: {
    actor?: string;
    account_id?: string | null;
    action: string;
    target?: string | null;
    outcome?: string;
    detail?: unknown;
  }
): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (ts, actor, account_id, action, target, outcome, detail)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        now(),
        entry.actor ?? 'system',
        entry.account_id ?? null,
        entry.action,
        entry.target ?? null,
        entry.outcome ?? 'ok',
        entry.detail === undefined ? null : JSON.stringify(entry.detail)
      )
      .run();
  } catch (e) {
    // Audit must never break the request it is describing.
    console.error('audit_write_failed', String(e));
  }
}

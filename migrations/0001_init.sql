-- Applied to D1 `google-orchestrator` (17145321-e34d-4f32-8328-a6e70906219e).
-- Kept here as the source of truth for the shape the Worker expects.
-- Migrate FORWARD from this; do not recreate.

CREATE TABLE IF NOT EXISTS accounts (
  account_id    TEXT PRIMARY KEY,
  email         TEXT NOT NULL,
  domain        TEXT,
  label         TEXT,
  kind          TEXT NOT NULL DEFAULT 'personal',   -- personal | workspace
  status        TEXT NOT NULL DEFAULT 'active',     -- active | paused | reauth_required
  scopes        TEXT NOT NULL DEFAULT '',
  gmail_enabled INTEGER NOT NULL DEFAULT 0,
  drive_enabled INTEGER NOT NULL DEFAULT 0,
  last_ok_at    INTEGER,
  last_error    TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_email  ON accounts(email);
CREATE INDEX        IF NOT EXISTS idx_accounts_status ON accounts(status);

-- refresh_token_enc is AES-GCM ciphertext; iv is its nonce; key_version tracks
-- which master key generation encrypted it. Access tokens are NOT stored here --
-- they live in KV with a TTL, so one iv column never covers two ciphertexts.
CREATE TABLE IF NOT EXISTS tokens (
  account_id        TEXT PRIMARY KEY,
  access_token_enc  TEXT,
  refresh_token_enc TEXT NOT NULL,
  key_version       INTEGER NOT NULL DEFAULT 1,
  iv                TEXT NOT NULL,
  expires_at        INTEGER NOT NULL DEFAULT 0,
  granted_scopes    TEXT NOT NULL DEFAULT '',
  rotated_at        INTEGER,
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
);

-- Single-use, expiring CSRF state. consumed_at is set atomically in the callback.
CREATE TABLE IF NOT EXISTS oauth_state (
  state            TEXT PRIMARY KEY,
  account_id       TEXT,
  requested_scopes TEXT NOT NULL DEFAULT '',
  pkce_verifier    TEXT,
  expires_at       INTEGER NOT NULL,
  consumed_at      INTEGER,
  created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sweeps (
  sweep_id       TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  kind           TEXT NOT NULL,
  cron           TEXT,
  account_filter TEXT NOT NULL DEFAULT '*',
  config         TEXT NOT NULL DEFAULT '{}',
  enabled        INTEGER NOT NULL DEFAULT 1,
  last_run_at    INTEGER,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sweep_runs (
  run_id          TEXT PRIMARY KEY,
  sweep_id        TEXT NOT NULL,
  started_at      INTEGER NOT NULL,
  finished_at     INTEGER,
  status          TEXT NOT NULL DEFAULT 'running',
  accounts_total  INTEGER NOT NULL DEFAULT 0,
  accounts_ok     INTEGER NOT NULL DEFAULT 0,
  accounts_failed INTEGER NOT NULL DEFAULT 0,
  items_processed INTEGER NOT NULL DEFAULT 0,
  error           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sweep_runs_sweep ON sweep_runs(sweep_id, started_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  actor      TEXT NOT NULL DEFAULT 'system',
  account_id TEXT,
  action     TEXT NOT NULL,
  target     TEXT,
  outcome    TEXT NOT NULL DEFAULT 'ok',
  detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts      ON audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id, ts DESC);

CREATE TABLE IF NOT EXISTS sync_state (
  account_id     TEXT NOT NULL,
  surface        TEXT NOT NULL,   -- gmail | drive
  cursor         TEXT,
  history_id     TEXT,
  page_token     TEXT,
  last_synced_at INTEGER,
  PRIMARY KEY (account_id, surface)
);

-- Per-user identity. Google sign-in replaces the single shared password as the
-- normal way in; DASH_PASSWORD survives only as owner break-glass.
CREATE TABLE IF NOT EXISTS users (
  email         TEXT PRIMARY KEY,
  name          TEXT,
  role          TEXT NOT NULL DEFAULT 'viewer',   -- owner | operator | viewer
  status        TEXT NOT NULL DEFAULT 'active',   -- active | suspended
  account_scope TEXT NOT NULL DEFAULT 'allowlist',-- all | allowlist
  invited_by    TEXT,
  last_login_at INTEGER,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

-- Which connected Google accounts a scoped user may reach.
CREATE TABLE IF NOT EXISTS user_accounts (
  email      TEXT NOT NULL,
  account_id TEXT NOT NULL,
  granted_by TEXT,
  granted_at INTEGER NOT NULL,
  PRIMARY KEY (email, account_id)
);
CREATE INDEX IF NOT EXISTS idx_user_accounts_email ON user_accounts(email);

-- oauth_state now serves two flows: connecting a Google account to the vault,
-- and signing a human in. Same redirect URI, distinguished here.
ALTER TABLE oauth_state ADD COLUMN purpose TEXT NOT NULL DEFAULT 'connect';

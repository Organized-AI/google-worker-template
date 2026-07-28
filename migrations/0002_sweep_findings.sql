CREATE TABLE IF NOT EXISTS sweep_findings (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id     TEXT NOT NULL,
  account_id TEXT NOT NULL,
  kind       TEXT NOT NULL,
  title      TEXT NOT NULL,
  url        TEXT,
  detail     TEXT,
  ts         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON sweep_findings(run_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_acct ON sweep_findings(account_id, ts DESC);

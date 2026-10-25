-- Subscribers with double opt-in. Filters are stored as JSON text arrays.
CREATE TABLE IF NOT EXISTS subscribers (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  email            TEXT NOT NULL UNIQUE COLLATE NOCASE,
  status           TEXT NOT NULL DEFAULT 'pending',   -- pending | active | unsubscribed
  verify_hash      TEXT,                              -- sha256 of emailed token
  verify_expires   INTEGER,                           -- unix seconds
  created_at       INTEGER NOT NULL,
  verified_at      INTEGER,
  last_verify_sent INTEGER,
  last_digest_at   INTEGER,                           -- unix seconds; digest only sends CVEs seen after this
  min_severity     TEXT NOT NULL DEFAULT 'HIGH',      -- ALL | LOW | MEDIUM | HIGH | CRITICAL
  kev_only         INTEGER NOT NULL DEFAULT 0,
  min_epss         REAL NOT NULL DEFAULT 0,           -- 0..1
  vendors          TEXT NOT NULL DEFAULT '[]',        -- JSON array, lowercase CPE vendor/product names
  keywords         TEXT NOT NULL DEFAULT '[]',        -- JSON array, matched in description
  cwes             TEXT NOT NULL DEFAULT '[]'         -- JSON array like ["CWE-79"]
);

CREATE INDEX IF NOT EXISTS idx_subscribers_status ON subscribers(status);

-- Admin page support. No personal data: IPs are stored only as truncated HMACs, audit rows reference subscriber ids, never emails.
CREATE TABLE IF NOT EXISTS admin_throttle (
  key          TEXT PRIMARY KEY,          -- "ip:<hmac>" or "global"
  fails        INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL,
  locked_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admin_audit (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  at            INTEGER NOT NULL,
  action        TEXT NOT NULL,            -- login_ok | login_fail | logout | reveal | unsubscribe | delete
  subscriber_id INTEGER,
  ip_hash       TEXT
);

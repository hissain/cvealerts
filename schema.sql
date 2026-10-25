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

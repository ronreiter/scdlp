PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS audit (
    id              INTEGER PRIMARY KEY,
    ts              INTEGER NOT NULL,
    file_path       TEXT NOT NULL,
    file_key        TEXT NOT NULL,
    file_key_kind   TEXT NOT NULL,
    process_pid     INTEGER NOT NULL,
    process_exe     TEXT NOT NULL,
    process_chain   TEXT NOT NULL,
    identity_key    TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    rule_id         INTEGER,
    matched_kind    TEXT,
    duration_us     INTEGER
);

CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit(ts DESC);

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS rules (
    id              INTEGER PRIMARY KEY,
    file_key        TEXT NOT NULL,
    file_key_kind   TEXT NOT NULL CHECK (file_key_kind IN ('path','category')),
    identity_key    TEXT NOT NULL,
    identity_kind   TEXT NOT NULL CHECK (identity_kind IN ('chain','exe-only')),
    verdict         TEXT NOT NULL CHECK (verdict IN ('allow','deny')),
    created_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL,
    expires_at      INTEGER,
    note            TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS rules_lookup_idx
    ON rules (file_key, file_key_kind, identity_key, identity_kind);

CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

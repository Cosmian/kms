-- SQLite-specific SQL queries.
--
-- These queries override entries from query.sql when SQLite JSON syntax diverges
-- from the PostgreSQL / shared syntax.  The `get_sqlite_query!` macro checks this
-- file first and falls back to `PGSQL_QUERIES` (query.sql) for any name not found here.

-- name: count-non-destroyed-keys
SELECT COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND (
    json_type(object, '$.SymmetricKey') IS NOT NULL OR
    json_type(object, '$.PrivateKey')   IS NOT NULL OR
    json_type(object, '$.PublicKey')    IS NOT NULL OR
    json_type(object, '$.SplitKey')     IS NOT NULL
);

-- ── CRL persistence (SQLite-specific override) ────────────────────────────────
-- SQLite uses BLOB instead of PostgreSQL's BYTEA.

-- name: create-table-crls
CREATE TABLE IF NOT EXISTS crls (
    issuer_id    TEXT    NOT NULL PRIMARY KEY,
    crl_der      BLOB    NOT NULL,
    crl_number   INTEGER NOT NULL,
    generated_at TEXT    NOT NULL,
    next_update  TEXT    NOT NULL
);

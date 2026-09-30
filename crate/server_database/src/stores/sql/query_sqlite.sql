-- SQLite-specific SQL queries.
--
-- These queries override entries from query.sql when SQLite JSON syntax diverges
-- from the PostgreSQL / shared syntax.  The `get_sqlite_query!` macro checks this
-- file first and falls back to `PGSQL_QUERIES` (query.sql) for any name not found here.

-- name: count-non-destroyed-keys
SELECT COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND json_extract(attributes, '$.ObjectType') IN ('SymmetricKey', 'PrivateKey', 'PublicKey', 'SplitKey');

-- name: create-index-objects-rotate-lookup
CREATE INDEX IF NOT EXISTS idx_objects_rotate_name ON objects (json_extract(attributes, '$.RotateName'), owner) WHERE json_extract(attributes, '$.RotateName') IS NOT NULL;

-- name: create-index-objects-rotate-auto
CREATE INDEX IF NOT EXISTS idx_objects_rotate_auto ON objects (state) WHERE json_extract(attributes, '$.RotateAutomatic') = 1;

-- name: create-index-objects-type-state
CREATE INDEX IF NOT EXISTS idx_objects_type_state ON objects (json_extract(attributes, '$.ObjectType'), state);

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

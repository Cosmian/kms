-- SQLite-specific SQL queries.
--
-- These queries override entries from query.sql when SQLite JSON syntax diverges
-- from the PostgreSQL / shared syntax.  The `get_sqlite_query!` macro checks this
-- file first and falls back to `pgsql_queries()` (query.sql) for any name not found here.

-- ── Optimistic locking: per-object `version` counter, bumped by every write ──

-- name: create-table-objects
CREATE TABLE IF NOT EXISTS objects (
        id VARCHAR(128) PRIMARY KEY,
        object VARCHAR NOT NULL,
        attributes jsonb NOT NULL,
        state VARCHAR(32),
        owner VARCHAR(255),
        wrapping_key_id VARCHAR(128),
        version INTEGER NOT NULL DEFAULT 0
);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state, objects.version
        FROM objects
        WHERE objects.id=$1;

-- name: update-object-with-object
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3, version=version+1 WHERE id=$4;

-- name: update-object-with-object-if-version
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3, version=version+1 WHERE id=$4 AND version=$5;

-- name: update-object-with-state
UPDATE objects SET state=$1, version=version+1 WHERE id=$2;

-- name: upsert-object
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT(id)
        DO UPDATE SET object=$2, attributes=$3, state=$4, owner=$5, wrapping_key_id=$6, version=objects.version+1
        WHERE objects.owner=$5;

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

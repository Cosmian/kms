-- Never put a `--` comment between a `-- name:` tag and its query's closing `;`: the rawsql loader joins a query's lines with spaces, so a mid-body `--` would comment out the rest, including the `;`.

-- name: create-table-audit-events
CREATE TABLE IF NOT EXISTS kms_audit_events (
    instance_id      TEXT        NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 255),
    chain_generation BIGINT      NOT NULL CHECK (chain_generation >= 0),
    id               BIGINT      NOT NULL CHECK (id >= 0),
    timestamp        TIMESTAMPTZ NOT NULL,
    operation        TEXT        NOT NULL,
    username         TEXT        NOT NULL,
    object_uid       TEXT,
    algorithm        TEXT,
    client_ip        TEXT,
    result           TEXT        NOT NULL,
    duration_ms      BIGINT      NOT NULL CHECK (duration_ms >= 0),
    request_id       UUID,
    details          TEXT,
    prev_hash        BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    row_hash         BYTEA       NOT NULL CHECK (octet_length(row_hash) = 32),
    PRIMARY KEY (instance_id, chain_generation, id)
);

-- for info: the KMS does not need this index, but it's kept for the convenience of auditors
-- as time-based queries are common, and a B-tree index is cheap to maintain relative to that.
-- name: create-index-audit-events-timestamp
CREATE INDEX IF NOT EXISTS idx_kms_audit_events_timestamp ON kms_audit_events (timestamp);

-- name: create-audit-append-only-guard
CREATE OR REPLACE FUNCTION kms_audit_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $BODY$ BEGIN RAISE EXCEPTION 'kms_audit_events is append-only: % is not permitted', TG_OP USING ERRCODE = '23001'; END; $BODY$;

-- name: create-audit-trigger-no-update
DROP TRIGGER IF EXISTS kms_audit_no_update ON kms_audit_events;

-- name: create-audit-trigger-no-update-create
CREATE TRIGGER kms_audit_no_update BEFORE UPDATE ON kms_audit_events FOR EACH ROW EXECUTE FUNCTION kms_audit_reject_mutation();

-- name: create-audit-trigger-no-delete
DROP TRIGGER IF EXISTS kms_audit_no_delete ON kms_audit_events;

-- name: create-audit-trigger-no-delete-create
CREATE TRIGGER kms_audit_no_delete BEFORE DELETE ON kms_audit_events FOR EACH ROW EXECUTE FUNCTION kms_audit_reject_mutation();

-- PostgreSQL never fires row-level triggers for TRUNCATE; only a statement-level
-- trigger can reject it, and this is what stops the table owner (exempt from REVOKE)
-- from truncating the table with its own ordinary credentials.
-- name: create-audit-trigger-no-truncate
DROP TRIGGER IF EXISTS kms_audit_no_truncate ON kms_audit_events;

-- name: create-audit-trigger-no-truncate-create
CREATE TRIGGER kms_audit_no_truncate BEFORE TRUNCATE ON kms_audit_events FOR EACH STATEMENT EXECUTE FUNCTION kms_audit_reject_mutation();

-- name: create-audit-revoke-mutations
REVOKE UPDATE, DELETE, TRUNCATE ON kms_audit_events FROM PUBLIC;

-- name: select-audit-schema-columns
SELECT instance_id, chain_generation, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash FROM kms_audit_events LIMIT 0;

-- name: select-audit-advisory-lock
SELECT pg_try_advisory_lock(hashtextextended($1, 0));

-- name: insert-audit-event
INSERT INTO kms_audit_events (instance_id, chain_generation, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: select-audit-latest-generation
SELECT MAX(chain_generation) FROM kms_audit_events WHERE instance_id = $1;

-- name: select-audit-generations
SELECT DISTINCT chain_generation FROM kms_audit_events WHERE instance_id = $1 ORDER BY chain_generation ASC;

-- name: select-audit-events-page
SELECT instance_id, chain_generation, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash FROM kms_audit_events WHERE instance_id = $1 AND chain_generation = $2 AND id > $3 ORDER BY id ASC LIMIT $4;

-- name: select-audit-instances
SELECT DISTINCT instance_id FROM kms_audit_events ORDER BY instance_id ASC;

-- name: select-audit-event-row-hash
SELECT row_hash FROM kms_audit_events WHERE instance_id = $1 AND chain_generation = $2 AND id = $3;

-- name: select-audit-generation-evidence
SELECT id, 'v1' || '|' || encode(convert_to(instance_id, 'UTF8'), 'hex') || '|' || chain_generation || '|' || id || '|' || to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' || encode(convert_to(operation, 'UTF8'), 'hex') || '|' || encode(convert_to(username, 'UTF8'), 'hex') || '|' || COALESCE(encode(convert_to(object_uid, 'UTF8'), 'hex'), '-') || '|' || COALESCE(encode(convert_to(algorithm, 'UTF8'), 'hex'), '-') || '|' || COALESCE(encode(convert_to(client_ip, 'UTF8'), 'hex'), '-') || '|' || encode(convert_to(result, 'UTF8'), 'hex') || '|' || duration_ms || '|' || COALESCE(request_id::text, '-') || '|' || COALESCE(encode(convert_to(details, 'UTF8'), 'hex'), '-') || '|' || encode(prev_hash, 'hex') || '|' || encode(row_hash, 'hex') AS evidence_line FROM kms_audit_events WHERE instance_id = $1 AND chain_generation = $2 AND id > $3 ORDER BY id ASC LIMIT $4;


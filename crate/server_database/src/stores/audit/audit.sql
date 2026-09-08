-- name: create-table-audit-events
CREATE TABLE IF NOT EXISTS kms_audit_events (
    instance_id  TEXT        NOT NULL CHECK (length(instance_id) BETWEEN 1 AND 255),
    id           BIGINT      NOT NULL CHECK (id >= 0),
    timestamp    TIMESTAMPTZ NOT NULL,
    operation    TEXT        NOT NULL,
    username     TEXT        NOT NULL,
    object_uid   TEXT,
    algorithm    TEXT,
    client_ip    TEXT,
    result       TEXT        NOT NULL,
    duration_ms  BIGINT      NOT NULL CHECK (duration_ms >= 0),
    request_id   UUID,
    details      TEXT,
    prev_hash    BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    row_hash     BYTEA       NOT NULL CHECK (octet_length(row_hash) = 32),
    PRIMARY KEY (instance_id, id)
);

-- name: add-column-audit-events-details
ALTER TABLE kms_audit_events ADD COLUMN IF NOT EXISTS details TEXT;

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

-- name: create-audit-revoke-mutations
REVOKE UPDATE, DELETE, TRUNCATE ON kms_audit_events FROM PUBLIC;

-- name: select-audit-schema-columns
SELECT instance_id, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash FROM kms_audit_events LIMIT 0;

-- name: select-audit-advisory-lock
SELECT pg_try_advisory_lock(hashtextextended($1, 0));

-- name: insert-audit-event
INSERT INTO kms_audit_events (instance_id, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: select-audit-chain-head
SELECT instance_id, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash FROM kms_audit_events WHERE instance_id = $1 ORDER BY id DESC LIMIT 1;

-- name: select-audit-events-page
SELECT instance_id, id, timestamp, operation, username, object_uid, algorithm, client_ip, result, duration_ms, request_id, details, prev_hash, row_hash FROM kms_audit_events WHERE instance_id = $1 AND id > $2 ORDER BY id ASC LIMIT $3;

-- name: select-audit-instances
SELECT DISTINCT instance_id FROM kms_audit_events ORDER BY instance_id ASC;

-- name: select-audit-table-exists
SELECT to_regclass('kms_audit_events') IS NOT NULL;

-- name: select-audit-event-row-hash
SELECT row_hash FROM kms_audit_events WHERE instance_id = $1 AND id = $2;

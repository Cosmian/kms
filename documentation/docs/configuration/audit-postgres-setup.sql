-- Production setup for the Cosmian KMS PostgreSQL audit backend.
--
-- Run this as a superuser (or a role with CREATEROLE/CREATEDB) against a database dedicated
-- to the audit trail, SEPARATE from the KMS's main object-storage database.
--
-- The KMS's own auto-DDL path (on first connection, if `kms_audit_events` does not exist)
-- is a development convenience only. In production, the KMS must NOT own the table: an
-- owner can bypass its own grants and disable its own triggers. Provision the schema here,
-- under a dedicated owner role, and grant the KMS a role with only INSERT/SELECT.

-- 1. Roles
CREATE ROLE kms_audit_owner  WITH LOGIN PASSWORD 'CHANGE_ME_OWNER';
CREATE ROLE kms_audit_writer WITH LOGIN PASSWORD 'CHANGE_ME_WRITER';

-- 2. Schema, owned by kms_audit_owner (connect as kms_audit_owner for the statements below,
--    or use `ALTER TABLE ... OWNER TO kms_audit_owner;` afterwards)
CREATE TABLE IF NOT EXISTS kms_audit_events (
    instance_id  TEXT        NOT NULL,
    id           BIGINT      NOT NULL,
    timestamp    TIMESTAMPTZ NOT NULL,
    operation    TEXT        NOT NULL,
    username     TEXT        NOT NULL,
    object_uid   TEXT,
    algorithm    TEXT,
    client_ip    TEXT,
    result       TEXT        NOT NULL,
    duration_ms  BIGINT      NOT NULL,
    request_id   UUID,
    prev_hash    BYTEA       NOT NULL,
    row_hash     BYTEA       NOT NULL,
    PRIMARY KEY (instance_id, id)
);

CREATE INDEX IF NOT EXISTS idx_kms_audit_events_timestamp ON kms_audit_events (timestamp);

CREATE OR REPLACE FUNCTION kms_audit_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $BODY$ BEGIN RAISE EXCEPTION 'kms_audit_events is append-only: % is not permitted', TG_OP USING ERRCODE = '23001'; END; $BODY$;

DROP TRIGGER IF EXISTS kms_audit_no_update ON kms_audit_events;
CREATE TRIGGER kms_audit_no_update BEFORE UPDATE ON kms_audit_events FOR EACH ROW EXECUTE FUNCTION kms_audit_reject_mutation();

DROP TRIGGER IF EXISTS kms_audit_no_delete ON kms_audit_events;
CREATE TRIGGER kms_audit_no_delete BEFORE DELETE ON kms_audit_events FOR EACH ROW EXECUTE FUNCTION kms_audit_reject_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON kms_audit_events FROM PUBLIC;

-- 3. Grant the KMS's own role the minimum it needs: INSERT for the writer, SELECT so
--    `ckms audit export|verify` can also use this same role for read-only access.
GRANT INSERT, SELECT ON kms_audit_events TO kms_audit_writer;

-- kms_audit_writer has no privilege to run CREATE OR REPLACE FUNCTION, DROP TRIGGER, or
-- REVOKE, so the KMS's own auto-DDL bootstrap path is a guaranteed no-op once this script has
-- run — it only fires if `to_regclass('kms_audit_events')` is NULL.

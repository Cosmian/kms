
-- name: create-table-parameters
CREATE TABLE IF NOT EXISTS parameters (
  name VARCHAR(128) PRIMARY KEY,
  value VARCHAR(256)
);

-- name: upsert-parameter
INSERT INTO parameters (name,value) VALUES ($1, $2)
        ON CONFLICT(name)
        DO UPDATE SET value=$2
        WHERE parameters.name=$1;

-- name: select-parameter
SELECT value FROM parameters WHERE name=$1;

-- name: insert-parameter-if-absent
INSERT INTO parameters (name,value) VALUES ($1, $2) ON CONFLICT(name) DO NOTHING;

-- name: delete-parameter
DELETE FROM parameters WHERE name=$1;

-- name: has-table-parameters
SELECT to_regclass('parameters') IS NOT NULL;

-- 1263358785 is ASCII "KMSA" (audit schema bootstrap uses slot 1); slot 2 serializes startup migrations.
-- name: select-migration-advisory-lock
SELECT pg_try_advisory_lock(1263358785, 2);


-- name: create-table-objects
CREATE TABLE IF NOT EXISTS objects (
        id VARCHAR(128) PRIMARY KEY,
        object VARCHAR NOT NULL,
        attributes jsonb NOT NULL,
        state VARCHAR(32),
        owner VARCHAR(255),
        wrapping_key_id VARCHAR(128)
);
-- name: add-column-attributes
ALTER TABLE objects ADD COLUMN attributes json;
-- name: has-column-attributes
SELECT attributes from objects;

-- name: add-column-wrapping-key-id
ALTER TABLE objects ADD COLUMN IF NOT EXISTS wrapping_key_id VARCHAR(128);

-- name: add-column-version
ALTER TABLE objects ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 0;

-- name: has-objects
SELECT 1 FROM objects LIMIT 1;

-- name: is-attributes-jsonb
SELECT atttypid = 'jsonb'::regtype FROM pg_attribute WHERE attrelid = 'objects'::regclass AND attname = 'attributes';

-- name: alter-attributes-jsonb
ALTER TABLE objects ALTER COLUMN attributes TYPE jsonb USING attributes::jsonb;

-- name: create-table-read_access
CREATE TABLE IF NOT EXISTS read_access (
        id VARCHAR(128),
        userid VARCHAR(255),
        permissions json NOT NULL,
        UNIQUE (id, userid)
);

-- name: create-table-tags
CREATE TABLE IF NOT EXISTS tags (
        id VARCHAR(128),
        tag VARCHAR(255),
        UNIQUE (id, tag)
);

-- name: clean-table-objects
DELETE FROM objects;

-- name: clean-table-read_access
DELETE FROM read_access;

-- name: clean-table-tags
DELETE FROM tags;

-- name: clean-table-crls
DELETE FROM crls;

-- name: insert-objects
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) VALUES ($1, $2, $3, $4, $5, $6);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state, objects.version
        FROM objects
        WHERE objects.id=$1;

-- name: select-object-state
SELECT objects.state, objects.attributes FROM objects WHERE objects.id=$1;

-- name: update-object-with-object
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3, version=version+1 WHERE id=$4;

-- name: update-object-with-object-if-version
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3, version=version+1 WHERE id=$4 AND version=$5;

-- name: update-object-if-owned-version
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3, version=version+1
WHERE id=$4 AND owner=$5 AND version=$6 AND state<>$7 AND state<>$8;

-- name: update-object-with-state
UPDATE objects SET state=$1, version=version+1 WHERE id=$2;

-- name: delete-object
DELETE FROM objects WHERE id=$1;

-- name: upsert-object
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT(id)
        DO UPDATE SET object=$2, attributes=$3, state=$4, owner=$5, wrapping_key_id=$6, version=objects.version+1
        WHERE objects.owner=$5;

-- name: select-user-accesses-for-object
SELECT permissions
        FROM read_access
        WHERE id=$1 AND userid=$2;

-- name: upsert-row-read_access
INSERT INTO read_access (id, userid, permissions) VALUES ($1, $2, $3)
        ON CONFLICT(id, userid)
        DO UPDATE SET permissions=$3
        WHERE read_access.id=$1 AND read_access.userid=$2;

-- name: delete-rows-read_access
DELETE FROM read_access WHERE id=$1 AND userid=$2;

-- name: delete-read-access-for-object
DELETE FROM read_access WHERE id=$1;

-- name: has-row-objects
SELECT 1 FROM objects WHERE id=$1 AND owner=$2;

-- name: update-rows-read_access-with-permission
UPDATE read_access SET permissions=$3
        WHERE id=$1 AND userid=$2;

-- name: select-rows-read_access-with-object-id
SELECT userid, permissions
        FROM read_access
        WHERE id=$1;

-- name: select-objects-access-obtained
SELECT read_access.id, COALESCE(objects.owner, ''), COALESCE(objects.state, 'Active'), read_access.permissions
        FROM read_access
        LEFT JOIN objects
        ON objects.id = read_access.id
        WHERE read_access.userid=$1 OR read_access.userid='*';

-- name: insert-tags
INSERT INTO tags (id, tag) VALUES ($1, $2);

-- name: insert-tags-if-absent
INSERT INTO tags (id, tag) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: select-tags
SELECT tag FROM tags WHERE id=$1;

-- name: delete-tags
DELETE FROM tags WHERE id=$1;


-- name: select-from-tags
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state
FROM objects
INNER JOIN (
    SELECT id
    FROM tags
    WHERE tag IN (@TAGS)
    GROUP BY id
    HAVING COUNT(DISTINCT tag) = @LEN
) AS matched_tags
ON objects.id = matched_tags.id;

-- name: select-uids-from-tags
SELECT id FROM tags WHERE tag IN (@TAGS) GROUP BY id HAVING COUNT(DISTINCT tag) = @LEN;

-- name: create-index-objects-owner
CREATE INDEX IF NOT EXISTS idx_objects_owner ON objects (owner);

-- name: create-index-objects-state
CREATE INDEX IF NOT EXISTS idx_objects_state ON objects (state);

-- name: create-index-read_access-userid
CREATE INDEX IF NOT EXISTS idx_read_access_userid ON read_access (userid);

-- name: create-index-objects-wrapping-key-id
CREATE INDEX IF NOT EXISTS idx_objects_wrapping_key_id ON objects (wrapping_key_id);

-- name: create-index-tags-tag-id
CREATE INDEX IF NOT EXISTS idx_tags_tag_id ON tags (tag, id);

-- name: create-index-objects-rotate-lookup
CREATE INDEX IF NOT EXISTS idx_objects_rotate_name ON objects ((attributes ->> 'RotateName'), owner) WHERE (attributes ->> 'RotateName') IS NOT NULL;

-- name: create-index-objects-rotate-auto
CREATE INDEX IF NOT EXISTS idx_objects_rotate_auto ON objects (state) WHERE (attributes ->> 'RotateAutomatic') = 'true';

-- name: create-index-objects-type-state
CREATE INDEX IF NOT EXISTS idx_objects_type_state ON objects ((attributes ->> 'ObjectType'), state);

-- name: list-uids-for-tags
SELECT id FROM tags WHERE tag = ANY($1::text[]) GROUP BY id HAVING COUNT(DISTINCT tag) = $2::int;

-- name: find-wrapped-by
SELECT DISTINCT objects.id, objects.state, objects.attributes
FROM objects
LEFT JOIN read_access ON objects.id = read_access.id AND read_access.userid = $2
WHERE (objects.owner = $2 OR read_access.userid = $2)
  AND objects.wrapping_key_id = $1;

-- name: select-objects-null-wrapping-key
SELECT id, object FROM objects WHERE wrapping_key_id IS NULL;

-- name: update-wrapping-key-id
UPDATE objects SET wrapping_key_id = $1 WHERE id = $2;

-- name: select-certificates-missing-serial-tag
SELECT objects.id, objects.object FROM objects
INNER JOIN tags c ON c.id = objects.id AND c.tag = '_cert'
WHERE NOT EXISTS (SELECT 1 FROM tags s WHERE s.id = objects.id AND SUBSTR(s.tag, 1, 8) = '_serial=');

-- name: create-table-crypto_officer_activations
CREATE TABLE IF NOT EXISTS crypto_officer_activations (
        activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        activated_by VARCHAR(255),
        sealed_record TEXT NOT NULL,
        revoked_at TIMESTAMP,
        revoked_by VARCHAR(255)
);

-- name: insert-crypto-officer-activation
INSERT INTO crypto_officer_activations (sealed_record, activated_by)
        VALUES ($1, $2);

-- name: select-active-crypto-officer-activation-by
SELECT sealed_record FROM crypto_officer_activations
        WHERE activated_by = $1 AND revoked_at IS NULL
        ORDER BY activated_at DESC LIMIT 1;

-- name: select-any-active-crypto-officer-activation
SELECT COUNT(*) FROM crypto_officer_activations WHERE revoked_at IS NULL;

-- name: revoke-crypto-officer-activation
UPDATE crypto_officer_activations SET revoked_at = CURRENT_TIMESTAMP, revoked_by = $1, sealed_record = ''
        WHERE activated_by = $2 AND revoked_at IS NULL;

-- name: tombstone-revoked-crypto-officer-activations
UPDATE crypto_officer_activations SET sealed_record = ''
        WHERE revoked_at IS NOT NULL AND sealed_record <> '';

-- name: count-all-non-destroyed
SELECT COUNT(*) FROM objects WHERE state != 'Destroyed';

-- name: count-non-destroyed-keys
SELECT COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND (attributes ->> 'ObjectType') IN ('SymmetricKey', 'PrivateKey', 'PublicKey', 'SplitKey');

-- name: key-inventory
SELECT attributes ->> 'ObjectType', attributes ->> 'CryptographicAlgorithm',
(attributes ->> 'CryptographicLength')::BIGINT, state, COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND (attributes ->> 'ObjectType') IN ('SymmetricKey', 'PrivateKey', 'PublicKey', 'SplitKey')
GROUP BY 1, 2, 3, 4;

-- name: key-deactivation-dates
SELECT (attributes -> 'DeactivationDate')::TEXT FROM objects
WHERE state IN ('PreActive', 'Active')
AND (attributes ->> 'ObjectType') IN ('SymmetricKey', 'PrivateKey', 'PublicKey', 'SplitKey')
AND attributes -> 'DeactivationDate' IS NOT NULL;

-- ── CRL persistence (RFC 5280 §5) ─────────────────────────────────────────────
-- One row per CA issuer. On regeneration the row is replaced in-place so that
-- the public CDP endpoint can resume serving the last signed CRL after restart.

-- name: create-table-crls
CREATE TABLE IF NOT EXISTS crls (
    issuer_id    VARCHAR(128) NOT NULL PRIMARY KEY,
    crl_der      BYTEA        NOT NULL,
    crl_number   BIGINT       NOT NULL,
    generated_at VARCHAR(32)  NOT NULL,
    next_update  VARCHAR(32)  NOT NULL
);

-- name: upsert-crl
INSERT INTO crls (issuer_id, crl_der, crl_number, generated_at, next_update)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (issuer_id)
    DO UPDATE SET
        crl_der      = EXCLUDED.crl_der,
        crl_number   = EXCLUDED.crl_number,
        generated_at = EXCLUDED.generated_at,
        next_update  = EXCLUDED.next_update;

-- name: select-crl
SELECT crl_der, generated_at FROM crls WHERE issuer_id = $1;

-- name: list-crl-issuers
SELECT issuer_id, next_update FROM crls ORDER BY issuer_id;

-- name: health-check
SELECT 1;

-- name: select-max-crl-number
SELECT MAX(crl_number) FROM crls;

-- name: alter-column-attributes-jsonb
ALTER TABLE objects ALTER COLUMN attributes TYPE jsonb USING attributes::jsonb;

-- name: add-column-co-activated-by
ALTER TABLE crypto_officer_activations ADD COLUMN IF NOT EXISTS activated_by VARCHAR(255);

-- name: create-unique-index-co-activations-active
CREATE UNIQUE INDEX IF NOT EXISTS idx_co_activations_active
        ON crypto_officer_activations (activated_by)
        WHERE revoked_at IS NULL;

-- name: select-pg-backend-ssl
SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid();

-- ── AES-GCM invocation counter (NIST SP 800-38D §8.3) ──────────────────────────
-- One row per key, apart from the objects table so that counting never changes an object's
-- version. `reserve-gcm-invocations` adds $2 to the count and returns the new count, or no row
-- when the new count would exceed $3.

-- name: create-table-gcm_invocations
CREATE TABLE IF NOT EXISTS gcm_invocations (
    object_id VARCHAR(128) NOT NULL PRIMARY KEY,
    count     BIGINT       NOT NULL
);

-- name: clean-table-gcm_invocations
DELETE FROM gcm_invocations;

-- name: purge-orphan-gcm-invocations
DELETE FROM gcm_invocations WHERE object_id NOT IN (SELECT id FROM objects);

-- name: reserve-gcm-invocations
INSERT INTO gcm_invocations (object_id, count) VALUES ($1, $2)
ON CONFLICT (object_id) DO UPDATE SET count = gcm_invocations.count + $2
WHERE gcm_invocations.count + $2 <= $3
RETURNING count;

-- name: delete-gcm-invocations
DELETE FROM gcm_invocations WHERE object_id = $1;

-- name: create-table-cluster-nodes
CREATE TABLE IF NOT EXISTS cluster_nodes (
    node_id         VARCHAR(64)  NOT NULL PRIMARY KEY,
    version         VARCHAR(64)  NOT NULL,
    last_heartbeat  BIGINT       NOT NULL,
    is_leader       BOOLEAN      NOT NULL DEFAULT FALSE
);

-- name: clear-cluster-leader
UPDATE cluster_nodes SET is_leader = FALSE;

-- name: upsert-cluster-node
INSERT INTO cluster_nodes (node_id, version, last_heartbeat, is_leader)
VALUES ($1, $2, $3, $4)
ON CONFLICT (node_id) DO UPDATE SET
    version = EXCLUDED.version,
    last_heartbeat = EXCLUDED.last_heartbeat,
    is_leader = EXCLUDED.is_leader;

-- name: delete-stale-cluster-nodes
DELETE FROM cluster_nodes WHERE last_heartbeat < $1;

-- name: select-live-cluster-nodes
SELECT node_id, version, last_heartbeat, is_leader
FROM cluster_nodes WHERE last_heartbeat >= $1 ORDER BY node_id;

-- Session-level advisory lock, scoped to the current database. Returns true when acquired.
-- name: try-cron-lock
SELECT pg_try_advisory_lock(hashtextextended(current_database() || ':' || $1, 0));

-- name: release-cron-lock
SELECT pg_advisory_unlock(hashtextextended(current_database() || ':' || $1, 0));

-- name: create-table-object_state_events
CREATE TABLE IF NOT EXISTS object_state_events (
        event_id UUID PRIMARY KEY,
        object_id VARCHAR(128) NOT NULL,
        state VARCHAR(32) NOT NULL,
        object VARCHAR,
        wrapping_key_id VARCHAR(128),
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- name: create-table-object_state_event_tombstones
CREATE TABLE IF NOT EXISTS object_state_event_tombstones (
        event_id UUID PRIMARY KEY
);

-- name: create-index-object_state_events-object_id
CREATE INDEX IF NOT EXISTS idx_object_state_events_object_id ON object_state_events (object_id);

-- name: insert-object-state-event
INSERT INTO object_state_events (event_id, object_id, state, object, wrapping_key_id)
SELECT gen_random_uuid(), id, $2::varchar,
       CASE WHEN $2::varchar IN ('Destroyed', 'Destroyed_Compromised') THEN object END,
       CASE WHEN $2::varchar IN ('Destroyed', 'Destroyed_Compromised') THEN wrapping_key_id END
FROM objects WHERE id = $1;

-- name: tombstone-object-state-events
INSERT INTO object_state_event_tombstones (event_id)
SELECT e.event_id FROM object_state_events e
WHERE e.object_id = $1
  AND NOT EXISTS (SELECT 1 FROM object_state_event_tombstones t WHERE t.event_id = e.event_id);

-- Reconcile state information written by an older KMS without the derive trigger: append missing
-- phases or compromise status, including a baseline when no live event remains.
-- name: backfill-object-state-events
WITH observed AS MATERIALIZED (
    SELECT id, kms_effective_state(id) AS effective_state FROM objects WHERE state IS NOT NULL
)
INSERT INTO object_state_events (event_id, object_id, state, object, wrapping_key_id)
SELECT gen_random_uuid(), o.id, o.state,
       CASE WHEN o.state IN ('Destroyed', 'Destroyed_Compromised') THEN o.object END,
       CASE WHEN o.state IN ('Destroyed', 'Destroyed_Compromised') THEN o.wrapping_key_id END
FROM objects o
JOIN observed e ON e.id = o.id
WHERE kms_state_join(e.effective_state, o.state) IS DISTINCT FROM e.effective_state;

-- Events and tombstones of objects deleted by an older KMS (downgrade or rolling restart).
-- name: purge-orphan-object-state-event-tombstones
DELETE FROM object_state_event_tombstones
WHERE event_id IN (SELECT e.event_id FROM object_state_events e
                   WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = e.object_id));

-- name: purge-orphan-object-state-events
DELETE FROM object_state_events e
WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = e.object_id);

-- name: delete-object-state-event-tombstones
DELETE FROM object_state_event_tombstones
WHERE event_id IN (SELECT event_id FROM object_state_events WHERE object_id = $1);

-- name: delete-object-state-events
DELETE FROM object_state_events WHERE object_id = $1;

-- name: clean-table-object_state_event_tombstones
DELETE FROM object_state_event_tombstones;

-- name: clean-table-object_state_events
DELETE FROM object_state_events;

-- name: select-constraint-exists
SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = $1);

-- name: phase1-tags-id-not-null
ALTER TABLE tags ALTER COLUMN id SET NOT NULL;

-- name: phase1-tags-tag-not-null
ALTER TABLE tags ALTER COLUMN tag SET NOT NULL;

-- An interrupted CONCURRENTLY build leaves an INVALID index that IF NOT EXISTS would skip and
-- ADD CONSTRAINT ... USING INDEX would reject. No constraint uses it while the key is absent.
-- name: phase1-tags-pkey-index-reset
DROP INDEX IF EXISTS idx_tags_pkey;

-- name: phase1-tags-pkey-index
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_tags_pkey ON tags (id, tag);

-- name: phase1-tags-pkey
ALTER TABLE tags ADD CONSTRAINT tags_pkey PRIMARY KEY USING INDEX idx_tags_pkey;

-- name: phase1-tags-drop-unique
ALTER TABLE tags DROP CONSTRAINT IF EXISTS tags_id_tag_key;

-- name: phase1-read-access-id-not-null
ALTER TABLE read_access ALTER COLUMN id SET NOT NULL;

-- name: phase1-read-access-userid-not-null
ALTER TABLE read_access ALTER COLUMN userid SET NOT NULL;

-- name: phase1-read-access-pkey-index-reset
DROP INDEX IF EXISTS idx_read_access_pkey;

-- name: phase1-read-access-pkey-index
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_read_access_pkey ON read_access (id, userid);

-- name: phase1-read-access-pkey
ALTER TABLE read_access ADD CONSTRAINT read_access_pkey PRIMARY KEY USING INDEX idx_read_access_pkey;

-- name: phase1-read-access-drop-unique
ALTER TABLE read_access DROP CONSTRAINT IF EXISTS read_access_id_userid_key;

-- name: phase1-co-activations-id
ALTER TABLE crypto_officer_activations ADD COLUMN IF NOT EXISTS id BIGINT GENERATED BY DEFAULT AS IDENTITY;

-- An interrupted CONCURRENTLY build leaves an INVALID index that IF NOT EXISTS would skip and
-- ADD CONSTRAINT ... USING INDEX would reject. No constraint uses it while the key is absent.
-- name: phase1-co-activations-pkey-index-reset
DROP INDEX IF EXISTS idx_co_activations_pkey;

-- name: phase1-co-activations-pkey-index
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_co_activations_pkey ON crypto_officer_activations (id);

-- name: phase1-co-activations-pkey
ALTER TABLE crypto_officer_activations ADD CONSTRAINT crypto_officer_activations_pkey PRIMARY KEY USING INDEX idx_co_activations_pkey;

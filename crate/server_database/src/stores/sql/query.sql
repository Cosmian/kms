
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

-- name: delete-parameter
DELETE FROM parameters WHERE name=$1;


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

-- name: insert-objects
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) VALUES ($1, $2, $3, $4, $5, $6);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state
        FROM objects
        WHERE objects.id=$1;

-- name: update-object-with-object
UPDATE objects SET object=$1, attributes=$2, wrapping_key_id=$3 WHERE id=$4;

-- name: update-object-with-state
UPDATE objects SET state=$1 WHERE id=$2;

-- name: delete-object
DELETE FROM objects WHERE id=$1;

-- name: upsert-object
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT(id)
        DO UPDATE SET object=$2, attributes=$3, state=$4, owner=$5, wrapping_key_id=$6
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
        WHERE read_access.userid=$1;

-- name: insert-tags
INSERT INTO tags (id, tag) VALUES ($1, $2);

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
UPDATE crypto_officer_activations SET revoked_at = CURRENT_TIMESTAMP, revoked_by = $1
        WHERE activated_by = $2 AND revoked_at IS NULL;

-- name: count-all-non-destroyed
SELECT COUNT(*) FROM objects WHERE state != 'Destroyed';

-- name: count-non-destroyed-keys
SELECT COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND (object ? 'SymmetricKey' OR
     object ? 'PrivateKey'   OR
     object ? 'PublicKey'    OR
     object ? 'SplitKey');

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

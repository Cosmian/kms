-- name: create-table-parameters
CREATE TABLE IF NOT EXISTS parameters
(
    name  VARCHAR(128) PRIMARY KEY,
    value VARCHAR(256)
);

-- name: upsert-parameter
INSERT INTO parameters (name, value)
VALUES (?, ?)
ON DUPLICATE KEY UPDATE value=VALUES(value);

-- name: select-parameter
SELECT value
FROM parameters
WHERE name = ?;

-- name: delete-parameter
DELETE
FROM parameters
WHERE name = ?;


-- name: create-table-objects
CREATE TABLE IF NOT EXISTS objects
(
    id              VARCHAR(128) PRIMARY KEY,
    object          LONGTEXT NOT NULL,
    attributes      json NOT NULL,
    state           VARCHAR(32),
    owner           VARCHAR(255),
    wrapping_key_id VARCHAR(128)
);

-- name: add-column-attributes
ALTER TABLE objects
    ADD COLUMN attributes json;

-- name: has-column-attributes
SHOW COLUMNS FROM objects LIKE 'attributes';

-- name: has-column-wrapping-key-id
SHOW COLUMNS FROM objects LIKE 'wrapping_key_id';

-- name: add-column-wrapping-key-id
ALTER TABLE objects ADD COLUMN wrapping_key_id VARCHAR(128);

-- name: has-column-co-activated-by
SHOW COLUMNS FROM crypto_officer_activations LIKE 'activated_by';

-- name: add-column-co-activated-by
ALTER TABLE crypto_officer_activations ADD COLUMN activated_by VARCHAR(255);

-- name: create-table-read_access
CREATE TABLE IF NOT EXISTS read_access
(
    id          VARCHAR(128) NOT NULL,
    userid      VARCHAR(255) NOT NULL,
    permissions json NOT NULL,
    PRIMARY KEY (id, userid)
);

-- name: create-table-tags
CREATE TABLE IF NOT EXISTS tags
(
    id  VARCHAR(128) NOT NULL,
    tag VARCHAR(255) NOT NULL,
    PRIMARY KEY (id, tag)
);

-- name: clean-table-objects
DELETE
FROM objects;

-- name: clean-table-read_access
DELETE
FROM read_access;

-- name: clean-table-tags
DELETE
FROM tags;


-- name: insert-objects
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id)
VALUES (?, ?, ?, ?, ?, ?);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state
FROM objects
WHERE objects.id = ?;

-- name: update-object-with-object
UPDATE objects
SET object=?,
    attributes=?,
    wrapping_key_id=?
WHERE id = ?;

-- name: update-object-with-state
UPDATE objects
SET state=?
WHERE id = ?;

-- name: delete-object
DELETE
FROM objects
WHERE id = ?;

-- name: upsert-object
INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id)
VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE object=VALUES(object),
                        attributes=VALUES(attributes),
                        state=VALUES(state),
                        owner=VALUES(owner),
                        wrapping_key_id=VALUES(wrapping_key_id);

-- name: select-user-accesses-for-object
SELECT permissions
FROM read_access
WHERE id = ?
  AND userid = ?;

-- name: upsert-row-read_access
INSERT INTO read_access (id, userid, permissions)
VALUES (?, ?, ?)
ON DUPLICATE KEY
    UPDATE permissions = IF((id = VALUES(id)) AND (userid = VALUES(userid)), VALUES(permissions), permissions);

-- name: delete-rows-read_access
DELETE
FROM read_access
WHERE id = ?
  AND userid = ?;

-- name: delete-read-access-for-object
DELETE
FROM read_access
WHERE id = ?;

-- name: has-row-objects
SELECT 1
FROM objects
WHERE id = ?
  AND owner = ?;

-- name: update-rows-read_access-with-permission
UPDATE read_access
SET permissions=?
WHERE id = ?
  AND userid = ?;

-- name: select-rows-read_access-with-object-id
SELECT userid, permissions
FROM read_access
WHERE id = ?;

-- name: select-objects-access-obtained
SELECT read_access.id, COALESCE(objects.owner, ''), COALESCE(objects.state, 'Active'), read_access.permissions
FROM read_access
         LEFT JOIN objects
                    ON objects.id = read_access.id
WHERE read_access.userid = ?;

-- name: insert-tags
INSERT INTO tags (id, tag)
VALUES (?, ?);

-- name: select-tags
SELECT tag
FROM tags
WHERE id = ?;

-- name: delete-tags
DELETE
FROM tags
WHERE id = ?;


-- name: select-from-tags
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state, read_access.permissions
FROM objects
         INNER JOIN (SELECT id
                     FROM tags
                     WHERE tag IN (@TAGS)
                     GROUP BY id
                     HAVING COUNT(DISTINCT tag) = ?) AS matched_tags
                    ON objects.id = matched_tags.id
         LEFT JOIN read_access
                   ON objects.id = read_access.id AND (read_access.userid = ? OR read_access.userid = '*');

-- name: select-uids-from-tags
SELECT id
FROM tags
WHERE tag IN (@TAGS)
GROUP BY id
HAVING COUNT(DISTINCT tag) = ?;

-- name: find-wrapped-by
SELECT DISTINCT objects.id, objects.state, objects.attributes
FROM objects
LEFT JOIN read_access ON objects.id = read_access.id AND read_access.userid = ?
WHERE (objects.owner = ? OR read_access.userid = ?)
  AND objects.wrapping_key_id = ?;

-- name: select-objects-null-wrapping-key
SELECT id, object FROM objects WHERE wrapping_key_id IS NULL;

-- name: update-wrapping-key-id
UPDATE objects SET wrapping_key_id = ? WHERE id = ?;

-- name: has-index
SELECT 1
FROM information_schema.statistics
WHERE table_schema = DATABASE()
  AND table_name = ?
  AND index_name = ?
LIMIT 1;

-- name: create-index-objects-owner
CREATE INDEX idx_objects_owner ON objects (owner);

-- name: create-index-objects-state
CREATE INDEX idx_objects_state ON objects (state);

-- name: create-index-read_access-userid
CREATE INDEX idx_read_access_userid ON read_access (userid);

-- name: create-index-objects-wrapping-key-id
CREATE INDEX idx_objects_wrapping_key_id ON objects (wrapping_key_id);

-- name: create-table-crypto_officer_activations
CREATE TABLE IF NOT EXISTS crypto_officer_activations (
        id INTEGER PRIMARY KEY AUTO_INCREMENT,
        activated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        activated_by VARCHAR(255),
        sealed_record TEXT NOT NULL,
        revoked_at TIMESTAMP NULL DEFAULT NULL,
        revoked_by VARCHAR(255)
);

-- name: insert-crypto-officer-activation
INSERT INTO crypto_officer_activations (sealed_record, activated_by)
        VALUES (?, ?);

-- name: select-active-crypto-officer-activation
SELECT sealed_record FROM crypto_officer_activations WHERE revoked_at IS NULL
        ORDER BY activated_at DESC LIMIT 1;

-- name: revoke-crypto-officer-activation
UPDATE crypto_officer_activations SET revoked_at = CURRENT_TIMESTAMP, revoked_by = ?
        WHERE revoked_at IS NULL;

-- name: count-all-non-destroyed
SELECT COUNT(*) FROM objects WHERE state != 'Destroyed';

-- name: count-non-destroyed-keys
SELECT COUNT(*) FROM objects
WHERE state NOT IN ('Destroyed', 'Destroyed_Compromised')
AND (
    JSON_TYPE(JSON_EXTRACT(object, '$.SymmetricKey')) IS NOT NULL OR
    JSON_TYPE(JSON_EXTRACT(object, '$.PrivateKey'))   IS NOT NULL OR
    JSON_TYPE(JSON_EXTRACT(object, '$.PublicKey'))    IS NOT NULL OR
    JSON_TYPE(JSON_EXTRACT(object, '$.SplitKey'))     IS NOT NULL
);

-- ── CRL persistence (MySQL-specific) ─────────────────────────────────────────
-- MySQL uses LONGBLOB for binary data and REPLACE INTO for upsert.

-- name: create-table-crls
CREATE TABLE IF NOT EXISTS crls (
    issuer_id    VARCHAR(128) NOT NULL PRIMARY KEY,
    crl_der      LONGBLOB     NOT NULL,
    crl_number   BIGINT       NOT NULL,
    generated_at VARCHAR(32)  NOT NULL,
    next_update  VARCHAR(32)  NOT NULL
);

-- name: upsert-crl
INSERT INTO crls (issuer_id, crl_der, crl_number, generated_at, next_update)
    VALUES (?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
        crl_der      = VALUES(crl_der),
        crl_number   = VALUES(crl_number),
        generated_at = VALUES(generated_at),
        next_update  = VALUES(next_update);

-- name: select-crl
SELECT crl_der, generated_at FROM crls WHERE issuer_id = ?;

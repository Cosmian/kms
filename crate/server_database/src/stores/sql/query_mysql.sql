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
    id         VARCHAR(128) PRIMARY KEY,
    object     LONGTEXT NOT NULL,
    attributes json NOT NULL,
    state      VARCHAR(32),
    owner      VARCHAR(255)
);

-- name: add-column-attributes
ALTER TABLE objects
    ADD COLUMN attributes json;

-- name: has-column-attributes
SHOW COLUMNS FROM objects LIKE 'attributes';

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
INSERT INTO objects (id, object, attributes, state, owner)
VALUES (?, ?, ?, ?, ?);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state
FROM objects
WHERE objects.id = ?;

-- name: update-object-with-object
UPDATE objects
SET object=?,
    attributes=?
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
INSERT INTO objects (id, object, attributes, state, owner)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE object=VALUES(object),
                        attributes=VALUES(attributes),
                        state=VALUES(state),
                        owner=VALUES(owner);

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
SELECT objects.id, owner, state, permissions
FROM objects
         INNER JOIN read_access
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

-- name: create-table-notifications
CREATE TABLE IF NOT EXISTS notifications
(
    id         BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    event_type VARCHAR(64)  NOT NULL,
    message    TEXT         NOT NULL,
    object_id  VARCHAR(255),
    created_at VARCHAR(64)  NOT NULL,
    read_at    VARCHAR(64)
);

-- name: clean-table-notifications
DELETE FROM notifications;

-- name: health-check
SELECT 1;

-- name: find-wrapped-by-objects
SELECT DISTINCT objects.id, objects.state, objects.attributes
FROM objects
LEFT JOIN read_access ON objects.id = read_access.id AND read_access.userid = ?
WHERE (objects.owner = ? OR read_access.userid = ?)
  AND (
    JSON_UNQUOTE(JSON_EXTRACT(objects.object, '$.SymmetricKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier')) = ?
    OR JSON_UNQUOTE(JSON_EXTRACT(objects.object, '$.PrivateKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier')) = ?
    OR JSON_UNQUOTE(JSON_EXTRACT(objects.object, '$.SecretData.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier')) = ?
    OR JSON_UNQUOTE(JSON_EXTRACT(objects.object, '$.SplitKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier')) = ?
    OR JSON_UNQUOTE(JSON_EXTRACT(objects.object, '$.PGPKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier')) = ?
  );

-- name: find-due-for-rotation
SELECT objects.id, objects.attributes
FROM objects
WHERE objects.state = 'Active'
  AND JSON_EXTRACT(objects.attributes, '$.RotateInterval') IS NOT NULL
  AND CAST(JSON_UNQUOTE(JSON_EXTRACT(objects.attributes, '$.RotateInterval')) AS UNSIGNED) > 0;

-- name: insert-notification
INSERT INTO notifications (user_id, event_type, message, object_id, created_at)
VALUES (?, ?, ?, ?, ?);

-- name: last-insert-id
SELECT LAST_INSERT_ID();

-- name: list-notifications
SELECT id, user_id, event_type, message, object_id, created_at, read_at
FROM notifications WHERE user_id = ?
ORDER BY (read_at IS NULL) DESC, created_at DESC
LIMIT ? OFFSET ?;

-- name: count-unread-notifications
SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL;

-- name: mark-notification-read
UPDATE notifications SET read_at = ?
WHERE id = ? AND user_id = ? AND read_at IS NULL;

-- name: row-count
SELECT ROW_COUNT();

-- name: mark-all-notifications-read
UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL;

-- name: set-session-isolation-level
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- name: set-session-lock-timeout
SET SESSION innodb_lock_wait_timeout=10;

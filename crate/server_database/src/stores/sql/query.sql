
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
        owner VARCHAR(255)
);
-- name: add-column-attributes
ALTER TABLE objects ADD COLUMN attributes json;
-- name: has-column-attributes
SELECT attributes from objects;

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
INSERT INTO objects (id, object, attributes, state, owner) VALUES ($1, $2, $3, $4, $5);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state
        FROM objects
        WHERE objects.id=$1;

-- name: update-object-with-object
UPDATE objects SET object=$1, attributes=$2 WHERE id=$3;

-- name: update-object-with-state
UPDATE objects SET state=$1 WHERE id=$2;

-- name: delete-object
DELETE FROM objects WHERE id=$1;

-- name: upsert-object
INSERT INTO objects (id, object, attributes, state, owner) VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT(id)
        DO UPDATE SET object=$2, attributes=$3, state=$4, owner=$5
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
SELECT objects.id, objects.owner, objects.state, read_access.permissions
        FROM objects
        INNER JOIN read_access
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

-- name: create-table-notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  event_type VARCHAR(64) NOT NULL,
  message TEXT NOT NULL,
  object_id VARCHAR(255),
  created_at VARCHAR(64) NOT NULL,
  read_at VARCHAR(64)
);

-- name: clean-table-notifications
DELETE FROM notifications;

-- name: pragma-wal-mode
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;

-- name: health-check
SELECT 1;

-- name: check-object-exists
SELECT 1 FROM objects WHERE id=$1 LIMIT 1;

-- name: alter-table-objects-attributes-jsonb
ALTER TABLE objects ALTER COLUMN attributes TYPE jsonb USING attributes::jsonb;

-- name: select-uids-for-tags-any
SELECT id FROM tags WHERE tag = ANY($1::text[]) GROUP BY id HAVING COUNT(DISTINCT tag) = $2::int;

-- name: find-wrapped-by-objects
SELECT DISTINCT objects.id, objects.state, objects.attributes
FROM objects
LEFT JOIN read_access ON objects.id = read_access.id AND read_access.userid = $2
WHERE (objects.owner = $2 OR read_access.userid = $2)
  AND (
    (objects.object::jsonb) -> 'SymmetricKey' -> 'KeyBlock' -> 'KeyWrappingData' -> 'EncryptionKeyInformation' ->> 'UniqueIdentifier' = $1
    OR (objects.object::jsonb) -> 'PrivateKey' -> 'KeyBlock' -> 'KeyWrappingData' -> 'EncryptionKeyInformation' ->> 'UniqueIdentifier' = $1
    OR (objects.object::jsonb) -> 'SecretData' -> 'KeyBlock' -> 'KeyWrappingData' -> 'EncryptionKeyInformation' ->> 'UniqueIdentifier' = $1
    OR (objects.object::jsonb) -> 'SplitKey' -> 'KeyBlock' -> 'KeyWrappingData' -> 'EncryptionKeyInformation' ->> 'UniqueIdentifier' = $1
    OR (objects.object::jsonb) -> 'PGPKey' -> 'KeyBlock' -> 'KeyWrappingData' -> 'EncryptionKeyInformation' ->> 'UniqueIdentifier' = $1
  );

-- name: find-wrapped-by-objects-sqlite
SELECT DISTINCT objects.id, objects.state, objects.attributes
FROM objects
LEFT JOIN read_access ON objects.id = read_access.id AND read_access.userid = $2
WHERE (objects.owner = $2 OR read_access.userid = $2)
  AND (
    json_extract(objects.object, '$.SymmetricKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier') = $1
    OR json_extract(objects.object, '$.PrivateKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier') = $1
    OR json_extract(objects.object, '$.SecretData.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier') = $1
    OR json_extract(objects.object, '$.SplitKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier') = $1
    OR json_extract(objects.object, '$.PGPKey.KeyBlock.KeyWrappingData.EncryptionKeyInformation.UniqueIdentifier') = $1
  );

-- name: find-due-for-rotation
SELECT objects.id, objects.attributes
FROM objects
WHERE objects.state = 'Active'
  AND (objects.attributes::jsonb ->> 'RotateInterval') IS NOT NULL
  AND CAST((objects.attributes::jsonb ->> 'RotateInterval') AS BIGINT) > 0;

-- name: find-due-for-rotation-sqlite
SELECT objects.id, objects.attributes
FROM objects
WHERE objects.state = 'Active'
  AND json_extract(objects.attributes, '$.RotateInterval') IS NOT NULL
  AND CAST(json_extract(objects.attributes, '$.RotateInterval') AS INTEGER) > 0;

-- name: create-notifications-sequence
CREATE SEQUENCE IF NOT EXISTS notifications_id_seq AS BIGINT;

-- name: alter-notifications-id-bigint
DO $$ BEGIN
  ALTER TABLE notifications ALTER COLUMN id TYPE BIGINT USING id::BIGINT;
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- name: set-notifications-id-default
ALTER TABLE notifications ALTER COLUMN id SET DEFAULT nextval('notifications_id_seq'::regclass);

-- name: insert-notification
INSERT INTO notifications (user_id, event_type, message, object_id, created_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id;

-- name: list-notifications
SELECT id, user_id, event_type, message, object_id, created_at, read_at
FROM notifications WHERE user_id = $1
ORDER BY (read_at IS NULL) DESC, created_at DESC
LIMIT $2 OFFSET $3;

-- name: count-unread-notifications
SELECT COUNT(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL;

-- name: mark-notification-read
UPDATE notifications SET read_at = $1
WHERE id = $2 AND user_id = $3 AND read_at IS NULL;

-- name: mark-all-notifications-read
UPDATE notifications SET read_at = $1 WHERE user_id = $2 AND read_at IS NULL;

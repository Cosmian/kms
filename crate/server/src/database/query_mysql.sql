-- name: create-table-context
CREATE TABLE IF NOT EXISTS context
(
    version VARCHAR(40) PRIMARY KEY,
    state   VARCHAR(40)
);

-- name: create-table-objects
CREATE TABLE IF NOT EXISTS objects
(
    id         VARCHAR(40) PRIMARY KEY,
    object     json NOT NULL,
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
    id          VARCHAR(40),
    userid      VARCHAR(255),
    permissions json NOT NULL,
    UNIQUE (id, userid)
);

-- name: create-table-tags
CREATE TABLE IF NOT EXISTS tags
(
    id  VARCHAR(40),
    tag VARCHAR(255),
    UNIQUE (id, tag)
);

-- name: clean-table-context
DELETE
FROM context;

-- name: clean-table-objects
DELETE
FROM objects;

-- name: clean-table-read_access
DELETE
FROM read_access;

-- name: clean-table-tags
DELETE
FROM tags;

-- name: select-context
SELECT *
FROM context
LIMIT 1;

-- name: insert-context
INSERT INTO context (version, state)
VALUES (?, ?);

-- name: update-context
UPDATE context
SET version=?,
    state=?
WHERE state = ?;

-- name: delete-version
DELETE
FROM context
WHERE version = ?;

-- name: insert-objects
INSERT INTO objects (id, object, attributes, state, owner)
VALUES (?, ?, ?, ?, ?);

-- name: select-object
SELECT objects.id, objects.object, objects.attributes, objects.owner, objects.state, read_access.permissions
FROM objects
         LEFT JOIN read_access
                   ON objects.id = read_access.id AND (read_access.userid = ? OR read_access.userid = '*')
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
WHERE id = ?
  AND owner = ?;

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

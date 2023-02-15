-- name: create-table-objects
CREATE TABLE IF NOT EXISTS objects (
        id VARCHAR(40) PRIMARY KEY,
        object json NOT NULL,
        state VARCHAR(32),
        owner VARCHAR(255)
);

-- name: create-table-read_access
CREATE TABLE IF NOT EXISTS read_access (
        id VARCHAR(40),
        userid VARCHAR(255),
        permissions json NOT NULL,
        UNIQUE (id, userid)
);

-- name: clean-table-objects
DELETE FROM objects;

-- name: clean-table-read_access
DELETE FROM read_access;

-- name: insert-row-objects
INSERT INTO objects (id, object, state, owner) VALUES (?, ?, ?, ?);

-- name: select-row-objects
SELECT object, state FROM objects WHERE id=? AND owner=?;

-- name: select-row-objects-join-read_access
SELECT objects.object, objects.state, read_access.permissions
        FROM objects, read_access
        WHERE objects.id=? AND read_access.id=? AND read_access.userid=?;

-- name: update-rows-objects-with-object
UPDATE objects SET object=? WHERE id=? AND owner=?;

-- name: update-rows-objects-with-state
UPDATE objects SET state=? WHERE id=? AND owner=?;

-- name: delete-rows-objects
DELETE FROM objects WHERE id=? AND owner=?;

-- name: upsert-row-objects
INSERT INTO objects (id, object, state, owner) VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
                object = IF(objects.owner=?, VALUES(object), object),
                state = IF(objects.owner=?, VALUES(state), state);

-- name: select-row-read_access
SELECT permissions FROM read_access WHERE id=? AND userid=?;

-- name: upsert-row-read_access
INSERT INTO read_access (id, userid, permissions) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE permissions = IF((id=VALUES(id)) AND (userid=VALUES(userid)), VALUES(permissions), permissions);

-- name: delete-rows-read_access
DELETE FROM read_access WHERE id=? AND userid=?;

-- name: has-row-objects
SELECT 1 FROM objects WHERE id=? AND owner=?;

-- name: update-rows-read_access-with-permission
UPDATE read_access SET permissions=?
        WHERE id=? AND userid=?;

-- name: select-rows-read_access-with-object-id
SELECT userid, permissions
        FROM read_access
        WHERE id=?;

-- name: select-rows-objects-shared
SELECT objects.id, owner, state, permissions
        FROM objects
        INNER JOIN read_access
        ON objects.id = read_access.id
        WHERE read_access.userid=?;

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
INSERT INTO objects (id, object, state, owner) VALUES ($1, $2, $3, $4);

-- name: select-row-objects
SELECT object, state FROM objects WHERE id=$1 AND owner=$2;

-- name: select-row-objects-where-owner
SELECT id, state FROM objects WHERE owner=$1;

-- name: select-row-objects-join-read_access
SELECT objects.object, objects.state, read_access.permissions 
        FROM objects, read_access 
        WHERE objects.id=$1 AND read_access.id=$1 AND read_access.userid=$2;

-- name: update-rows-objects-with-object
UPDATE objects SET object=$1 WHERE id=$2 AND owner=$3;

-- name: update-rows-objects-with-state
UPDATE objects SET state=$1 WHERE id=$2 AND owner=$3;

-- name: delete-rows-objects
DELETE FROM objects WHERE id=$1 AND owner=$2;

-- name: upsert-row-objects
INSERT INTO objects (id, object, state, owner) VALUES ($1, $2, $3, $4)
        ON CONFLICT(id)
        DO UPDATE SET object=$2, state=$3
        WHERE objects.owner=$4;

-- name: select-row-read_access
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
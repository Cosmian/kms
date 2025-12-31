
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
        WHERE objects.id=$1;
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

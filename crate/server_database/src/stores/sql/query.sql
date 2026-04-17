
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

-- ── RBAC tables ─────────────────────────────────────────────────────────

-- name: create-table-roles
CREATE TABLE IF NOT EXISTS roles (
        id VARCHAR(128) PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        description TEXT,
        builtin BOOLEAN NOT NULL DEFAULT FALSE
);

-- name: create-table-role_permissions
CREATE TABLE IF NOT EXISTS role_permissions (
        role_id VARCHAR(128) NOT NULL,
        object_id VARCHAR(128) NOT NULL,
        operations json NOT NULL,
        PRIMARY KEY (role_id, object_id)
);

-- name: create-table-user_roles
CREATE TABLE IF NOT EXISTS user_roles (
        user_id VARCHAR(255) NOT NULL,
        role_id VARCHAR(128) NOT NULL,
        granted_by VARCHAR(255) NOT NULL,
        PRIMARY KEY (user_id, role_id)
);

-- name: clean-table-roles
DELETE FROM roles;

-- name: clean-table-role_permissions
DELETE FROM role_permissions;

-- name: clean-table-user_roles
DELETE FROM user_roles;

-- name: insert-role
INSERT INTO roles (id, name, description, builtin) VALUES ($1, $2, $3, $4);

-- name: select-role
SELECT id, name, description, builtin FROM roles WHERE id=$1;

-- name: select-all-roles
SELECT id, name, description, builtin FROM roles ORDER BY name;

-- name: update-role
UPDATE roles SET name=$2, description=$3 WHERE id=$1;

-- name: delete-role
DELETE FROM roles WHERE id=$1;

-- name: upsert-role-permissions
INSERT INTO role_permissions (role_id, object_id, operations) VALUES ($1, $2, $3)
        ON CONFLICT(role_id, object_id)
        DO UPDATE SET operations=$3
        WHERE role_permissions.role_id=$1 AND role_permissions.object_id=$2;

-- name: delete-role-permissions
DELETE FROM role_permissions WHERE role_id=$1 AND object_id=$2;

-- name: select-role-permissions
SELECT object_id, operations FROM role_permissions WHERE role_id=$1;

-- name: insert-user-role
INSERT INTO user_roles (user_id, role_id, granted_by) VALUES ($1, $2, $3);

-- name: delete-user-role
DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2;

-- name: select-user-roles
SELECT r.id, r.name, r.description, r.builtin
        FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id=$1
        ORDER BY r.name;

-- name: select-role-users
SELECT user_id, role_id, granted_by FROM user_roles WHERE role_id=$1;

-- name: select-role-operations-for-user-object
WITH RECURSIVE role_tree(role_id) AS (
        SELECT ur.role_id FROM user_roles ur WHERE ur.user_id=$1
    UNION
        SELECT rh.junior_role_id FROM role_hierarchy rh
        INNER JOIN role_tree rt ON rh.senior_role_id = rt.role_id
)
SELECT rp.operations
        FROM role_permissions rp
        INNER JOIN role_tree rt ON rp.role_id = rt.role_id
        WHERE rp.object_id=$2 OR rp.object_id='*';

-- name: create-table-role_hierarchy
CREATE TABLE IF NOT EXISTS role_hierarchy (
        senior_role_id VARCHAR(128) NOT NULL,
        junior_role_id VARCHAR(128) NOT NULL,
        PRIMARY KEY (senior_role_id, junior_role_id)
);

-- name: clean-table-role_hierarchy
DELETE FROM role_hierarchy;

-- name: insert-hierarchy-edge
INSERT INTO role_hierarchy (senior_role_id, junior_role_id) VALUES ($1, $2);

-- name: delete-hierarchy-edge
DELETE FROM role_hierarchy WHERE senior_role_id=$1 AND junior_role_id=$2;

-- name: select-junior-roles
SELECT r.id, r.name, r.description, r.builtin
        FROM roles r
        INNER JOIN role_hierarchy rh ON r.id = rh.junior_role_id
        WHERE rh.senior_role_id=$1
        ORDER BY r.name;

-- name: select-senior-roles
SELECT r.id, r.name, r.description, r.builtin
        FROM roles r
        INNER JOIN role_hierarchy rh ON r.id = rh.senior_role_id
        WHERE rh.junior_role_id=$1
        ORDER BY r.name;

-- name: select-all-hierarchy-edges
SELECT senior_role_id, junior_role_id FROM role_hierarchy;

-- name: delete-hierarchy-edges-for-role
DELETE FROM role_hierarchy WHERE senior_role_id=$1 OR junior_role_id=$1;

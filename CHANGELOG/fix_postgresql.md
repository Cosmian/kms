## Bug Fixes

### PostgreSQL / SQLite / MySQL: add `(tag, id)` index for Locate-by-tags

`Locate` requests filtering by tag scanned the `tags` table sequentially on
the SQL backends: every tag lookup filters on `tag` while grouping by `id`,
but `tags` only carried `UNIQUE (id, tag)` (leading column `id`), which is
unusable for a `tag`-leading predicate. On large tables this made tag-based
`Locate` operations slow.

A secondary index `idx_tags_tag_id` on `(tag, id)` is now created at startup
on all three SQL backends (PostgreSQL, SQLite, and MySQL/MariaDB). The
leading `tag` column turns the lookup into an index (index-only) scan, and
covering `id` keeps the `GROUP BY id` / `COUNT(DISTINCT tag)` aggregate
servable from the index without a heap fetch.

### PostgreSQL / SQLite: JSON-expression indexes for rotation and ObjectType lookups

On very large databases, keyset `name@latest` resolution (`find_by_rotate_name`),
the auto-rotation scheduler (`find_due_for_rotation`) and ObjectType filters
(CRL/OCSP/JWKS/Locate) scanned the whole `objects` table. Three indexes are
now created at startup on PostgreSQL and SQLite: `idx_objects_rotate_name`
(`RotateName`, `owner`; partial), `idx_objects_rotate_auto` (`state`; partial on
`RotateAutomatic = true`) and `idx_objects_type_state` (`ObjectType`, `state`).
On SQLite, planner statistics are refreshed at startup (`PRAGMA optimize`) so
these selective indexes are preferred over `idx_objects_state`. The first
start after upgrade on a large existing database takes longer while the
indexes build; PostgreSQL blocks writes to `objects` during each build.

### PostgreSQL / SQLite / MySQL: cheaper `kms.keys.active.count` metric query

The active-keys COUNT now filters on the `ObjectType` attribute instead of
parsing the full serialized `object` JSON column of every row.

### PostgreSQL / SQLite / MySQL: Locate-by-tags no longer scans every tag row

The `(tag, id)` index only helped rare tags: the generated tag lookup
(`WHERE tag IN (…) GROUP BY id HAVING COUNT(DISTINCT tag) = N`) still had to
read and aggregate every row of every searched tag, so a request combining a
rare tag with a common tag (or a system tag such as `_kk`) was slow regardless
of the index. On large tables this made tag-based `Locate` take seconds and,
because the server fetched and deserialized every match before cutting the
result to `MaximumItems`, the cost scaled with the number of matches.

The tag filter is now emitted as one `INNER JOIN tags` per searched tag (the
planner starts from the rarest tag and probes `UNIQUE (id, tag)` for the
others), the owner/grant check is an `EXISTS` probe of `read_access` instead of
a `LEFT JOIN` plus `DISTINCT`, and the `Locate` path pushes the
`MaximumItems`/server cap (`LIMIT`) and the destroyed-object exclusion into the
query so the database stops after the requested page.

## Features

### Config

- Add `metrics_count_interval_secs` server setting (`--metrics-count-interval-secs`,
  default 30) controlling how often the `kms.objects.total` and
  `kms.keys.active.count` metrics are refreshed from full COUNT queries; `0`
  disables both the startup seed and the periodic refresh.

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

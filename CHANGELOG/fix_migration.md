## Bug Fixes

### Database (`wrapping_key_id` migration)

- Make the `wrapping_key_id` backfill a **one-time** migration instead of
  re-running on every server startup.

  **Root cause:** the backfill selected every object whose `wrapping_key_id`
  column was `NULL` and deserialized it in Rust to extract the wrapping-key UID.
  Unwrapped objects (typically the majority) legitimately keep a `NULL` value
  forever, so the O(N) scan re-ran on *every* boot, loading and deserializing the
  full object set each time — a startup-latency and memory regression that grew
  with database size, and duplicated across every node on HA restarts.

  **Fix:** the scan is now gated by a `wrapping_key_id_backfilled` marker written
  to the `parameters` table once it completes, so it runs at most once per
  database. The column-add, backfill and marker share a single transaction on
  SQLite and PostgreSQL; an interrupted run leaves the marker unset and
  re-executes cleanly on the next boot. Objects that fail to deserialize are now
  logged (`warn`) and skipped instead of silently ignored. Applies to SQLite,
  PostgreSQL and MySQL.

### Database (Redis-findex `wrapped_by` re-index)

- Backfill the `wrapped_by::<uid>` Findex index on startup so key rotation can
  find objects wrapped **before** the index was introduced.

  **Root cause:** on Redis-findex, `find_wrapped_by` relies on a
  `wrapped_by::<uid>` Findex keyword that newer code writes at object-insert time.
  Objects stored by earlier versions have no such keyword, so they were invisible
  to `find_wrapped_by` and would be silently skipped by key rotation.

  **Fix:** a one-time, marker-gated scan (`wrapping_key_id_backfilled`) re-indexes
  the keyword for every existing wrapped object at instantiation. Re-inserting an
  already-indexed keyword is idempotent, and the marker ensures the O(N) scan runs
  at most once per database (non-FIPS only).

## Performance

### Database (indexes)

- Create the `objects(owner)`, `objects(state)` and `read_access(userid)` indexes
  on **PostgreSQL** and **MySQL** as well — previously they were created on SQLite
  only, leaving the two production RDBMS backends without them. MySQL uses an
  `information_schema` existence check because it does not support
  `CREATE INDEX IF NOT EXISTS`.
- Add an `objects(wrapping_key_id)` index on all SQL backends to speed up the
  `find_wrapped_by` lookup used by key rotation and the migration scan.

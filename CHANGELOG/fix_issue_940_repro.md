# Redis/Findex concurrent Upsert and stale tag index (#940)

## Bug Fixes

### Redis-with-Findex

- Every object write (`create`, `update_object`, `update_state`, `delete` and `Database::atomic` batches) now goes through one two-phase Lua script
  (all preconditions validated before any write): `Create` keeps its "already exists" failure, every other operation is guarded by a compare-and-swap
  on the stored blob. A failed batch no longer leaves partial object writes.
- Lost CAS races (concurrent updates with replaced vs. preserved tags) re-read fresh state and retry the whole batch (bounded, with jittered backoff),
  eliminating lost tag updates. A `Create` then `Delete` of an existing uid in one batch now fails with "already exists" instead of exhausting the retries.
- Findex keywords are written only after the object write is confirmed (retried in place on transient errors), and updates now remove stale keywords,
  so a removed tag no longer selects the object. A failure of the live-object/active-key counters after a commit is logged and corrected by the periodic reconcile instead of failing the request.
- After a keyword removal the Findex entries are re-inserted from the freshly read object, so interleaved post-commit index updates cannot leave an object unfindable.
- `find`, `list_uids_for_tags`, `find_by_rotate_name` and `find_wrapped_by` discard stale Findex hits: the stored object must still carry every searched keyword (tags and attributes).
- The batch script requires a single-node Redis (Redis Cluster is not supported); documented in the Redis database guide.
- The #940 repro tests run from `test_db_redis_with_findex` (`mise run test:db:redis`, `--ignored`); they use the standard Redis URL (`REDIS_HOST`), databases 1–5, which they flush.

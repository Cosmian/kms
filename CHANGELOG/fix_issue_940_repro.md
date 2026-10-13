# Redis/Findex concurrent Upsert and stale tag index (#940)

## Bug Fixes

### Redis-with-Findex

- `Database::atomic` now applies a whole batch with a single two-phase Lua script
  (all preconditions validated before any write): `Create` keeps its "already exists"
  failure, every other operation is guarded by a compare-and-swap on the stored blob.
  A failed batch no longer leaves partial object writes.
- Lost CAS races (concurrent `Upsert` with replaced vs. preserved tags) re-read fresh
  state and retry the whole batch (bounded), eliminating lost tag updates.
- Findex keywords are written only after the object write is confirmed, and `Upsert`
  now removes stale keywords, so a removed tag no longer selects the object.

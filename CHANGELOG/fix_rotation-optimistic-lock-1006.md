## Bug Fixes

- Guard key rotation against concurrent re-keys of the same key: `objects` rows carry a `version` counter (new column on SQLite, PostgreSQL and MySQL, added automatically on startup; stored in the record for Redis-Findex) incremented on every write, and `Re-Key` / `Re-Key Key Pair` retire the old key with a compare-and-set on it. The losing request now fails with a `Conflict` error instead of silently overwriting the first replacement and orphaning its new key; auto-rotation skips a key that hit a `Conflict` and leaves it to the next scheduler check (#1006).

## Bug Fixes

### PostgreSQL: fix `kms.keys.active.count` metric (#1203)

`count_non_destroyed_keys()` on the PostgreSQL backend always failed at
runtime because the `count-non-destroyed-keys` query applied the JSONB-only
`?` (key-exists) operator directly to the `objects.object` column, which is
typed `VARCHAR`, not `jsonb`. As a result, the `kms.keys.active.count`
metric was never updated on PostgreSQL deployments, and the failure was only
visible at `debug!` log level.

The query now explicitly casts the column (`object::jsonb ? '...'`) before
applying the operator, and the failure is now logged at `warn!` level (both
at server startup and in the periodic metrics cron) so a persistently
failing query is visible without enabling debug logging.

### Redis: enable TLS support (`rediss://`) (#1195)

The Redis client dependency did not enable a TLS backend, so connecting to a
Redis instance using a `rediss://` URL (e.g. a managed/remote Redis
requiring TLS) failed with `can't connect with TLS, the feature is not
enabled`. The `tls-native-tls` and `tokio-native-tls-comp` features are now
enabled on the `redis` crate dependency, allowing `rediss://` connection
URLs to be used with the Redis-findex backend.

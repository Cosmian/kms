## Bug Fixes

### Server concurrency under high load

- Fix server crash/hang under concurrent AWS XKS benchmarks (16 clients, 4 CPUs) caused by tracing `span.enter()` used across `.await` boundaries — replaced all 31 occurrences in KMIP operations with `tracing::Instrument` to prevent unbounded span nesting and memory growth
- Fix `delete_attribute` tracing span incorrectly named `"encrypt"` instead of `"delete_attribute"`

### Unwrapped key cache performance

- Optimize cache fingerprint computation: serialize only the `KeyBlock` instead of the entire KMIP `Object` to TTLV, significantly reducing CPU usage on cache hit/miss paths
- Eliminate sequential write lock contention in cache `insert()` by using the existing mpsc channel for timestamp updates instead of acquiring a second `RwLock`

### SQLite backend concurrency

- Implement read/write connection split for SQLite: dedicated writer connection + pool of reader connections (default: 2×CPU cores, capped at 10) leveraging WAL mode concurrent read support
- Honor the previously ignored `max_connections` parameter for SQLite backends

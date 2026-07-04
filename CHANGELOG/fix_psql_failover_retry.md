## Bug Fixes

### Database (PostgreSQL)

- Fix PostgreSQL pool returning dead connections after primary failure
  ([#1039](https://github.com/Cosmian/kms/pull/1039))

  **Root cause — `RecyclingMethod::Fast` race condition:**
  `deadpool-postgres` defaults to `RecyclingMethod::Fast`, which recycles idle
  connections by checking only `Client::is_closed()`. That flag is set
  asynchronously by the tokio-postgres background `Connection` task — it becomes
  `true` only once the tokio runtime has scheduled and polled the task after
  receiving a TCP FIN/RST. Under load, `pool.get()` can run *before* that
  scheduling occurs, causing a dead connection (one whose underlying socket is
  already closed at OS level) to be returned to the caller. The subsequent query
  then fails with `connection closed` or `broken pipe`, which the `pg_retry!`
  macro must detect and retry.

  **Fix — `RecyclingMethod::Verified`:**
  Set `recycling_method: RecyclingMethod::Verified` on the pool `ManagerConfig`.
  `Verified` runs `client.simple_query("")` on every recycled connection before
  returning it. An empty-string query is the lightest possible round-trip;
  if the socket is dead, the OS returns `ECONNRESET`/`EPIPE` synchronously,
  regardless of whether the tokio-postgres background task has run. This
  eliminates the race window entirely. On failure, deadpool discards the
  connection and calls `Manager::create()`, which opens a new connection via
  the multi-host URL (`host1:5434,host2:5435`), transparently failing over to
  the surviving node.

  This is explicitly documented in `deadpool-postgres`: *"under some
  circumstances (i.e. hard-closed network connections) it's possible that
  `is_closed()` returns `false` while the connection is dead. You will receive
  an error on your first query then."* — `Verified` prevents exactly that.

- Add structured `tracing::warn!` at every retry point in `pg_retry!` and
  `pg_retry_tx!` macros (fields: `attempt`, `delay_ms`, `error`), making
  failover observable in production logs.

### Test Infrastructure

- Add `test_db_postgresql_failover` integration test (orchestrated by
  `mise run test:db:psql`) that:
    - Starts two independent PostgreSQL instances (`pg1:5434`, `pg2:5435`) via a
    dedicated `pg-failover` Docker Compose profile.
    - Warms the connection pool against `pg1` via signal-file coordination (no
    `docker` calls inside the Rust test).
    - Kills `pg1` to simulate a primary failure, then asserts that `crud()` and
    `tx_and_list()` succeed against `pg2` within 5 s.

- Fix CI race in `mise run test:db:psql`: wait for PostgreSQL to pass
  `pg_isready` (not just TCP port open) before launching the failover test,
  preventing spurious skips when the container is still initialising.

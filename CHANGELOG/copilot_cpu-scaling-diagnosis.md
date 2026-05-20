## Performance

### Server

- Wrap CPU-bound crypto operations (`encrypt_single`, `encrypt_bulk`, `decrypt_single`, `decrypt_bulk`, `sign_with_private_key`) in `tokio::task::spawn_blocking` to prevent Tokio worker thread starvation under high concurrency, especially for heavy operations (RSA key generation, large-payload encryption)

### PostgreSQL backend

- Replace all `client.prepare()` / `tx.prepare()` calls with `prepare_cached()` (29 call sites) to eliminate redundant Parse+Describe round-trips to the server on every operation; statements are now resolved from the per-connection `StatementCache` on repeated calls
- Add missing indexes `idx_objects_owner ON objects(owner)`, `idx_objects_state ON objects(state)`, and `idx_read_access_userid ON read_access(userid)` — the absence of these caused full table scans on every `find()` / `list_user_operations_granted()` call
- Change `transact` inner functions to accept `&deadpool_postgres::Transaction<'_>` instead of `&tokio_postgres::Transaction<'_>` to enable statement caching within transactions

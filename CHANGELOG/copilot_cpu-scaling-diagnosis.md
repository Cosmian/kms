## Performance

### Server

- Wrap CPU-bound crypto operations (`encrypt_single`, `encrypt_bulk`, `decrypt_single`, `decrypt_bulk`, `sign_with_private_key`) in `tokio::task::spawn_blocking` to prevent Tokio worker thread starvation under high concurrency, especially for heavy operations (RSA key generation, large-payload encryption)

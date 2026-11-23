## Features

### Benchmarks

- `ckms bench --cek-switch` and `mise run bench:jose-cek-switch`: fixed-rate JWE decrypt (RSA-OAEP CEK unwrap) + re-encrypt over several KMS servers sharing one HSM token, with a CEK switch mid-run. Writes a 100 ms latency timeline per server, a summary (peak, recovery time), and the number of HSM unwraps per server and CEK. The task fails (performance gate) when less than 95 % of the target rate completes, a message fails, or latency does not recover after the switch. `benchmark.yml` runs it as `jose-cek-switch`.

## Bug Fixes

### JOSE

- Concurrent `POST /v1/crypto/decrypt` requests carrying the same new RSA-OAEP `encrypted_key` (e.g. the first messages after a client switches its CEK) now trigger one HSM unwrap per server instead of one per in-flight request.

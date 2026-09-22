# KMS Test Server Benchmarks (`crate/test_kms_server/benches`)

This directory contains the Criterion benchmarks executed when running `cargo bench` from the workspace root or via `-p test_kms_server`.

## Benchmark Targets Scope

| File / Module | Cargo Benchmark Target (`[[bench]]`) | Operations & Cryptographic Scope | Concurrency / Execution Model | Feature Gating / Variant | Purpose |
|---|---|---|---|---|---|
| **`benches.rs`** | `benches` | Root entry point and runner coordinator; defines and registers Criterion benchmark groups across symmetric, RSA, and EC suites | Sequential Criterion iterations driving an in-process KMS test server via `KmsClient` | FIPS (default) / `non-fips`<br>(`criterion_main!` switches active groups) | Coordinates single-call statistical micro-benchmarks across cryptographic primitives |
| **`symmetric_benches.rs`** | `benches` (submodule) | • Symmetric key generation (AES-128, AES-192, AES-256, and ChaCha20 under `non-fips`)<br>• AES-GCM (128-bit, 256-bit) single-block encrypt & decrypt<br>• AES-256-GCM bulk encrypt & decrypt (100,000 bytes)<br>• ChaCha20-Poly1305 encrypt & decrypt<br>• Parametrized AES encryption (varying batch sizes and plaintext lengths) | In-process KMIP operation dispatch via client | ChaCha20-Poly1305 and ChaCha20 key generation gated behind `feature = "non-fips"` | Latency and throughput micro-benchmarking for symmetric cipher and key creation paths |
| **`rsa_benches.rs`** | `benches` (submodule) | • RSA key pair creation (2048-bit, 4096-bit)<br>• RSA-OAEP encryption & decryption (2048-bit, 4096-bit)<br>• RSA-AES Key Wrap (KWP) encryption & decryption (2048-bit, 4096-bit)<br>• RSA PKCS#1 v1.5 encryption & decryption (2048-bit, 4096-bit)<br>• Parametrized RSA message batches (`Message` KMIP structure) | In-process KMIP operation dispatch via client | RSA PKCS#1 v1.5 (single-operation and parametrized) gated behind `feature = "non-fips"` | Measures CPU-heavy asymmetric RSA key lifecycle, wrapping, and encryption overhead |
| **`sign_benches.rs`** | `benches` (submodule) | • EC key pair creation: NIST P-256, P-384, P-521, secp256k1, Ed25519, Ed448<br>• ECDSA sign & verify (P-256 with SHA-256, P-384 with SHA-384, P-521 with SHA-512)<br>• ECDSA secp256k1 sign & verify (with SHA-256)<br>• EdDSA sign & verify (Ed25519, Ed448)<br>• RSA-PSS sign & verify (2048-bit, 4096-bit with SHA-256) | In-process KMIP operation dispatch via client | `secp256k1`, `Ed25519`, and `Ed448` key creation and sign/verify gated behind `feature = "non-fips"` | Statistical latency evaluation for digital signature generation and verification across standard and non-FIPS curves |
| **`http_throughput.rs`** | `http_throughput` | • AES-256-GCM symmetric encryption<br>• RSA-2048 OAEP decryption<br>• ECDSA P-256 signing | Boots an in-process Actix-web KMS server across a worker thread sweep (`WORKER_COUNTS = &[1, 2, 4, 8]`) driving 16 concurrent HTTP tasks per Criterion iteration | FIPS / `non-fips` compatible | Proves multi-core CPU scaling efficiency and server throughput (req/s); feeds flamegraph profiling (`mise run bench:flamegraph`) |

## Running Benchmarks

### Micro-benchmarks (`benches`)

```bash
# Default (FIPS mode)
cargo bench -p test_kms_server --bench benches

# With non-FIPS algorithms (Ed25519, Ed448, secp256k1, ChaCha20, RSA PKCS#1 v1.5)
cargo bench -p test_kms_server --bench benches --features non-fips
```

### HTTP Throughput & Multi-core Scaling (`http_throughput`)

```bash
# Run throughput benchmark
cargo bench -p test_kms_server --bench http_throughput

# Or via MISE task (also generates CPU scaling flamegraphs with Linux perf)
mise run bench:flamegraph
```

# KMS Test Server Benchmarks (`crate/test_kms_server/benches`)

This directory contains the benchmarks executed for HTTP throughput and CPU-scaling flamegraphs.

> **Note on Micro-benchmarks**:
> Direct cryptographic operation micro-benchmarks previously residing here have been consolidated into `ckms bench` (`crate/clients/clap/src/actions/bench/`), which provides full over-the-wire round-trip benchmarking across KMIP (`ttlv-json`, `ttlv-bytes`), JOSE REST, and HSM backends with statistical Criterion reports and markdown/JSON outputs.

## Benchmark Targets Scope

| File / Module | Cargo Benchmark Target (`[[bench]]`) | Operations & Cryptographic Scope | Concurrency / Execution Model | Feature Gating / Variant | Purpose |
|---|---|---|---|---|---|
| **`http_throughput.rs`** | `http_throughput` | • AES-256-GCM symmetric encryption<br>• RSA-2048 OAEP decryption<br>• ECDSA P-256 signing | Boots an in-process Actix-web KMS server across a worker thread sweep (`WORKER_COUNTS = &[1, 2, 4, 8]`) driving 16 concurrent HTTP tasks per Criterion iteration | FIPS / `non-fips` compatible | Proves multi-core CPU scaling efficiency and server throughput (req/s); feeds flamegraph profiling (`mise run bench:flamegraph`) |

## Running Benchmarks

### HTTP Throughput & Multi-core Scaling (`http_throughput`)

```bash
# Run throughput benchmark directly
cargo bench -p test_kms_server --bench http_throughput

# Or via MISE task (generates CPU scaling flamegraphs with Linux perf)
mise run bench:flamegraph
```

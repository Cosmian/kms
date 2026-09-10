# `cosmian_pkcs11_bench`

A real `dlopen()`-based load benchmark for the `cosmian_pkcs11` PKCS#11 provider
(`crate/clients/pkcs11/provider`).

Unlike `mise bench:load` (which load-tests the KMIP REST API directly through
`KmsClient`), this binary drives the *actual* Cryptoki C API of the built
`libcosmian_pkcs11.{so,dylib}` — the same call path real-world PKCS#11 consumers
(Oracle TDE, OpenSSH, disk-encryption tools, ...) use:

- `dlopen()`s the provider library and resolves its Cryptoki v2.40 function table
  via `C_GetFunctionList` (see `src/loader.rs`).
- Opens a single, shared `C_OpenSession` handle reused by every concurrent worker
  thread of the load sweep. This is intentional: the provider's own session store
  (`crate/clients/pkcs11/module/src/sessions.rs`) serializes all session access
  behind one global `Mutex`, so this benchmark measures real-world single-session
  contention rather than artificial per-thread parallelism.
- Provisions one AES secret key and one RSA key pair in the target KMS via the
  REST API (`src/setup.rs`) before the Cryptoki hot loop starts.
- Sweeps a list of concurrency levels **independently for each operation**
  (`encrypt`, `decrypt`, `sign`, `verify`, `key-creation`), reporting throughput and
  p50/p95/p99 latency per level (`src/load.rs`) — mirroring `mise bench:load`'s own
  per-operation granularity rather than timing a combined round trip.
- Writes `load_pkcs11.json` in the same schema as `mise bench:load`
  (`src/report.rs`), so the shared report pipeline
  (`.mise/lib/bench_helpers.sh::bench_generate_report` +
  `.mise/scripts/bench/plot_version_compare.py`) generates a dedicated
  `documentation/docs/benchmarks/ckms_bench_pkcs11/` report — charts, tables, and
  all — with zero changes to that pipeline's JSON parsing.

## Usage

Run via the `mise` task, which builds the server, the `cosmian_pkcs11` cdylib, and
this benchmark, starts a temporary SQLite-backed KMS server, drives the sweep, and
generates the report:

```bash
mise run bench:load-pkcs11 --sanity               # quick smoke test
mise run bench:load-pkcs11                        # full sweep, mode=all
mise run bench:load-pkcs11 --mode sign --time 30 --concurrency 1,2,4,8
```

See `mise run bench:load-pkcs11 --help` for all flags (variant, link, release, mode,
concurrency, time, warmup, cooldown, sanity).

## Benchmark modes

Each mode is measured **independently** — its own concurrency sweep, its own row in
the report table, its own SVG chart — never combined into a single round trip.

| Mode            | Cryptoki calls exercised                                       |
| --------------- | ---------------------------------------------------------------- |
| `encrypt`       | `C_EncryptInit`/`C_Encrypt` (AES-CBC-PAD)                          |
| `decrypt`       | `C_DecryptInit`/`C_Decrypt` (AES-CBC-PAD, against ciphertext produced once during setup, not timed) |
| `sign`          | `C_SignInit`/`C_Sign` (RSA, `CKM_SHA256_RSA_PKCS`)                 |
| `verify`        | `C_VerifyInit`/`C_Verify` (RSA, `CKM_SHA256_RSA_PKCS`) — **skipped with a console notice** if the loaded provider does not implement it (see below) |
| `key-creation`  | `C_GenerateKey` + `C_DestroyObject` (ephemeral AES key)            |
| `all` (default) | Runs every mode above in sequence                                  |

Two Cryptoki functions are not implemented by `cosmian_pkcs11_module`
(`crate/clients/pkcs11/module/src/pkcs11.rs`, registered via its
`cryptoki_fn_not_supported!` macro):

- **`C_VerifyInit`/`C_Verify`** always return `CKR_FUNCTION_NOT_SUPPORTED`. The
  `verify` mode probes this once before sweeping and skips with a console notice
  (`"C_Verify is not implemented by the loaded provider ... skipping"`) rather than
  publishing fabricated numbers for an operation that always fails.
- **`C_GenerateKeyPair`** is not implemented either — asymmetric keys are always
  created through the KMS REST API, not PKCS#11 — so `key-creation` only benchmarks
  the one Cryptoki key-creation path the provider does support: symmetric
  `C_GenerateKey`.

## Running the binary directly

The binary itself only needs the provider library path and a KMS server URL (used
once, to provision the benchmark keys via REST):

```bash
cargo build -p cosmian_kms_server -p cosmian_pkcs11 -p cosmian_pkcs11_bench --release
# ... start a KMS server, write a ckms.toml pointing CKMS_CONF at it (the provider
# resolves its own server URL from CKMS_CONF, not from --kms-url) ...
./target/release/pkcs11_bench \
  --pkcs11-lib ./target/release/libcosmian_pkcs11.so \
  --kms-url http://127.0.0.1:9998 \
  --mode all
```

Run standalone like this, the binary only prints the results table and writes
`load_pkcs11.json` under `$CRITERION_HOME` (or `$CARGO_TARGET_DIR/criterion`, or
`target/criterion`) — it does not itself invoke the report/chart pipeline; that is
the `mise run bench:load-pkcs11` task's job.

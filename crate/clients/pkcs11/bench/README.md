# `cosmian_pkcs11_bench`

A real `dlopen()`-based load benchmark for the `cosmian_pkcs11` PKCS#11 provider
(`crate/clients/pkcs11/provider`).

Unlike `mise bench:load` (which load-tests the KMIP REST API directly through
`KmsClient`), this binary drives the *actual* Cryptoki C API of the built
`libcosmian_pkcs11.{so,dylib}` — the same call path real-world PKCS#11 consumers
(Oracle TDE, OpenSSH, disk-encryption tools, ...) use:

- `dlopen()`s the provider library and resolves its Cryptoki v3.1 function table
  through `C_GetInterface` (see `src/loader.rs`).
- Opens one dedicated `C_OpenSession` handle **per concurrent worker thread** (up to
  the highest requested `--concurrency` level), pooled once up front: the
  provider's session store (`crate/clients/pkcs11/module/src/sessions.rs`) locks
  each session independently, so this lets concurrent operations against different
  sessions run truly in parallel — mirroring how a well-behaved, high-concurrency
  PKCS#11 consumer (e.g. a connection-pooled disk-encryption integration) would
  actually use the provider. Pass `--shared-session` to instead force every thread
  onto a single shared handle, reproducing the pre-fix
  everyone-serializes-on-one-lock behavior for direct before/after comparison.
- Provisions one AES secret key, one RSA key pair, one EC P-256 key pair, and one
  Ed25519 key pair in the target KMS via the REST API (`src/setup.rs`) before the
  Cryptoki hot loop starts.
- Sweeps a list of concurrency levels **independently for each operation**
  (`encrypt`, `decrypt`, `sign-rsa`, `verify-rsa`, `sign-ecdsa`, `verify-ecdsa`,
  `sign-eddsa`, `verify-eddsa`, `key-creation`), reporting throughput and
  p50/p95/p99 latency per level (`src/load.rs`) — mirroring `mise bench:load`'s own
  per-operation granularity rather than timing a combined round trip. `--mode sign`
  and `--mode verify` are aggregate shortcuts that run every signature algorithm
  (RSA, ECDSA, and — in `non-fips` builds — EdDSA) in sequence.
- Writes `load_pkcs11.json` in the same schema as `mise bench:load`
  (`src/report.rs`), so the shared report pipeline
  (`.mise/lib/bench_helpers.sh::bench_generate_report` +
  `.mise/scripts/bench/plot_version_compare.py`) generates a dedicated
  `documentation/docs/benchmarks/ckms_bench_pkcs11/` report — charts, tables, and
  all — with zero changes to that pipeline's JSON parsing.
- `--criterion` runs real `criterion`-crate single-operation micro-benchmarks
  instead of the concurrency sweep — see "Criterion mode" below.

## Usage

Run via the `mise` task, which builds the server, the `cosmian_pkcs11` cdylib, and
this benchmark, starts a temporary SQLite-backed KMS server, drives the sweep, and
generates the report:

```bash
mise run bench:load-pkcs11 --sanity               # quick smoke test
mise run bench:load-pkcs11                        # full sweep, mode=all
mise run bench:load-pkcs11 --mode sign --time 30 --concurrency 1,2,4,8    # every signature algorithm
mise run bench:load-pkcs11 --mode sign-ecdsa --time 30 --concurrency 1,2,4,8
mise run bench:load-pkcs11 --criterion --speed quick   # fast, single-op latency only
```

See `mise run bench:load-pkcs11 --help` for all flags (variant, link, release, mode,
concurrency, time, warmup, cooldown, sanity, shared-session, criterion, speed).

## Criterion mode

`--criterion` skips the concurrency sweep entirely and instead runs each mode once
as a real [`criterion`](https://docs.rs/criterion) single-operation micro-benchmark
(`src/criterion_bench.rs`), using the exact same setup/closures as the load sweep
(`load::prepare_ops`, shared by both so the two can never diverge on what a mode
actually calls). It writes `criterion.json`, not `load_pkcs11.json`, so the
generated report contains only the "Criterion data" section — no "Load test data"
— matching `mise bench:load --criterion`'s own behavior/`--speed` presets exactly.

This is much faster to iterate on (no warmup/cooldown per concurrency level, and
`--speed quick`'s 10 samples / 1s measurement complete in a couple of seconds) and
gives statistically rigorous per-call latency (mean/median/CI) — the right tool for
bottleneck-hunting, as opposed to the full sweep's job of characterizing
concurrent-load behavior.

Optimized runs build the server, provider, and harness with the workspace
`bench` profile (`opt-level = 3`, debug symbols retained), not the normal release
profile (`opt-level = "z"`, optimized for binary size). On the same host this
reduced the measured v3 `C_SignMessage` path from roughly 433 µs to 227 µs.

**A concrete lesson from using it:** on a shared (non-dedicated) host, the exact
same single-operation benchmark measured sub-millisecond in two consecutive runs
and ~100x that (tens of milliseconds) in a third — not a code regression, just
unrelated background load (IDE indexing, browsers, ...) briefly winning the CPU.
`bench_warn_cpu_scaling` (`.mise/lib/bench_helpers.sh`, shared by every `bench/*`
task) now also flags an elevated 1-minute load average up front for exactly this
reason — treat an isolated slow sample as suspect until reproduced.

When `sign-eddsa` is selected, criterion mode also emits
`pkcs11_overhead.json` and the generated report includes a permanent differential
breakdown:

1. request construction;
2. TTLV + JSON serialization;
3. the published-benchmark equivalent (pre-serialized full KMIP message, raw HTTP);
4. pre-serialized bare `Sign` raw HTTP (the request shape used by `KmsClient::sign`);
5. response JSON + TTLV parsing;
6. typed JSON `KmsClient::sign`;
7. pre-serialized full-message binary TTLV over raw HTTP;
8. binary TTLV response parsing;
9. typed binary-TTLV message Sign;
10. the Tokio `block_on` control cost;
11. PKCS#11 v3 `C_SignMessage` with a pre-sized 64-byte Ed25519 buffer;
12. the legacy `C_Sign(NULL)` + `C_Sign(buffer)` API after the fixed-size
   length-query optimization.

For this mode the task builds `cosmian_pkcs11` with its compile-time-only
`benchmarking` feature. That feature exposes allocation-free in-memory phase
counters (session lookup/lock, backend dispatch, request construction,
sync-to-async bridge, typed client call, and signature copy) through two
benchmark-only dynamic-library symbols. The normal provider build has no clocks or
atomic updates on the signing path.

The fixed-size one-call tier is the default benchmark behavior. The standard
two-call tier guards the module-side length-query optimization: before the fix,
`C_Sign(NULL)` performed a complete remote KMS Sign, so one logical signature
generated two HTTP/KMIP requests. Fixed-size EdDSA and RSA length queries now
return the size from key metadata without signing remotely, so the one-call and
standard two-call tiers should be equivalent within measurement noise.

The typed binary-TTLV and v3 `C_SignMessage` tiers use an A/B/A/B bracket:
typed-before, PKCS#11-before, typed-after, PKCS#11-after. The report compares the
average of each pair. This compensates for approximately linear thermal,
scheduler, or server drift during a benchmark suite; three identical unbracketed
runs previously made the late PKCS#11 tier drift from 308 to 415 µs while the
typed tier remained near 150 µs.

## Benchmark modes

Each mode is measured **independently** — its own concurrency sweep, its own row in
the report table, its own SVG chart — never combined into a single round trip.

| Mode            | Cryptoki calls exercised                                       |
| --------------- | ---------------------------------------------------------------- |
| `encrypt`       | `C_EncryptInit`/`C_Encrypt` (AES-CBC-PAD)                          |
| `decrypt`       | `C_DecryptInit`/`C_Decrypt` (AES-CBC-PAD, against ciphertext produced once during setup, not timed) |
| `sign`          | Every signature algorithm below (`sign-rsa`, `sign-ecdsa`, and — in `non-fips` builds — `sign-eddsa`), run one after another |
| `verify`        | Every verify algorithm below (`verify-rsa`, `verify-ecdsa`, and — in `non-fips` builds — `verify-eddsa`), run one after another |
| `sign-rsa`      | `C_SignInit`/`C_Sign` (RSA, `CKM_SHA256_RSA_PKCS`)                 |
| `verify-rsa`    | `C_VerifyInit`/`C_Verify` (RSA, `CKM_SHA256_RSA_PKCS`) — skipped with a console notice if the loaded provider does not implement it (see below) |
| `sign-ecdsa`    | `C_SignInit`/`C_Sign` (EC P-256, `CKM_ECDSA` — a pre-computed SHA-256 digest; the mechanism itself performs no hashing) |
| `verify-ecdsa`  | `C_VerifyInit`/`C_Verify` (EC P-256, `CKM_ECDSA`) — skipped with a console notice if the loaded provider does not implement it (see below) |
| `sign-eddsa`    | PKCS#11 v3 `C_MessageSignInit` once, then `C_SignMessage` per Ed25519 message |
| `verify-eddsa`  | `C_VerifyInit`/`C_Verify` (Ed25519, `CKM_EDDSA`) — skipped with a console notice if the loaded provider does not implement it (see below) |
| `key-creation`  | `C_GenerateKey` + `C_DestroyObject` (ephemeral AES key)            |
| `all` (default) | Runs every mode above in sequence                                  |

One Cryptoki function is not implemented by `cosmian_pkcs11_module`
(`crate/clients/pkcs11/module/src/pkcs11.rs`, registered via its
`cryptoki_fn_not_supported!` macro):

- **`C_GenerateKeyPair`** is not implemented — asymmetric keys are always
  created through the KMS REST API, not PKCS#11 — so `key-creation` only benchmarks
  the one Cryptoki key-creation path the provider does support: symmetric
  `C_GenerateKey`.

`C_VerifyInit`/`C_Verify` **are** fully implemented (`cryptoki_fn!`, not
`cryptoki_fn_not_supported!`); the `verify-rsa`/`verify-ecdsa`/`verify-eddsa` modes
still probe once before sweeping and skip with a console notice
(`"C_Verify is not implemented by the loaded provider ... skipping"`) purely as a
defensive fallback, in case a future provider build or backend configuration
doesn't support `C_Verify` for a given mechanism.

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

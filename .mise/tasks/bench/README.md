# KMS Benchmarks

Four independent benchmarks exist under `mise run bench:*`, each producing its own
report under `documentation/docs/benchmarks/<dir>/` (linked from the mdBook
"Benchmarks" nav section). It's easy to lose track of which is which — this table
is the canonical reference.

| # | Benchmark | What's exercised | Command | Report `<dir>` |
| --- | --- | --- | --- | --- |
| 1 | Software baseline | `ckms` + KMS server, all-software crypto (OpenSSL) — no HSM at all | `mise run bench:load` | `ckms_bench` |
| 2 | HSM-backed KEK | `ckms` + KMS server; keys are software keys wrapped by an HSM-resident KEK — Encrypt/Sign still run in software, only the KEK unwrap touches the HSM | `mise run bench:load-hsm` (default) | `ckms_bench_hsm_kek` |
| 3 | HSM-delegated crypto | `ckms` + KMS server; `hsm::<slot>::<uuid>` keys — key gen + Encrypt/Sign routed to the HSM's CryptoOracle (PKCS#11), crypto runs ON the HSM | `mise run bench:load-hsm --delegated` | `ckms_bench_delegated_crypto_operations` |
| 4 | Real PKCS#11 DLL | `cosmian_pkcs11` shared library `dlopen()`-ed + KMS server — drives the real Cryptoki C ABI (`C_Sign`, `C_Encrypt`, ...) | `mise run bench:load-pkcs11` | `ckms_bench_pkcs11` |

Benchmarks 2 and 3 are both driven by the same task (`bench/load-hsm`); the
`--delegated` flag switches between them. Benchmarks 1 and 4 are separate tasks
(`bench/load` and `bench/load-pkcs11` respectively). Benchmark 4 is the only one
that drives the real, `dlopen()`-ed Cryptoki C ABI — the same code path a real
PKCS#11 consumer application (e.g. Oracle TDE, OpenSSH, VeraCrypt) uses; the
other three drive the KMS's KMIP/REST API directly via the `ckms` client library.

All four accept `--criterion` to also run single-operation Criterion
micro-benchmarks alongside the concurrency sweep, and `--sanity` for a quick
smoke test. See `mise run bench:<task> --help` for the full flag list of each.

# KMS Benchmarks

Five independent benchmarks exist under `mise run bench:*`, each producing its own
report under `documentation/docs/benchmarks/<dir>/` (linked from the mdBook
"Benchmarks" nav section). It's easy to lose track of which is which — this table
is the canonical reference.

| # | Benchmark | What's exercised | Command | Report `<dir>` |
| --- | --- | --- | --- | --- |
| 1 | Software baseline | `ckms` + KMS server, all-software crypto (OpenSSL) — no HSM at all | `mise run bench:load` | `ckms_bench` |
| 2 | HSM-backed KEK | `ckms` + KMS server; keys are software keys wrapped by an HSM-resident KEK — Encrypt/Sign still run in software, only the KEK unwrap touches the HSM | `mise run bench:hsm` (default) | `ckms_bench_hsm_kek_softhsm2` (or `_<hsm_backend>`) |
| 3 | HSM-delegated crypto | `ckms` + KMS server; `hsm::<slot>::<uuid>` keys — key gen + Encrypt/Sign routed to the HSM's CryptoOracle (PKCS#11), crypto runs ON the HSM | `mise run bench:hsm --delegated` | `ckms_bench_hsm_delegated_softhsm2` (or `_<hsm_backend>`) |
| 4 | Real PKCS#11 DLL | `cosmian_pkcs11` shared library `dlopen()`-ed + KMS server — drives the real Cryptoki C ABI (`C_Sign`, `C_Encrypt`, ...) | `mise run bench:pkcs11` | `ckms_bench_pkcs11` |
| 5 | PKCS#11 HSM-delegated | Same as Benchmark 4, but with `hsm::<slot>::<uuid>` HSM-resident keys — `cosmian_pkcs11` makes HTTPS calls to KMS, which routes crypto operations to the HSM's CryptoOracle via PKCS#11 | `mise run bench:pkcs11 --delegated --hsm-model <backend>` | `ckms_bench_pkcs11_hsm_delegated_<hsm_backend>` |

Benchmarks 2 and 3 are both driven by the same task (`bench/hsm`); the
`--delegated` flag switches between them. Benchmarks 4 and 5 share the `bench/pkcs11` task;
the `--delegated` flag switches between them. Benchmarks 1, 2, and 3 drive the KMS's KMIP/REST API directly via the `ckms` client library; Benchmarks 4 and 5 drive the real, `dlopen()`-ed Cryptoki C ABI — the same code path a real PKCS#11 consumer application (e.g. Oracle TDE, OpenSSH, VeraCrypt) uses.

All five accept `--criterion` to also run single-operation Criterion
micro-benchmarks alongside the concurrency sweep, and `--sanity` for a quick
smoke test. See `mise run bench:<task> --help` for the full flag list of each.

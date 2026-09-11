# HSM-direct crypto benchmarks: `ckms bench --hsm` and `bench/load-hsm --delegated`

## Bug Fixes

### PKCS#11

- Fix `crate/clients/pkcs11/module/src/sessions.rs` serializing **every** Cryptoki
  operation across **every** session process-wide: the session store was one
  `Mutex<HashMap<CK_SESSION_HANDLE, Session>>`, locked by `session()` for the full
  duration of its callback — including the synchronous, blocking
  `RUNTIME.block_on(...)` KMS network round-trip that `C_Sign`/`C_Verify`/
  `C_Encrypt`/`C_Decrypt` all make. A concurrency sweep against
  `mise bench:load-pkcs11` (`--mode sign-eddsa`) showed the resulting bottleneck
  concretely: throughput stayed completely flat (~17-19 ops/s) from concurrency 1
  through 8, while p99 latency exploded from 74ms to over 5s — a single lock held
  across a blocking network call was serializing concurrent Cryptoki calls
  regardless of which session issued them
- Now: `SessionMap` stores `Arc<Mutex<Session>>` (one lock **per session**) behind
  an outer `RwLock` (was a `Mutex`) that is only ever held long enough to look up
  and clone that `Arc` — never across the actual (potentially slow) callback.
  Concurrent operations against *different* sessions now run fully in parallel;
  concurrent operations against the *same* session handle still serialize, as the
  Cryptoki spec requires without additional application-level synchronization.
  `create`/`exists`/`flags`/`session`/`close`/`close_all` all updated accordingly
- Re-benchmarked with the same `sign-eddsa` sweep after also switching
  `mise bench:load-pkcs11` to one dedicated session per worker thread (see
  "Testing" below, since a shared single session would have masked this fix
  entirely): throughput now scales with concurrency (19 → 34 → 57 → 82 ops/s at
  concurrency 1/2/4/8, a ~4.3x improvement at c=8) and p99 latency stays bounded
  (71ms → 193ms, vs. 73ms → 3.3s before)
- `cargo test -p cosmian_pkcs11_module --lib` (38 tests) and
  `cargo test -p cosmian_pkcs11 --lib --features non-fips` (19 tests, 5 pre-existing
  `#[ignore]`) both still pass unchanged

## Testing

### HSM-resident crypto benchmarking (`--hsm`)

- Add an `--hsm`/`--hsm-slot` flag pair to `ckms bench`, covering both the
  criterion micro-benchmarks and the `--load` concurrency sweep. When set,
  benchmark keys are created with the legacy flat-HSM `hsm::<slot>::<uuid>`
  unique identifier, so both key generation and `Encrypt`/`Sign` are routed
  by the server to the HSM's `CryptoOracle` (PKCS#11) instead of executing in
  KMS software — mirroring the existing software `bench`/`bench --load`
  structure, but for the HSM-delegation feature landed on this branch
- Algorithm coverage is limited to what the oracle supports **and** what was
  confirmed working end-to-end against a live SoftHSM2 2.6.1 token:
  encrypt (AES-GCM, AES-CBC, RSA-OAEP), sign (RSA-PSS, ECDSA P-256/P-384 —
  prehashed via `digested_data`, since SoftHSM2 only implements raw
  `CKM_ECDSA`, not the combined `CKM_ECDSA_SHA*` mechanisms — and EdDSA
  Ed25519/Ed448, non-FIPS), and AES/RSA/EC-P256/Ed25519/Ed448 key creation
  timing. `SignatureVerify` is not implemented at all for HSM-resident keys
  yet and is intentionally skipped (consistent with the existing software
  `--load` path, which is already Sign-only per #1155). P-521 key creation is
  excluded: a pre-existing bug in `crate/crypto/src/crypto/elliptic_curves/
  operation.rs` derives `cryptographic_length` from the generated private
  scalar's serialized byte length rather than the curve's nominal bit length,
  which can under-count P-521 keys and makes `HSM::create_keypair` reject the
  result — reproduced 3/3 attempts, unrelated to this benchmark, tracked as a
  follow-up
- JOSE is not supported under `--hsm`: `POST /v1/crypto/keys` has no way to
  request a caller-chosen `kid`, so an `hsm::`-prefixed key cannot be created
  through it; `--hsm --protocol jose` prints a skip notice instead of
  silently doing nothing

### New independent mise task: `bench/load-hsm --delegated`

- Add a new `.mise/tasks/bench/load-hsm-crypto` task (later merged into
  `bench/load-hsm` behind a `--delegated` flag — see the final section of
  this changelog), mirroring `bench/load-hsm`'s flag
  surface (`--variant`, `--mode`, `--protocol`, `--time`, `--concurrency`,
  `--http-workers`, `--warmup`, `--cooldown`, `--sanity`) plus `bench/load`'s
  `--criterion`/`--speed`. Runs fully independently of `bench/load` and
  `bench/load-hsm` (its own SoftHSM2 token, its own server) — unlike
  `bench/load-hsm`, which benchmarks a software KEK *wrapped* by the HSM
  (crypto still executes in KMS software), this task benchmarks crypto
  operations executed *directly* on the HSM
- Add `bench_start_server_hsm_resident` to `.mise/lib/bench_helpers.sh`: like
  `bench_start_server_hsm`, but does not set `key_encryption_key` — no KEK is
  ever created, since resident-key benchmarking doesn't need wrapping
- Add an optional `docs_subdir` argument to `bench_generate_report` (default
  `ckms_bench`, unchanged for `bench/load`/`bench/load-hsm`) so
  `bench/load-hsm --delegated` writes its report to a **separate**
  `documentation/docs/benchmarks/ckms_bench_hsm/` directory instead of
  clobbering the software baseline that `bench/load`/`bench/load-hsm` share
  (the shared helper replaces its target directory wholesale on every run)

### SoftHSM2 per-token degradation: found, isolated, and worked around

Running the full `--mode all` sweep in a single SoftHSM2 session initially
hung: concurrent RSA/EC key **generation** progressively degrades a
SoftHSM2 token — subsequent PKCS#11 operations, *even unrelated
Encrypt/Sign calls against different keys*, slowed from milliseconds to
**minutes** per request afterwards. This reproduced even with key-creation
concurrency capped at 4 client-side, so it is cumulative (more keys ever
created on the token), not purely a function of peak concurrency. This is a
SoftHSM2 limitation (a software simulator not built for heavy concurrent/
cumulative key generation on one token), not a KMS defect.

Fix, so a single `bench/load-hsm --delegated` invocation reliably produces a
complete report:

- `PreparedLoadOp::max_concurrency` (`load.rs`) caps HSM key-creation
  load-test concurrency at 4 regardless of the requested sweep, applied by
  `bench_load` per-operation.
- `bench/load-hsm --delegated`, when `--mode all` (the default), now runs
  `key-creation`, `encrypt`, and `sign-verify` as **three separate SoftHSM2
  sessions**, each with its own fresh token, so key-creation's key
  generation never contaminates the encrypt/sign token. Results are merged
  (the load JSON format is one-object-per-line, so concatenation is a valid
  merge) into a single final report. Single-mode runs (`--mode encrypt`,
  etc.) already only ever touch one fresh token and need no such isolation.

### Criterion group-name fix for HSM report categorization

The HSM criterion benchmarks were initially named `{protocol}/hsm/{op_type}/
{algorithm}` (e.g. `ttlv-json/hsm/encrypt/aes-gcm`), but
`.mise/scripts/bench/plot_version_compare.py`'s `bench_id_to_parts` expects
exactly `{protocol}/{op_type}/{algorithm}` (splitting on the first
underscore after stripping the protocol prefix) — the extra `hsm` segment
shifted `op_type` to `"hsm"`, which matches no chart category, so every HSM
criterion result was silently dropped from the report (`Criterion
Benchmarks` section rendered empty, despite `criterion.json` containing 16
benchmarks). Fixed by renaming groups to `{protocol}/{op_type}/hsm-
{algorithm}` (e.g. `ttlv-json/encrypt/hsm-aes-gcm`), which parses `op_type`
correctly, plus a matching one-line fix in `_is_symmetric` (strip the
`hsm-` prefix before checking for `aes`/`chacha`/etc.) so AES-GCM still
categorizes as **Symmetric Encryption** rather than falling through to
**Asymmetric Encryption**.

### Full HSM benchmark run — final report

`mise run bench:load-hsm --delegated --criterion --speed quick` (default modes/
protocols/concurrency, SoftHSM2 2.6.1, i9-14900T, release build) now
completes end-to-end: **6 load-test operations / 46 records / 6 SVG
charts**, **16 criterion benchmarks / 4 SVG charts**, written to
`documentation/docs/benchmarks/ckms_bench_hsm/report.md`.

Measured HSM-direct throughput (load test, `ttlv-json`):

| Operation | Concurrency 1 | Peak (concurrency) |
|---|---|---|
| `hsm/encrypt/aes-gcm` | 1,049 req/s | 2,697 req/s (c=8) |
| `hsm/encrypt/rsa-oaep` | 1,775 req/s | 2,894 req/s (c=8) |
| `hsm/sign-verify/rsa-pss` | 557 sig/s | 1,481 sig/s (c=8) |
| `hsm/sign-verify/ecdsa-p256` (prehashed) | 1,069 sig/s | 1,578 sig/s (c=2) |
| `hsm/key-creation/aes-256` | 43 keys/s | 43 keys/s (c=1; degrades with concurrency — see caveat) |
| `hsm/key-creation/rsa-2048` | 2.5 keys/s | 5.3 keys/s (c=4, capped) |

Criterion round-trip latency (`ttlv-json`, single request, mean):

| Benchmark | Latency |
|---|---|
| `hsm-aes-gcm/encrypt/256` | 1.72 ms |
| `hsm-rsa-oaep/encrypt/2048` | 2.14 ms |
| `hsm-ecdsa-p256/sign` | 3.67 ms |
| `hsm-ecdsa-p384/sign` | 3.81 ms |
| `hsm-rsa-pss/sign/2048` | 3.54 ms |
| `hsm-aes-256/create` | 77.2 ms |
| `hsm-ec-p256/create` | 226.8 ms |
| `hsm-rsa-2048/create` | 435.9 ms |

All HSM-direct throughput is one to two orders of magnitude below the
corresponding software numbers (e.g. software `ecdsa-p256` sign reached
~13,800 req/s at concurrency 16 in the same environment) — expected, since
every operation now round-trips through PKCS#11 to the (single-threaded,
software-simulated) SoftHSM2 token instead of in-process OpenSSL.

### Correction: Ed25519/Ed448 sign delegation DOES work — extended coverage

A follow-up re-investigation found that the earlier claim "Ed25519/Ed448
sign fails on SoftHSM2 with `CKR_MECHANISM_INVALID`" was a **false
negative caused by a manual-testing mistake**, not a real server limitation:
the earlier validation used `ckms ec sign -k <uid>` without `--curve
ed25519`, so the CLI built ECDSA (not EdDSA) `CryptographicParameters` by
default and the server correctly rejected the mismatched mechanism against
an Ed25519 key. Re-tested with the correct `ckms ec sign --curve ed25519
-k <uid>` (mirroring the CLI's own request-construction logic, which sets
`cryptographic_algorithm: Ed25519` with no `digital_signature_algorithm`
and no `digested_data`) — **both Ed25519 and Ed448 sign work end-to-end**
against a live SoftHSM2 2.6.1 token.

This corrects and extends the HSM bench:
- Added EdDSA (Ed25519/Ed448) sign to `bench_hsm_sign_verify` and
  `prepare_hsm_load_ops` (both criterion and `--load`), gated `non-fips`.
- Added ECDSA P-384 was already present; also added AES-CBC encrypt
  (`aes_cbc_params()` helper, new) and EC-P256/Ed25519/Ed448 key-creation
  timing to the criterion path.
- Re-ran the full HSM bench: now **9 load-test operations / 76 records / 9
  SVG charts**, **26 criterion benchmarks / 4 category charts** (up from 6/46/16
  before this correction).

Measured EdDSA HSM-direct sign throughput (load test, concurrency 1-16,
`ttlv-json`):

| Operation | Concurrency 1 | Peak (concurrency) |
|---|---|---|
| `hsm/sign-verify/eddsa-ed25519` | 611 sig/s | 877 sig/s (c=4) |
| `hsm/sign-verify/eddsa-ed448` | 507 sig/s | 906 sig/s (c=4) |

Criterion round-trip latency additions (`ttlv-json`, mean):

| Benchmark | Latency |
|---|---|
| `hsm-aes-cbc/encrypt/256` | 2.73 ms |
| `hsm-eddsa-ed25519/sign` | 6.70 ms |
| `hsm-eddsa-ed448/sign` | 6.40 ms |
| `hsm-ed25519/create` | 229.4 ms |
| `hsm-ed448/create` | 235.5 ms |

Separately, while investigating this, found and worked around one more
genuine SoftHSM2/environment issue: `HSM::create_keypair` for P-521 rejects
the generated key (`Invalid key length: 520 bits ... valid values are 224,
256, 384, 521`) 3/3 attempts in this environment — a pre-existing bug in
`crate/crypto/src/crypto/elliptic_curves/operation.rs`'s `cryptographic_length`
derivation (byte-length of the serialized private scalar, which can
under-count P-521 by one byte), unrelated to HSM delegation and out of
scope for this benchmark change; P-521 remains excluded from the HSM bench,
tracked as a follow-up.

### Full "every HSM-delegated crypto operation" coverage + report sections

A follow-up request asked to make the report's `## Protocols` and
`## Benchmark Methodology` sections HSM-aware, and to ensure every
HSM-delegated cryptographic operation is covered. Audited
`crate/interfaces/src/crypto_oracle.rs`'s `CryptoAlgorithm` (encrypt) and
`SigningAlgorithm` (sign) enums against the bench's existing coverage and
found two gaps:

- **Encrypt**: `RsaPkcsV15` and `RsaOaepSha1` were not benched (only
  `AesGcm`, `AesCbc`, `RsaOaepSha256`).
- **Sign**: `Sha1WithRsa`/`Sha256WithRsa`/`Sha384WithRsa`/`Sha512WithRsa`
  (RSA PKCS#1 v1.5 hash-and-sign, selected via
  `DigitalSignatureAlgorithm::SHA*WithRSAEncryption`) were not benched (only
  `RsaPss`, `Ecdsa`, `Ed25519`/`Ed448`).

Added both gaps to `bench_hsm_encrypt`/`bench_hsm_sign_verify` (criterion)
and `prepare_hsm_load_ops` (`--load`), with new ungated
(non-`non-fips`-gated) `CryptographicParameters` helpers in `helpers.rs`
(`rsa_oaep_sha1_params`, `hsm_rsa_pkcs1v15_encrypt_params`,
`hsm_rsa_pkcs1v15_sign_params`) — confirmed unconditionally supported by the
oracle via the existing `test_data/vectors/hsm/resident_rsa2048_*` vectors,
so these are not gated by FIPS mode. The one `SigningAlgorithm` variant
still without a bench entry, the bare (un-hashed) `RsaPkcsV15` sign, has no
reachable KMIP request shape (`from_kmip` always infers a hash for
`PKCS1v15` without an explicit digest) — documented as unreachable rather
than silently missing.

Made `## Protocols` and `## Benchmark Methodology` HSM-aware: added an
`--hsm` flag to `.mise/scripts/bench/plot_version_compare.py` (stripped from
`argv` before positional parsing), threaded through a new `is_hsm` parameter
on `bench_generate_report` (`.mise/lib/bench_helpers.sh`), passed as
`"true"` by `bench/load-hsm --delegated`. When set:
- `## Protocols` lists only `ttlv-json`/`ttlv-bytes` (not `jose`) and
  explains why JOSE key creation can't address `hsm::` keys.
- `## Benchmark Methodology` replaces the generic software text with the
  HSM delegation model, the full algorithm-coverage table above (including
  the two documented gaps), actual HSM payload sizes (64 bytes encrypt / 32
  bytes sign, not the software bench's per-algorithm size table), and the
  SoftHSM2 per-token degradation caveat (previously only in code comments).

Re-ran the full HSM bench: now **15 load-test operations / 136 records / 15
SVG charts**, **38 criterion benchmarks / 4 category charts** (up from
9/76/9/26) — every `CryptoAlgorithm`/`SigningAlgorithm` oracle variant
reachable via an ordinary KMIP request now has a bench entry.

### Regenerated the official software benchmark report (`ckms_bench`)

The checked-in `documentation/docs/benchmarks/ckms_bench/report.md` was
stale (`v5.24.0`, generated 2026-07-09) — it predated the EdDSA load-test
addition (`sign-verify/eddsa-ed25519`, part of the earlier #1155 work on
this branch), so `--load`'s Ed25519 numbers were validated during
development but never landed in the checked-in baseline. Regenerated via
`mise run bench:load --criterion --speed quick` (mode=all, protocol=all,
i9-14900T, release/non-fips) and kept the result (`v5.27.0`, 5 load
operations / 55 records, 212 criterion benchmarks): the Load Tests section
now includes `sign-verify/eddsa-ed25519` alongside `sign-verify/ecdsa-p256`,
reaching ~49,800 req/s (`ttlv-json`), ~49,100 req/s (`ttlv-bytes`), and
~63,600 req/s (`jose`) at concurrency 16 — confirming the extrapolation in
issue #1155 and roughly 3.8× the ECDSA P-256 throughput in the same run.

### Merged `bench/load-hsm-crypto` into `bench/load-hsm --delegated`

Having two separate, similarly-named mise tasks (`bench/load-hsm` for the
software-crypto KEK-wrap benchmark, `bench/load-hsm-crypto` for the
HSM-delegated crypto benchmark added above) was confusing — the names
differ only by a suffix, yet they exercise entirely different code paths.

Merged the two into a single task, `.mise/tasks/bench/load-hsm`, selected by
a new `-d`/`--delegated` boolean flag:

- Default (no flag): unchanged KEK-wrap benchmark (software crypto, root key
  wrapped by an HSM-resident KEK).
- `--delegated`: the HSM-delegated crypto benchmark (all crypto executed
  directly on the HSM), formerly `bench/load-hsm-crypto` — same
  three-session `--mode all` splitting, same `docs_subdir=ckms_bench_hsm`
  report output, same `--criterion`/`--speed` flags, unchanged behavior.

Deleted `.mise/tasks/bench/load-hsm-crypto`. Updated the two stale doc-comment
references in `crate/clients/clap/src/actions/bench/types.rs` and the two
comment references in `.mise/scripts/bench/plot_version_compare.py` that
named the old task, and regenerated
`documentation/docs/benchmarks/ckms_bench_hsm/report.md` (Methodology
section) to reference `bench/load-hsm --delegated` instead — this was done
by re-running `plot_version_compare.py` directly against the existing
`target/criterion/reports/5.27.0/` data, without a full benchmark re-run,
since only report text changed, not measured behavior.

Usage after the merge:

```bash
mise run bench:load-hsm                         # KEK-wrap (software crypto)
mise run bench:load-hsm --delegated --criterion  # HSM-delegated crypto
```

### Dropped ttlv-bytes from the HSM-delegated report; gave the KEK-wrap benchmark its own dedicated report

Follow-up to the diagnosis above ("Why HSM sign is ~80x slower" / the ttlv-json-vs-ttlv-bytes
ordering artefact): every ttlv-bytes measurement in the HSM-delegated report was
contaminated by running strictly *after* the ttlv-json sweep against the same
HSM-resident key/token, so ttlv-json appeared faster than ttlv-bytes in every single
row — the opposite of the software baseline, and not a real protocol difference.

- Removed all `ttlv-bytes` generation from HSM-delegated benchmarks:
  - `prepare_hsm_load_ops` (`load.rs`) no longer builds `PreSerializedBinary` ops for
    HSM-delegated operations; only `ttlv-json` is benchmarked. Requesting `--protocol
    ttlv-bytes`/`all` with `--hsm --load` now prints a skip notice explaining why.
  - `run_hsm_kmip_benches` (criterion mode, via `clap.rs`) is no longer called with
    `Transport::Bytes`; the same skip notice is printed instead.
- `documentation/docs/benchmarks/ckms_bench_hsm/report.md`'s Protocols section now
  documents `ttlv-json` as the only protocol, with the ordering-artefact explanation
  reproduced in full; a new Methodology subsection ("Why ttlv-json only (no
  ttlv-bytes)") documents the root cause for future readers.
- Gave the HSM-backed-KEK benchmark (`bench/load-hsm`'s default, non-`--delegated`
  mode) its own dedicated report directory,
  `documentation/docs/benchmarks/ckms_bench_hsm_kek/`, instead of silently sharing
  (and clobbering) the plain software baseline's `ckms_bench/` directory. Its
  Protocols/Methodology sections mirror the software baseline exactly (all three
  protocols, `jose` included, since only the KEK unwrap touches the HSM — Encrypt/Sign
  still execute in KMS software), prefixed with a one-paragraph note clarifying the
  HSM-backed-KEK setup. Added a `--kek` flag to `plot_version_compare.py` and a new
  `is_hsm_kek` parameter to `bench_generate_report` to produce this variant.
- There are now **three independent benchmark reports**, all linked from the mdBook
  "Benchmarks" nav section:
  1. `benchmarks/ckms_bench/report.md` — software baseline (`bench/load`)
  2. `benchmarks/ckms_bench_hsm_kek/report.md` — HSM-backed KEK, software crypto
     (`bench/load-hsm`, default)
  3. `benchmarks/ckms_bench_hsm/report.md` — HSM-delegated crypto, ttlv-json only
     (`bench/load-hsm --delegated`)

### New independent benchmark: `mise bench:load-pkcs11`

- Add a new `cosmian_pkcs11_bench` crate (`crate/clients/pkcs11/bench`) and a new
  `mise bench:load-pkcs11` task (renamed from an initial `bench:pkcs11`),
  benchmarking the `cosmian_pkcs11` PKCS#11 provider itself rather than the KMIP
  REST API: the benchmark `dlopen()`s the built `libcosmian_pkcs11.{so,dylib}` and
  drives its real Cryptoki v2.40 C ABI (`C_Initialize`, `C_OpenSession`,
  `C_EncryptInit`/`C_Encrypt`, `C_DecryptInit`/`C_Decrypt`, `C_SignInit`/`C_Sign`,
  `C_VerifyInit`/`C_Verify`, `C_GenerateKey`, ...) — the same call path real-world
  PKCS#11 consumers (Oracle TDE, OpenSSH, disk-encryption tools) use, which
  `bench/load`'s direct `KmsClient`/HTTP path does not exercise
- Intentionally uses a **single shared `C_OpenSession` handle** reused by every
  concurrent worker thread of the sweep, instead of one session per thread: the
  provider's own session store (`crate/clients/pkcs11/module/src/sessions.rs`)
  already serializes all session access behind one global `Mutex`, so this
  benchmarks real-world single-session contention rather than artificial
  per-thread parallelism
- Five modes, run individually or via the default `all`, each measured
  **independently** (its own concurrency sweep, its own report row/chart — never a
  combined round trip): `encrypt` (`C_EncryptInit`/`C_Encrypt`, AES-CBC-PAD),
  `decrypt` (`C_DecryptInit`/`C_Decrypt`, against ciphertext produced once during
  setup, not timed), `sign` (`C_SignInit`/`C_Sign`, RSA `CKM_SHA256_RSA_PKCS`),
  `verify` (`C_VerifyInit`/`C_Verify`, RSA `CKM_SHA256_RSA_PKCS`), and
  `key-creation` (`C_GenerateKey` + `C_DestroyObject`, ephemeral AES key per
  iteration — `C_GenerateKeyPair` is not implemented by the provider, since
  asymmetric keys are always created through the KMS REST API, not PKCS#11).
  `verify` is probed once before sweeping and skipped with a console notice if the
  loaded provider reports `CKR_FUNCTION_NOT_SUPPORTED` (as `cosmian_pkcs11_module`
  currently does for `C_VerifyInit`/`C_Verify`), instead of publishing fabricated
  numbers for an operation that always fails
- Reuses `.mise/lib/bench_helpers.sh` (`bench_start_server`,
  `bench_register_cleanup`, `bench_warn_cpu_scaling`, and now also
  `bench_generate_report`) for the temporary SQLite-backed KMS server and the
  report pipeline, and extends `.mise/lib/pkcs11_helpers.sh`'s
  `get_cosmian_pkcs11_lib` with an optional build-mode argument (defaults to
  `debug`, preserving existing callers) so the new task can resolve the
  library path for release builds too
- **Now generates a dedicated report**, `documentation/docs/benchmarks/ckms_bench_pkcs11/`,
  reusing the existing Criterion/`plot_version_compare.py` pipeline unchanged for
  chart/table generation: the benchmark binary writes `load_pkcs11.json` in the
  exact same schema `bench/load` uses (`crate/clients/pkcs11/bench/src/report.rs`),
  so `bench_generate_report`'s existing `load_*.json` glob picks it up with zero
  parsing changes. Added a new `--pkcs11` flag to `plot_version_compare.py`
  (alongside the existing `--hsm`/`--kek`) and a matching `is_pkcs11` parameter to
  `bench_generate_report`, so the report's Protocols/Methodology sections describe
  the real dlopen()-based Cryptoki benchmark instead of the generic
  KMIP-wire-protocol text — mirroring `bench/load`/`bench/load-hsm` exactly instead
  of a standalone console-only benchmark as originally implemented

### Add EdDSA-Ed25519 `sign`/`verify` modes to `mise bench:load-pkcs11`

- `mise bench:load-pkcs11` previously only exercised RSA (`CKM_SHA256_RSA_PKCS`)
  for its `sign`/`verify` modes — there was no way to benchmark Ed25519 through
  PKCS#11 at all, even though `cosmian_pkcs11_module` fully supports `CKM_EDDSA`.
  Added two new modes, `sign-eddsa`/`verify-eddsa`, that drive `C_SignInit`/`C_Sign`
  and `C_VerifyInit`/`C_Verify` with `CKM_EDDSA` against a dedicated Ed25519 key
  pair now provisioned by `src/setup.rs` alongside the existing AES/RSA keys,
  enabling a real, apples-to-apples comparison against `mise bench:load`'s
  `eddsa-ed25519` KMIP-REST case
- `Pkcs11Session::sign`/`verify` (`src/loader.rs`) now take an explicit
  `CK_MECHANISM_TYPE` parameter instead of hardcoding `CKM_SHA256_RSA_PKCS`, and a
  new `find_first_by_class_and_key_type` helper disambiguates the RSA vs. Ed25519
  private/public key objects by `CKA_KEY_TYPE` (`CKK_RSA`/`CKK_EC_EDWARDS`) — plain
  `find_first_by_class` would otherwise non-deterministically return whichever key
  the backend enumerates first now that two key pairs exist
- Added the two new mode names to `.mise/tasks/bench/load-pkcs11`'s `--mode`
  `choices` list and to the crate `README.md`'s mode table
- Corrected a stale doc comment/README claim that `C_VerifyInit`/`C_Verify` are
  unimplemented (`CKR_FUNCTION_NOT_SUPPORTED`) by `cosmian_pkcs11_module` — both
  are registered via `cryptoki_fn!`, not `cryptoki_fn_not_supported!`, and do work
  (confirmed live: `verify`/`verify-eddsa` both execute and report real
  throughput/latency). The runtime skip-with-notice fallback is kept as a
  defensive guard for a future provider/backend that doesn't support it, not
  because it is currently needed

### `mise bench:load-pkcs11` now pools one Cryptoki session per worker thread

- Every worker thread of the concurrency sweep previously hammered a **single**,
  process-wide-shared `C_OpenSession` handle — the doc comments framed this as
  intentionally modeling "real-world single-session contention", but it also meant
  the benchmark could never demonstrate any of the parallelism the module-level
  session-locking fix above (see "Bug Fixes") now provides
- `main.rs` now opens a *pool* of sessions up front (one per worker thread the
  sweep will ever spawn — the highest requested `--concurrency` level — or a
  single session under the new `--shared-session` flag), sequentially, before any
  worker thread is spawned. `Pkcs11Session::open` (`src/loader.rs`) now guards
  `C_Initialize` with an `AtomicBool` so it only actually runs once even though
  `open()` itself is now called once per pooled session (a second `C_Initialize`
  call is a Cryptoki protocol error, `CKR_CRYPTOKI_ALREADY_INITIALIZED`).
  `run_sweep`/`run_for`/`run_all` (`src/load.rs`) now thread a `&[Pkcs11Session]`
  pool through instead of a single shared `&Pkcs11Session`, indexing
  `pool[i % pool.len()]` per worker thread — object handles found via one session
  remain valid on any other session, since `crate/clients/pkcs11/module/src/
  objects_store.rs`'s object store is global, not scoped per session
- Added `--shared-session` (mise: `--shared-session`) to force the old
  everyone-shares-one-handle model back on, purely so the pre-fix numbers above
  remain reproducible for direct before/after comparison — it is not how a
  well-behaved, high-concurrency PKCS#11 consumer would actually use the provider,
  so it is not the default

### Add `--criterion` mode to `mise bench:load-pkcs11`; diagnose remaining latency variance

- Added real `criterion`-crate single-operation micro-benchmarks
  (`src/criterion_bench.rs`, new `--criterion`/`--speed` flags mirroring `mise
  bench:load --criterion`'s own `sanity`/`quick`/`normal` presets exactly) as a
  fast alternative to the concurrency sweep — no per-level warmup/cooldown,
  statistically rigorous mean/median/CI per mode, and (with `--speed quick`)
  results in a couple of seconds instead of tens of seconds to minutes. Skipping
  the sweep entirely means the generated report has only a "Criterion data"
  section, no "Load test data" one
- Refactored `load.rs`: extracted `prepare_ops` (all the one-time
  setup/object-discovery/`C_Verify`-support-probe logic previously inlined in
  `run_all`) so both the concurrency sweep and the new criterion path build each
  mode's closure identically and can never silently diverge
- `report.rs` gained `write_criterion_json`, a small self-contained duplicate of
  `crate/clients/clap/src/actions/bench/output.rs`'s criterion-estimates collector
  (that one is `pub(super)`-private to the `clap` bench module) — walks
  `$CRITERION_HOME` for `new/estimates.json` files and writes `criterion.json` in
  the identical JSONL schema, so `bench_generate_report`/`plot_version_compare.py`
  need zero changes to pick it up
- **Bottleneck-hunting finding, using the new fast loop**: re-benchmarking
  `sign-eddsa`/`sign` (RSA) in isolation, 3 back-to-back identical runs each,
  showed the exact same operation measuring 400µs-800µs in most runs and a
  ~70-250ms outlier (~100-500x) in others — with the very *first* sample of a slow
  run already slow (ruling out any kind of warmup/accumulation effect in the code).
  Correlated with host state: `uptime`/`ps` showed a 1-minute load average of
  ~3-5 on this shared development machine, with several competing CPU-hungry
  background processes (IDE indexing, browser, torrent client, ...) — not the
  benchmarked code. Conclusion: **no remaining code-level bottleneck found**; the
  session-locking and pooled-session fixes above are validated (concurrency scales
  correctly), and the occasional large outlier is host contention on a
  non-dedicated machine, not a regression
- Extended `bench_warn_cpu_scaling` (`.mise/lib/bench_helpers.sh`, shared by every
  `bench/*` task, not just this one) to also check `/proc/loadavg` and warn on an
  elevated 1-minute load average, citing this exact reproduced false alarm, so
  future users don't mistake host noise for a code regression
- **Follow-up fix**: the first `--criterion` run's report was silently missing all
  `sign`/`verify` rows from every chart/table. `.mise/scripts/bench/plot_version_compare.py`'s
  `bench_id_to_parts`/`_criterion_category` (pre-existing, shared with `mise bench:load
  --criterion`) only recognizes the combined op_type `"sign-verify"` for its
  "Sign / Verify" category — never bare `"sign"`/`"verify"`. `run_criterion` used a
  flat `c.bench_function("sign/eddsa-ed25519", ...)`, which criterion sanitizes to
  a single directory `sign_eddsa-ed25519`, parsed as op_type `"sign"` (unrecognized,
  dropped). Fixed by routing `sign`/`verify` labels through a real criterion
  *group* instead — `c.benchmark_group("sign-verify_eddsa-ed25519")` +
  `group.bench_function("sign"|"verify", ...)` — producing the
  `sign-verify_<algo>/<sign|verify>` ID shape the categorizer expects, mirroring
  how `crate/clients/clap/src/actions/bench/transport.rs::bench_op` benchmarks the
  KMIP path. `encrypt`/`decrypt`/`key-creation` labels are unaffected (already
  correctly categorized via the flat path)

### Attribute PKCS#11 Ed25519 signing overhead and remove duplicate remote signing

- Add an apples-to-apples Criterion ladder for Ed25519 signing to
  `mise bench:load-pkcs11 --criterion`: request construction, TTLV+JSON
  serialization, the published `ckms bench --criterion`-equivalent
  pre-serialized full-message HTTP call, a pre-serialized bare `Sign` HTTP call,
  response parsing, typed `KmsClient::sign`, the Tokio `block_on` control cost,
  one-call PKCS#11 signing, and the standard two-call PKCS#11 API after the
  fixed-size length-query optimization. All tiers
  use the same server, key, 32-byte payload, endpoint, runtime, and Criterion
  configuration, and are written to `pkcs11_overhead.json`
- Add a compile-time-only `benchmarking` feature to `cosmian_pkcs11_module` and
  `cosmian_pkcs11`. The feature collects allocation-free in-memory Sign phase
  timings and exposes benchmark-only reset/snapshot symbols to the dynamically
  loaded benchmark library; normal provider builds compile the probes to no-ops
- The phase data shows that session-map lookup, session-lock wait, backend lookup,
  request construction, and signature copying are individually sub-microsecond.
  The typed `KmsClient::sign` call dominates the one-call PKCS#11 path; the Tokio
  ready-future control is about 0.1 microseconds
- Fix a concrete two-request bug: `pkcs11_bench` previously called
  `C_Sign(NULL)` followed by `C_Sign(buffer)`, and `Session::sign` performed a
  complete remote KMS Sign for both calls. Ed25519 one-call signing measured
  approximately 344 microseconds while the historical path measured approximately
  680 microseconds in the same run. Fixed-size Ed25519/Ed448 and RSA length
  queries now return the required size from key metadata without contacting the
  KMS; undersized buffers are rejected the same way without remote signing

### Use binary TTLV for PKCS#11 remote Sign requests

- Change the `cosmian_pkcs11` provider's remote Sign transport from typed
  TTLV-JSON on `POST /kmip/2_1` to a KMIP 2.1 `RequestMessage` serialized as
  binary TTLV on `POST /kmip` with `application/octet-stream`
- Add `KmsClient::post_message_bytes`, which serializes and fully parses binary
  TTLV request/response messages while preserving HTTP and KMIP error handling
- Keep the PKCS#11 caller contract unchanged: `C_SignInit`/`C_Sign` still return
  the same Ed25519 signature bytes and PKCS#11 error codes; only the provider-to-KMS
  wire representation changes
- Regenerate the external `sign-tx` Ed25519 benchmark with the local release KMS,
  `ckms`, and `libcosmian_pkcs11.so`: 1000 signatures verified successfully;
  `C_Sign` p50 was 387.30 microseconds and total p50 was 428.60 microseconds on
  the shared benchmark host

### Use the PKCS#11 v3 message-signing flow for Ed25519 benchmarks

- Implement one-shot EdDSA message signing in the provider's v3.1 function table:
  `C_MessageSignInit` establishes the Ed25519 key/mechanism once,
  `C_SignMessage` signs each independent message while preserving that context,
  and `C_MessageSignFinal` releases it. Other v3 message-operation families remain
  conformant `CKR_FUNCTION_NOT_SUPPORTED` stubs
- Change `cosmian_pkcs11_bench` to discover the provider through `C_GetInterface`
  and a `CK_FUNCTION_LIST_3_0`; Ed25519 setup calls `C_MessageSignInit` once per
  worker session and each measured iteration calls only `C_SignMessage`
- Change the external `sign-tx` benchmark to use the same v3 discovery and
  Ed25519 message-signing flow. P-256 remains on classic
  `C_SignInit`/`C_Sign` because the implemented v3 message path is EdDSA-only
- Add unit coverage proving a message-sign context signs multiple messages and
  remains initialized until `C_MessageSignFinal`
- Build optimized PKCS#11 benchmarks with the speed-oriented workspace `bench`
  profile (`opt-level = 3`) instead of the size-oriented release profile
  (`opt-level = "z"`). A controlled same-host quick run reduced v3
  `C_SignMessage` from approximately 433 microseconds to 227 microseconds
- Bracket the key comparison A/B/A/B (typed binary before, PKCS#11 before, typed
  binary after, PKCS#11 after) and report pair averages, preventing a late-running
  tier from absorbing thermal/scheduler/server drift. In the first improved run,
  bracketed typed binary Sign measured 119.1 microseconds and bracketed v3
  `C_SignMessage` measured 124.4 microseconds: 5.3 microseconds / 4.4% overhead
- Add configurable fixed or varying differential payloads and regenerate the
  normal-speed report with varying 150-byte messages. The final bracketed means
  are 134.2 microseconds for typed binary Sign and 143.7 microseconds for PKCS#11
  v3 `C_SignMessage`: 9.6 microseconds / 7.1% incremental PKCS#11 overhead.
  Internal profiling attributes only tens of nanoseconds each to session lookup,
  lock wait, backend lookup, and signature copy; the remote typed KMS call remains
  the dominant boundary
- Stabilize the external `sign-tx` harness with a minimum elapsed warmup,
  three independent trials, median-trial selection, and optional separate CPU
  affinity for client and server. On the shared development host, affinity
  reduced trial p50 spread from 359.89-1223 microseconds to
  137.40-146.78 microseconds; the final 1000-iteration representative run
  measured 114.11 microseconds for `C_SignMessage` and 139.28 microseconds
  end-to-end including local verification

### `mise bench:load-pkcs11 --mode sign`/`--mode verify` now cover every signature algorithm

`--mode sign` previously benchmarked RSA (`CKM_SHA256_RSA_PKCS`) only; ECDSA had no
mode at all, and EdDSA required the separate `sign-eddsa`/`verify-eddsa` names.

- `src/setup.rs` now always provisions an EC P-256 key pair (FIPS-approved, unlike
  Ed25519, so it is provisioned unconditionally, mirroring the RSA key pair) in
  addition to the existing AES/RSA/Ed25519 keys.
- Renamed the previous `ConcreteMode::Sign`/`Verify` to `SignRsa`/`VerifyRsa` and
  added `SignEcdsa`/`VerifyEcdsa` (`CKM_ECDSA`, driven against the same 32-byte
  payload already used as the Ed25519 message — it doubles as the pre-computed
  SHA-256 digest `CKM_ECDSA` expects, since the mechanism performs no hashing of
  its own), disambiguated from the RSA/Ed25519 key pairs by `CKK_EC` in
  `find_first_by_class_and_key_type`.
- `BenchMode::Sign`/`Verify` are now aggregate CLI modes: `--mode sign` expands to
  `[SignRsa, SignEcdsa, SignEdDsa]` (`--mode verify` likewise) instead of naming one
  algorithm, so a single invocation benchmarks every signature algorithm the
  provider supports in one sweep/report, one row per algorithm — mirroring `--mode
  all`'s aggregate behavior but scoped to signing. `--mode sign-rsa`/`sign-ecdsa`/
  `sign-eddsa` (and their `verify-*` counterparts) remain available to benchmark one
  algorithm in isolation. FIPS builds drop the EdDSA entry from every aggregate,
  unchanged from the prior `sign-eddsa`/`verify-eddsa` gating.
- `mise bench:load-pkcs11 --mode sign --sanity`-equivalent run (debug build,
  concurrency 1, 2 s/level) confirmed all three algorithms execute end-to-end in one
  sweep: RSA-2048 (~36 ops/s), ECDSA P-256 (~258 ops/s), Ed25519 (~863 ops/s); same
  for `--mode verify` (RSA ~653 ops/s, ECDSA ~242 ops/s, Ed25519 ~860 ops/s).
- Updated `.mise/tasks/bench/load-pkcs11`'s `--mode` choices list and
  `crate/clients/pkcs11/bench/README.md`'s mode table/usage examples accordingly.
  `criterion_bench.rs`/`plot_version_compare.py` required no changes: both already
  parse `sign`/`verify` labels generically by splitting on `/`, so the new
  `sign/ecdsa-p256`/`verify/ecdsa-p256` labels are categorized correctly with zero
  additional code.

### CI fix: `test / HSM softhsm2 - non-fips` and `test / HSM crypt2pay - non-fips` — missing `SOFTHSM2_PKCS11_LIB` export

Both jobs failed in their `Test (PKCS#11 v3 conformance via pkcs11-tool)` step
(`mise run test:hsm-pkcs11-tool`), which always exercises a SoftHSM2-backed
HSM-KEK regardless of which HSM the surrounding job matrix targets:

```
Error: Unexpected server error: start KMS server: failed instantiating the server:
Invalid Request: Failed to instantiate the Softhsm2 HSM
(lib: /usr/lib/softhsm/libsofthsm2.so): Error loading the library:
/usr/lib/softhsm/libsofthsm2.so: cannot open shared object file: No such file or directory
```

Root cause: `hsm_kek_bootstrap` (`.mise/lib/pkcs11_helpers.sh`) sets up a SoftHSM2
token and extends `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`, but never exported
`SOFTHSM2_PKCS11_LIB` before starting the KMS server. The server resolves its
SoftHSM2 PKCS#11 library from that env var, falling back to a hardcoded path
(`crate/hsm/softhsm2/src/lib.rs::SOFTHSM2_PKCS11_LIB`,
`/usr/lib/softhsm/libsofthsm2.so` on Linux) that only exists when SoftHSM2 was
installed via the system package manager — not on the Nix-based CI runners used
here, where `mise`'s nix-shell builds SoftHSM2 into the Nix store instead. The
sibling helper `run_db_softhsm2_tests` (`.mise/lib/softhsm2.sh`) already exported
this variable correctly; `hsm_kek_bootstrap` was the one path that didn't.

Fix: `hsm_kek_bootstrap` now also exports
`SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH:-}"` (resolved by
`softhsm2_detect_lib`, called from `softhsm2_setup` earlier in the same function),
alongside the existing library-path exports. Verified locally end-to-end: `mise run
test:hsm-pkcs11-tool --variant non-fips` now bootstraps the HSM-KEK and passes all
five conformance checks (ECDSA P-256, ECDSA secp256k1, EdDSA Ed25519, RSA-PSS, and
the tampered-signature rejection case).

### CI fix: `test / HSM crypt2pay - non-fips` — `CKR_ATTRIBUTE_TYPE_INVALID` on `CKA_START_DATE`/`CKA_END_DATE` for AES keys

The same run's `test / HSM crypt2pay - non-fips` job failed earlier, in its plain
`Test` step (`cargo test -p crypt2pay_pkcs11_loader --lib -- tests::test_hsm_crypt2pay_all
--ignored`), before the pkcs11-tool step even started:

```
Error: Default("Failed to get the HSM attributes for key handle: 16777248. Return code: 18")
test tests::test_hsm_crypt2pay_all ... FAILED
```

Root cause: `crate/hsm/base_hsm/src/session/session_impl.rs::get_key_dates` queries
`CKA_START_DATE`/`CKA_END_DATE` via the shared `call_get_attributes` helper, whose
doc comment on the call site claims "If the HSM doesn't support these attributes,
just return None for both" — but `call_get_attributes` only special-cases
`CKR_OBJECT_HANDLE_INVALID` (returns `None`) and `CKR_ATTRIBUTE_SENSITIVE` (a
dedicated error); any other non-`CKR_OK` code, including `CKR_ATTRIBUTE_TYPE_INVALID`
(0x12 = 18), is treated as a hard failure. The Crypt2pay PKCS#11 emulator returns
exactly `CKR_ATTRIBUTE_TYPE_INVALID` for `CKA_START_DATE`/`CKA_END_DATE` on a plain
AES secret key (these attributes are only meaningful for certificates in the base
PKCS#11 spec), so `shared::get_key_metadata`'s very first `get_key_metadata` call —
on a freshly generated AES-256 key — always fails end-to-end against a real
Crypt2pay HSM. SoftHSM2 does not reproduce this (its emulator accepts the query and
returns `CKR_OK` with empty/zeroed dates), which is why `test / HSM softhsm2 -
non-fips`'s equivalent `test_hsm_softhsm2_all` test (calling the same
`shared::get_key_metadata` helper) was unaffected.

Fix: extracted the raw `C_GetAttributeValue` FFI call out of `call_get_attributes`
into a new `raw_get_attributes` helper returning the unmodified `CK_RV`, so
`get_key_dates` can interpret HSM-specific return codes itself without weakening
`call_get_attributes`'s existing strict semantics for its other, non-optional
callers (e.g. reading `CKA_MODULUS` for an RSA key, where an unexpected attribute
error should remain a hard failure). `get_key_dates` now treats both
`CKR_OBJECT_HANDLE_INVALID` and `CKR_ATTRIBUTE_TYPE_INVALID` as "dates unavailable"
and returns `(None, None)`, matching its own doc comment's intent.

Verified: `cargo test -p cosmian_kms_base_hsm --features non-fips --lib` (24 passed)
and `cargo clippy -p cosmian_kms_base_hsm --all-targets --features non-fips -- -D
warnings` both clean; re-ran `mise run test:hsm-softhsm2 --variant non-fips`
end-to-end locally (58 HSM vector tests + `test_hsm_softhsm2_all`, all still
passing) to confirm no regression on the HSM that previously worked. The Crypt2pay
path itself could not be re-verified locally (requires the physical/emulated
Crypt2pay HSM only available in CI), but the fix only changes behavior for the two
previously-unhandled return codes on this one call site.

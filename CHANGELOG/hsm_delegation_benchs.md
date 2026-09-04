# HSM-direct crypto benchmarks: `ckms bench --hsm` and `bench/load-hsm --delegated`

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

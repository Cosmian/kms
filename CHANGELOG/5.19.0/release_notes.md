# 5.19.0 release notes (full text)

Full text of the `## [5.19.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.19.0] - 2026-04-01

### 🚀 Features

- PostgreSQL HA cluster support with multi-host URLs (#818)

#### OpenSSH PKCS#11 Support

- **Reliable key material refresh**: fixed `ObjectsStore::upsert()` replacement logic so placeholder objects are properly updated with fetched key bytes, preventing `CKR_GENERAL_ERROR` during OpenSSH key enumeration.
- **Correct public-key decoding paths**: fixed RSA/EC public key extraction to use SPKI BIT STRING payload bytes and refactored conversion through `try_from_spki`, including correct EC OID handling.
- **PKCS#11-compliant EC point export**: encoded `CKA_EC_POINT` as DER OCTET STRING (PKCS#11 v2.40), enabling OpenSSH/OpenSSL parsing compatibility.
- **Safer attribute exposure for mixed key types**: guarded RSA-only attributes (`CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`) behind `is_rsa()` checks to avoid non-RSA lookup failures.
- **Provider runtime and API hardening**: migrated provider internals to lock-free/shared primitives (`OnceLock`, shared runtime, `LazyKeyMaterial`) and reduced cloning/boilerplate (`remote_id() -> &str`, macro-based trait impls),
- improving stability and performance under OpenSSH PKCS#11 usage patterns.

#### Web UI Enhancements - Sync UI with ckms

- **UI**: Add DeriveKey page — derive a symmetric key from an existing key or password using PBKDF2/HKDF, with full WASM binding (`derive_key_ttlv_request`, `parse_derive_key_ttlv_response`).
- **UI**: Add `/server-info` endpoint exposing KMS version, FIPS mode, and HSM status; display HSM info in the UI header.
- **UI**: Add `--no-ui` / `KMS_UI_ENABLE=false` server flag to disable the built-in web interface at runtime.
- **UI**: Regroup Azure, AWS, and Google CSE menu entries under a "Hyperscalers" group; add icons to all sidebar categories.
- **UI**: Hide PQC, MAC, and Covercrypt menu entries when the server is running in FIPS mode.

### 🐛 Bug Fixes

### JWT authentication

- Fix server worker panic on the first JWT-authenticated request: `jsonwebtoken` 10.x requires
  an explicit crypto-backend feature (`rust_crypto` or `aws_lc_rs`); added `rust_crypto` to both
  the workspace and CLI `jsonwebtoken` dependencies
- Fix `401 No authentication provided` when the JWT token carries an `aud` claim but the server
  has no expected audience configured: `jsonwebtoken` 10.x now rejects such tokens with
  `InvalidAudience` unless `validate_aud` is explicitly disabled; the server's JWT validation now
  sets `validate_aud = false` when no audience restriction is configured

### Server Security and Configuration

- **TLS auth** (#811): Reject client certificates whose CN is empty or `*`; prevents wildcard spoofing attacks.
- **HSM config** (#695): Expose `KMS_HSM_PASSWORD` and `KMS_HSM_SLOT` environment variables for `--hsm-password` / `--hsm-slot` server options so HSM credentials can be injected without config-file edits.

#### CLI Operations

- **CLI destroy type-safety** (#763): `ckms {sym,rsa,ec,pqc,cc} keys destroy` now performs a `GetAttributes` pre-flight check and rejects attempts to destroy a key of the wrong type with a clear error message.

#### HSM Operations

- **Server-side HSM destroy type guard** (#763): When `Destroy.expected_object_type` is set and the target UID belongs to an HSM object (prefix `hsm::`), the server performs a PKCS#11 attribute roundtrip to retrieve the actual key type and
- rejects the destroy with `Invalid_Object_Type` if the types do not match (e.g. attempting to destroy an AES key via `rsa keys destroy`). ([#763](https://github.com/Cosmian/kms/issues/763))
- **HSM destroy type-guard test assertion** (#763): Fixed `send_message` test helper in HSM tests to include `result_reason` in the error string so that `Invalid_Object_Type` is surfaced when the destroy-type guard fires;
the assertion now reliably matches the KMIP `ErrorReason`. ([#763](https://github.com/Cosmian/kms/issues/763))

#### Web UI

- **UI no-auth mode** (#739): The web UI `create` / `import` buttons are now enabled immediately in no-auth mode (`AuthMethod::None`); previously the async sequencing called the permissions API before the auth method was resolved,
causing buttons to stay disabled.

### 🔧 CI

- **CI**: All test scripts that start the KMS server are now protected against a system-level `/etc/cosmian/kms.toml`; `test_hsm_softhsm2.sh`, `test_hsm_utimaco.sh`, and `test_hsm_proteccio.sh` write a temporary config file and
pass `--config` explicitly so the server never falls back to the default path. `common.sh` now warns early when the default config file is found on the host. ([#810](https://github.com/Cosmian/kms/issues/810))

#### SBOM Generation

- **Fix sbomnix version and arguments**: The global nixpkgs pin ships an older sbomnix that does not support `--impure` or `--include-vulns`, causing *"unrecognized arguments"* errors in CI.
Pinned sbomnix to **v1.7.4** via its own GitHub flake (`github:tiiuae/sbomnix/v1.7.4`) — independent of the nixpkgs pin — so the supported flags are guaranteed. Restored `--impure --include-vulns` on all three `sbomnix` invocations,
moved `NIX_CONFIG=nix-command flakes` export to script start (needed for `nix run`), and removed the now-unnecessary `dedup_cves.py` post-processing step.

### 📚 Documentation

- **Docs**: Reintegrate PKCS#11 pages from `cli_documentation/docs/pkcs11` into main docs under `documentation/docs/integrations`, grouping database integrations in `integrations/databases`, disk encryption in `integrations/disk_encryption`,
and adding an OpenSSH integration entry.

#### KMIP Wrapping Documentation

- **`CKM_RSA_AES_KEY_WRAP` invocation** (#688): Document that this scheme is selected by pairing `CryptographicAlgorithm::RSA` with `PaddingMethod::None`; explains the counter-intuitive routing (None ≠ unpadded RSA), adds a KMIP JSON TTLV example,
and adds a routing table. Fix broken `../algorithms.md` links in `_export.md` and `_import.md`.

#### Benchmarking and CI Documentation

- **Benchmarks CI** (#776): `benchmarks.sh` now builds the KMS server + ckms CLI, starts a temporary SQLite KMS instance, and runs `ckms bench --speed sanity --format json` as an end-to-end smoke test;
supports `BENCH_SAVE_BASELINE` / `BENCH_LOAD_BASELINE` env vars for criterion regression comparisons on a dedicated machine.
- **Benchmark regression workflow** (#776): New `benchmark_regression.sh` script and `benchmark.yml` GitHub Actions workflow provide automated performance regression detection.
The script downloads the reference `benchmarks.json` from `package.cosmian.com`, runs benchmarks on the current branch, and fails if the average global regression exceeds a configurable threshold (default 10%).
The workflow runs on a self-hosted runner (for stable timings) on a weekly schedule and on demand. ([#776](https://github.com/Cosmian/kms/issues/776))

### 🔄 Refactor

#### Script Infrastructure Reorganization

- **Script reorganization**: Reorganized 76 scripts from the flat `.github/scripts/`, `nix/scripts/`, and `scripts/` directories into logical subdirectories under
`.github/scripts/`: `test/`, `build/`, `package/`, `release/`, `benchmarks/`, `pykmip/`, `sbom/`, `docs/`, `demo/`, `windows/`, `shared/`. All cross-references in `nix.sh`, workflow YAMLs, and the scripts themselves have been updated.
Added `shared/colors.sh` for shared terminal color helpers and `benchmarks/docker_helpers.sh` for shared Docker benchmark utilities.
- **ckms**: Renamed TLS-related CLI parameters and environment variables from `ssl_xxx` to `tls_xxx` (e.g. `--ssl-client-pkcs12-path` → `--tls-client-pkcs12-path`, `KMS_SSL_CLIENT_PKCS12_PATH` → `KMS_TLS_CLIENT_PKCS12_PATH`).
Update any scripts or config files that reference the old `ssl_` prefix.

### ⚙️ Build

- *(deps)* Bump sigstore/cosign-installer from 4.1.0 to 4.1.1 (#832)
- *(deps)* Bump picomatch (#831)
- *(deps)* Bump brace-expansion (#833)
- *(deps)* Bump brace-expansion (#836)
- *(deps)* Bump crazy-max/ghaction-dump-context from 2 to 3 (#865)
- *(deps)* Bump actions/checkout from 4 to 6 (#872)
- *(deps)* Bump actions/upload-artifact from 4 to 7 (#873)

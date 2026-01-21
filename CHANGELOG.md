# Changelog

All notable changes to this project will be documented in this file.

## [5.15.0] - 2026-01-21

### 🚀 Features

- Upgrade OpenSSL to 3.6.0 but keep 3.1.2 for FIPS crypto provider [#667](https://github.com/Cosmian/kms/pull/667)
    - Summary of changes:

      | OpenSSL Linkage | FIPS | Non‑FIPS |
      | --- | --- | --- |
      | Static | Linkage: OpenSSL 3.6.0; runtime loads FIPS provider from OpenSSL 3.1.2 | Linkage: OpenSSL 3.6.0; runtime uses default/legacy providers |
      | Dynamic | Linkage: OpenSSL 3.1.2; ships FIPS configs and provider OpenSSL 3.1.2 | Linkage: OpenSSL 3.6.0; ships `libssl`/`libcrypto` and providers |

- Provide /health endpoint [#690](https://github.com/Cosmian/kms/pull/690)
- Add k256 (RFC6979) curve for sign/verify for non-fips builds [#671](https://github.com/Cosmian/kms/pull/671)
- Download CLI through UI [#678](https://github.com/Cosmian/kms/pull/678)
- Support RFC 3394 (AESKeyWrap with **no** padding) [#658](https://github.com/Cosmian/kms/pull/658)

  **⚠️ WARNING about AES Key Wrap changes**

  Any previously **manually** exported keys in **JSON** format must be manually updated if they have been previously wrapped with AES. This can be done using the following command:

  ```bash
  sed -i 's/NISTKeyWrap/AESKeyWrapPadding/g' your_exported_key.json
  ```

### 🐛 Bug Fixes

- Remove RUSTSEC-2023-0071 about `rsa` dependency and handle database without sqlx [#646](https://github.com/Cosmian/kms/pull/646).
    - Summary of changes:
        - `openidconnect` is removed in favor of manual OIDC implementation
        - `jwt-simple` is replaced by `jsonwebtoken`
        - old crate`cloudproof_findex` (->crypto_core->rsa) has been removed
        - `sqlx` has been replaced by those crates:
            - tokio-postgres
            - deadpool-postgres
            - mysql_async
            - tokio-rusqlite
            - rusqlite
- Fix Docker container issues [#692](https://github.com/Cosmian/kms/issues/692) and [#670](https://github.com/Cosmian/kms/issues/670) thanks to [#667](https://github.com/Cosmian/kms/pull/667)
- Upgrade lru and downgrade yank flat2 to 1.1.5 [#680](https://github.com/Cosmian/kms/pull/680)
- Fix double hash in RSASSAPSS in raw and digest data mode for sign/verify [#677](https://github.com/Cosmian/kms/pull/677)
- RSA signature/verify tests only run on non-fips [#684](https://github.com/Cosmian/kms/pull/684)
- Derive session cookie encryption key from public URL and user-provided salt for load-balanced deployments [#664](https://github.com/Cosmian/kms/pull/664)

### 📚 Documentation

- Add MySQL integration doc [#647](https://github.com/Cosmian/kms/pull/647)
- Update Percona integration doc [#665](https://github.com/Cosmian/kms/pull/665)
- Add AWS ECS Fargate doc [#686](https://github.com/Cosmian/kms/pull/686)

### ⚙️ Build

- *(deps)* Bump react-router from 7.5.3 to 7.12.0 in /ui in the npm_and_yarn group across 1 directory [#673](https://github.com/Cosmian/kms/pull/673)

### ⚙️ Miscellaneous Tasks

- Filter test_all workflow for dependabot branches [#674](https://github.com/Cosmian/kms/pull/674)
- Test packaging on dependabot branch but wo GPG [#675](https://github.com/Cosmian/kms/pull/675)
- Re-enable packaging workflow [#676](https://github.com/Cosmian/kms/pull/676)

## [5.14.1] - 2025-12-26

### 🚀 Features

- Add IDP multiple audiences configuration on [idp_auth] [#656](https://github.com/Cosmian/kms/pull/656). Dehardcode `kacls-migration` audience for Google CSE migration and allow alternative audiences (e.g. for Google Decrypter use)

### ⚠️ WARNING

**Server TOML configuration - kms.toml:** The deprecated [auth] section has been fully removed in favor of [idp_auth]. Usage is:

```toml
...
[idp_auth]
jwt_auth_provider = [
  "https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience,another_client_id",
  "https://auth0.example.com,,my-app",
  "https://keycloak.example.com/auth/realms/myrealm,,audience_1,audience_2"
]
...
```

### 📚 Documentation

- Publish SBOM and vulnerability reports ([#648](https://github.com/Cosmian/kms/pull/648))
- Improve readme ([#645](https://github.com/Cosmian/kms/pull/645))

### 🐛 Bug Fixes

- Sign and verify for raw and digest data - rfc6979 ([#654](https://github.com/Cosmian/kms/pull/654))
- Allow explicitly AGPL-3.0-or-later license

### ⚙️ Miscellaneous Tasks

- Make Github release sequential - fix cargo publish ([#642](https://github.com/Cosmian/kms/pull/642))

## [5.14.0] - 2025-12-15

### 🚀 Features

- Sign and SignatureVerify support across CLI, and UI ([#522](https://github.com/Cosmian/kms/issues/522), [#606](https://github.com/Cosmian/kms/pull/606)):
    - CLI: Added `sign` and `signature_verify` subcommands for RSA and Elliptic Curves (`crate/cli/src/actions/kms/.../sign.rs`, `.../signature_verify.rs`).
    - UI: Added React pages for RSA and EC signing and verification (`ui/src/RsaSign.tsx`, `ui/src/RsaVerify.tsx`, `ui/src/ECSign.tsx`, `ui/src/ECVerify.tsx`), and surfaced object type in Locate.
- Make DB pool max_connections configurable ([#632](https://github.com/Cosmian/kms/pull/632))
- Support sign and verify on CLI/UI + issue 619 ([#606](https://github.com/Cosmian/kms/pull/606))

### 🚜 Refactor

- Server: Consolidate KMIP operations `Sign` and `SignatureVerify` for RSA and Elliptic Curves (`crate/server/src/core/operations/sign.rs`, `signature_verify.rs`; routes updated). Supported signature schemes: RSASSA-PSS, ECDSA, EdDSA (Ed25519, Ed448).
- Digest (pre-hashed) mode for signing and verification ([#619](https://github.com/Cosmian/kms/issues/619)):
    - Introduced `digested=true` handling so inputs are treated as final digests (no implicit hashing) across RSA and EC paths (crypto + server).
    - RSA: Added verify support using pre-hashed input, including PKCS#1 v1.5 and RSASSA-PSS flows (`crate/crypto/src/crypto/rsa/verify.rs`).
    - EC: Added verify support using pre-hashed input (`crate/crypto/src/crypto/elliptic_curves/verify.rs`).
- Non-FIPS EC deterministic behavior (RFC 6979-like) via RustCrypto P256 implementation in non-FIPS builds.
- RSASSA-PSS: Server respects `salt_len` when specified (including `0`) during `Sign`.

### 🧪 Testing

- Added CLI and crypto tests for sign/verify flows, including digested mode

### 🐛 Bug Fixes

- MySQL schema missing PRIMARY KEY ([#628](https://github.com/Cosmian/kms/pull/628))
- On JWT auth, token was not properly forwarded in requests ([#629](https://github.com/Cosmian/kms/pull/629))
- Support COSMIAN_KMS_CONF env. variable in docker ([#630](https://github.com/Cosmian/kms/pull/630))
- Support AWS ECS Fargate ([#634](https://github.com/Cosmian/kms/pull/634))
- ObjectType Attribute problem ([#588](https://github.com/Cosmian/kms/pull/588))
- *(UI)* Remove in home page the incorrect HSM comment ([#639](https://github.com/Cosmian/kms/pull/639))
- Support mysql TDE while fixing the KMIP 1.x TTLV deserializer ([#631](https://github.com/Cosmian/kms/pull/631))
- Cli needs snake case ([#640](https://github.com/Cosmian/kms/pull/640))

### 📚 Documentation

- Rename .github/README.md
- Update installation instructions ([#635](https://github.com/Cosmian/kms/pull/635))

### ⚙️ Build

- *(deps)* Bump sigstore/cosign-installer from 3.7.0 to 4.0.0 ([#624](https://github.com/Cosmian/kms/pull/624))
- *(deps)* Bump crazy-max/ghaction-dump-context from 1 to 2 ([#625](https://github.com/Cosmian/kms/pull/625))
- *(deps)* Bump actions/setup-node from 4 to 6 ([#626](https://github.com/Cosmian/kms/pull/626))
- *(deps)* Bump actions/download-artifact from 4 to 6 ([#627](https://github.com/Cosmian/kms/pull/627))
- *(deps)* Bump actions/download-artifact from 6 to 7 ([#637](https://github.com/Cosmian/kms/pull/637))
- *(deps)* Bump actions/upload-artifact from 5 to 6 ([#638](https://github.com/Cosmian/kms/pull/638))

### ⚙️ Miscellaneous Tasks

- Rearrange releases ([#636](https://github.com/Cosmian/kms/pull/636))

## [5.13.0] - 2025-12-07

### 🚀 Features

- KMIP XML Vector Conformance (1.4 & 2.1) ([see details](#-kmip-xml-vector-conformance-14--21)) ([#583](https://github.com/Cosmian/kms/pull/583))
- Nix: Reproducible Package Management ([see details](#-nix-reproducible-package-management)) ([#596](https://github.com/Cosmian/kms/pull/596)):
- Create OpenTelemetryConfig to be consumed for server metrics ([#610](https://github.com/Cosmian/kms/pull/610))

### 🐛 Bug Fixes

- Better sql for the Find query ([#618](https://github.com/Cosmian/kms/pull/618))
- HSM unwrapping without permission ([#621](https://github.com/Cosmian/kms/pull/621))

### 📚 Documentation

- Fix UI README.md ([#611](https://github.com/Cosmian/kms/pull/611))
- Add vsphere minimal version ([#612](https://github.com/Cosmian/kms/pull/612))

### 🧪 Testing

- Support official KMIP test vectors 1.4/2.1 ([#583](https://github.com/Cosmian/kms/pull/583))

### ⚙️ Build

- Reproducible Package Management with Nix ([#596](https://github.com/Cosmian/kms/pull/596))
- *(deps)* Bump docker/metadata-action from 4 to 5 ([#613](https://github.com/Cosmian/kms/vpull/613))
- *(deps)* Bump actions/checkout from 4 to 6 ([#614](https://github.com/Cosmian/kms/pull/614))
- *(deps)* Bump crazy-max/ghaction-import-gpg from 5 to 6 ([#615](https://github.com/Cosmian/kms/pull/615))
- *(deps)* Bump actions/upload-artifact from 4 to 5 ([#616](https://github.com/Cosmian/kms/pull/616))
- *(deps)* Bump softprops/action-gh-release from 1 to 2 ([#617](https://github.com/Cosmian/kms/pull/617))

### ✅ KMIP XML Vector Conformance (1.4 & 2.1)

- End-to-end alignment with the official KMIP XML test vectors across library, server routing, and CLI: Create, Query/DiscoverVersions, attribute flows, and OpaqueObject revoke/destroy are covered.

#### 🚀 Features

- KMIP crate
    - Operations/types/messages:
        - Expanded Operation enum and message wiring to include: Interop, PKCS11, Check, RNG Retrieve, RNG Seed, GetAttributeList, MACVerify, ModifyAttribute, Log, plus responses.
        - Request/Response batch items are Clone with structured Display for clearer diagnostics.
        - Added Vendor OpaqueDataType; Display impls for CryptographicDomainParameters, ProtectionStorageMasks, StorageStatusMask.
    - TTLV improvements:
        - Deserializer coercions: Integer/Interval→i64, Enumeration/LongInteger→u8; ByteString→hex for ShortUniqueIdentifier.
        - Relaxed Attribute decoding supporting VendorAttribute and AttributeName+Value forms.
        - deserialize_ignored_any no-op to avoid loops in permissive paths.
    - Protocol alignment:
        - DiscoverVersions now uses KMIP 0.x types (protocol_version_major/minor) per spec; Query advertises operations/objects supported.
    - XML support:
        - Added XML serializer/deserializer and parser with tests for 1.4 and 2.1 XML vectors.

- server
    - New KMIP operations exposed and routed: DiscoverVersions, Query, RNG Retrieve, RNG Seed, MACVerify, GetAttributeList, ModifyAttribute, Check.
    - OpaqueObject Revoke/Destroy parity with vectors; deterministic ordering for GetAttributeList.
    - RNG implementation module (ANSI X9.31) with public routing.
    - Optional cascade mechanism for Destroy and Revoke.

- CLI
    - New subcommands: rng (Retrieve/Seed), mac verify, discover-versions, query.
    - New opaque-object subcommands: Create/Import/Export/Revoke/Destroy (no wrap/unwrap).

- kms_client
    - REST client methods added for RNG Retrieve/Seed, MACVerify, Query, DiscoverVersions, Check, GetAttributeList, attribute ops, register, and crypto ops.

- server_database
    - Deterministic GetAttributeList behavior across backends; Locate query refinements; backend adapters updated (MySQL, PostgreSQL, SQLite, Redis-Findex).

- crypto
    - Robustness and consistency improvements to RSA OAEP and wrap/unwrap paths used by KMIP flows.

- interfaces / hsm / access / client_utils
    - Minor interface refinements and HSM integration stability improvements supporting the new routes and attribute flows.

#### 🐛 Bug Fixes

- Export OpaqueObject Raw/Base64 returns opaque bytes (no KeyBlock).
- DiscoverVersions type/field mismatches fixed by switching to KMIP 0.x (major/minor).
- TTLV deserializer: better errors and coercions (u8 from Enumeration/LongInteger; i64 widening from Integer/Interval; vendor Attribute decoding) for XML vector compatibility.
- GetAttributeList: unified, deterministic ordering across environments.

#### 🧪 Testing

- Extensive XML vector tests for 1.4 and 2.1 in the kmip crate (mandatory/optional suites, crypto coverage).
- Added CLI tests: OpaqueObject CRUD (create/import, export json/base64/raw, revoke, destroy), RNG Retrieve/Seed, MAC Verify, Query, and DiscoverVersions.
- Server TTLV tests expanded (e.g., DSA creation/get flows) and vector integrations.

#### 📚 Documentation / Tooling

- Added KMIP specification scaffolding READMEs and a script to generate XML-based support tables.
- Build scripts adjusted for the new test coverage and flows.

### ✅ Nix: Reproducible Package Management

#### 🚀 Features

- **Reproducible builds with Nix**:
    - Full migration to Nix package manager for deterministic, bit-for-bit reproducible builds
    - Automated hash verification system ensuring build artifact integrity across platforms
    - Support for offline/air-gapped builds with complete dependency caching
    - Unified build system replacing platform-specific scripts (`.sh`, `.ps1`)
    - Comprehensive build variants: FIPS/non-FIPS × static/dynamic × vendor/non-vendor
    - Native support for cross-platform builds (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows)

- **Build infrastructure improvements**:
    - New `nix/` directory with reproducible derivations for KMS server, OpenSSL 3.1.2, UI, and Docker images
    - Automated hash tracking system with 400+ expected hashes for all build artifacts and dependencies
    - Deterministic OpenSSL 3.1.2 builds (both FIPS and non-FIPS variants) with static linking support
    - Docker images built entirely through Nix for consistency
    - Package signing infrastructure for Debian (.deb) and RPM packages
    - SBOM (Software Bill of Materials) generation integrated into build process

- **Testing & CI enhancements**:
    - Refactored GitHub workflows with comprehensive reusable components
    - New test suites: `test_all.sh`, `smoke_test_deb.sh`, `smoke_test_rpm.sh`, `smoke_test_dmg.sh`
    - Database-specific test scripts for MySQL, PostgreSQL, Redis, and SQLite backends
    - HSM integration tests for Utimaco, Proteccio, SoftHSM2, and Crypt2pay
    - Google CSE endpoint testing with HSM integration
    - Systemd service file validation tests
    - Docker image smoke tests with health checks

#### 🚜 Refactor

- **CI/CD pipeline reorganization**:
    - New reusable workflow structure: `main.yml` → `main_base.yml`/`packaging.yml`
    - Separated authentication tests by FIPS/non-FIPS variants
    - Modularized test execution with dedicated scripts per component
    - Common utilities consolidated in `.github/scripts/common.sh`

#### 📚 Documentation

- Comprehensive Nix build system documentation with visual diagrams:
    - Build architecture and reproducibility guarantees
    - Hash verification flow and offline build processes
    - Package signing setup and verification procedures
    - Troubleshooting guides and learning resources
- GitHub workflows documentation with complete execution flow diagrams
- Updated Copilot instructions for Nix-based development
- Build and test guide in `.github/copilot-instructions.md`

## [5.12.1] - 2025-11-28

### 🐛 Bug Fixes

- Avoid negative certificate serial number ([#609](https://github.com/Cosmian/kms/pull/609))

### 💼 Other

- Remove useless css in autogenerated doc

### ⚙️ Build

- *(deps)* Bump actions/checkout from 5 to 6 ([#604](https://github.com/Cosmian/kms/pull/604))

## [5.12.0] - 2025-11-19

### 🚀 Features

- Azure byok UI ([#597](https://github.com/Cosmian/kms/pull/597))
- Upgrade Findex from v5 to v8 ([#542](https://github.com/Cosmian/kms/pull/542))
    - *(redis)*: Created a new data storage schema for Redis, using a double-index instead of the "next Keyword".
    - *(redis)*: Developed a migration algorithm to update data under KMSes prior to 5.12.x.
    - *(redis)*: Introduction of strong typing for UserId and ObjectUid to reduce string manipulation errors, and created new types inspired from legacy cloudproof components.
    - Used new crypto core serializations for storage (when applicable)

### 🐛 Bug Fixes

- Automatic key unwrapping depending on ObjectType ([#600](https://github.com/Cosmian/kms/pull/600)):
    - Automatically unwrap keys (that are wrapped) when retrieving keys from database. It can be useful when server is configured with a Key Encryption Key that wraps all new keys. The unwrapped keys stay temporarily in expiring cache.
    - This feature is combined to the parameter default_unwrap_type that filters the ObjectType to unwrap.
    - Possible filters in server configuration are: All, Certificate, CertificateRequest, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey

### 📚 Documentation

- Rework all the databases migration and represent more easy to read schemas ([#542](https://github.com/Cosmian/kms/pull/542))
- Document migration flows
- Update KMS configuration TOML file with parameter `default_unwrap_type`.

### ⚙️ Build

- *(deps-dev)*: bump js-yaml from 4.1.0 to 4.1.1 in /ui in the npm_and_yarn group across 1 directory

### 🧪 Testing

- *(redis)*: Add two integration tests that migrate from version 5.1.0 and 5.2.0 to ([#542](https://github.com/Cosmian/kms/pull/542))

### ⚙️ Miscellaneous Tasks

- Refactored migration traits between the SQL databases and the Redis one (while possible)
- Deleted a lot of dead code
- Marked the Label parameter as deprecated.
- Updated the `aes_gcm_siv_not_openssl` functions to avoid using deprecated dependencies.

### ⚠️ WARNING

**Redis users:** Starting version 5.12.0,  the KMS will start operating with a new version of Findex (the SSE used with the Redis DB), and a  data migration is necessary :

**🚨 IMPORTANT: Back up your Redis database before upgrading to version 5.12.0.** 🚨

- If you're upgrading from a version prior to 5.0.0 : Please export your keys using standard formats (PKCS#8, PEM, etc.) and re-import them after clearing the redis store. Databases created with version 4.x.x are not compatible with the automated migration routine and won't start if the `db_version` key is unset.
- If you're upgrading from a 5.x DB : A transparent migration process will occur and should typically take less than a minute.

## [5.11.2] - 2025-11-12

### 🐛 Bug Fixes ([#598](https://github.com/Cosmian/kms/pull/598))

- Fix key wrapping where `wrapping-key` is itself wrapped: unwrap it and then use it
- Add an automatic key unwrapping for google_cse key at server startup
- Create a `OnceCell` HSM instance when multiple KMS servers are use - avoiding potential startup error
- Improved handling of wrapped keys, attribute propagation, and TLS cipher suite configuration

### 🧪 Testing ([#598](https://github.com/Cosmian/kms/pull/598))

- Add CLI-tests on Google CSE endpoints (/wrap, /privatekeydecrypt, etc.) and on Google key pair creation - all with the google_cse key wrapped by HSM

### 📚 Documentation ([#598](https://github.com/Cosmian/kms/pull/598))

- Example of configuration file: replace deprecated [auth] section with [idp_auth]

## [5.11.1] - 2025-11-04

### 📚 Documentation

- Rework KMIP support documentation ([#595](https://github.com/Cosmian/kms/pull/595))
- Remove double entry on KMIP Support

### 🧪 Testing

- *(windows)*: Enable test on whole workspace([#593](https://github.com/Cosmian/kms/pull/593))

## [5.11.0] - 2025-10-28

### 🚀 Features

- Add Crypt2pay HSM integration with a dedicated loader crate
- Generic "other" HSM support using Softhsm2 compatibility
- Enable empty (null) password/pin HSM login via special handling in slot management
- Add Windows/macOS installers with cargo packager tool ([#585](https://github.com/Cosmian/kms/pull/585))

### 🐛 Bug Fixes

- *(google_cse)* Load RSA private as PKCS8 or PKCS1 format ([#592](https://github.com/Cosmian/kms/pull/592))

### ⚠️ WARNING

**Gmail CSE users:** Versions 5.8/5.9 and 5.10 contain a blocking issue with Gmail Client-Side Encryption support (issue loading PKCS#8 RSA private key). Please upgrade to version 5.11.0 or later to ensure proper Gmail CSE functionality.

### 📚 Documentation

- Add KMIP current support ([#581](https://github.com/Cosmian/kms/pull/581))

### Build

- *(deps)* Bump esbuild ([#587](https://github.com/Cosmian/kms/pull/587))

## [5.10.0] - 2025-10-21

### 🚀 Features

- Add HSM key search with basic filters ([#552](https://github.com/Cosmian/kms/pull/552))
- Support wrapping SecretData object in export ([#551](https://github.com/Cosmian/kms/pull/551))
- Support DeriveKey KMIP operation ([#554](https://github.com/Cosmian/kms/pull/554))
- Add option to enable automatic unwrapping for Get and Export requests ([#579](https://github.com/Cosmian/kms/pull/579))

### 🐛 Bug Fixes

- Enable workspace clippy lints for all crates ([#553](https://github.com/Cosmian/kms/pull/553))
- Release HSM tests ([#567](https://github.com/Cosmian/kms/pull/567))
- Keep error info on DBerror ([#516](https://github.com/Cosmian/kms/pull/516))
- React CVE deps ([#566](https://github.com/Cosmian/kms/pull/566))
- Remove min_specialization feature ([#569](https://github.com/Cosmian/kms/pull/569))
- HSM key search fails after encountering incompatible key ([#574](https://github.com/Cosmian/kms/pull/574))
- *(windows)* Socket server listen on localhost instead of 0.0.0.0 ([#575](https://github.com/Cosmian/kms/pull/575))

### 📚 Documentation

- Add SmartCard HSM to README.md ([#563](https://github.com/Cosmian/kms/pull/563))
- Added documentation for Smart card HSM and SoftHSM2 ([#570](https://github.com/Cosmian/kms/pull/570))
- Add server configs examples ([#568](https://github.com/Cosmian/kms/pull/568))

### 🧪 Testing

- Filter tests with credentials and prerequisites ([#571](https://github.com/Cosmian/kms/pull/571))
- Enable Google CSE on workspace

### ⚙️ Miscellaneous Tasks

- Add CLA Assistant GitHub Action configuration
- Create CLA.md and CONTRIBUTING.md
- About forks, skip Google CSE tests and docker build
- About dependabot branches, skip Google CSE tests and docker build ([#559](https://github.com/Cosmian/kms/pull/559))
- Move CLA assistant workflow to correct path
- Skip public doc rebuild on forks and dependabot branches
- Skip CLA assistant on dependabot branches
- Integrate CLA signature in main_base.yml workflow - 2
- Trigger on issue comment
- Use an unprotected branch for CLA signing
- Remove trigger on pull_request_target
- Upgrade toolchain to nightly 2025-09-15 ([#564](https://github.com/Cosmian/kms/pull/564))

### Build

- *(deps)* Bump actions/checkout from 4 to 5
- *(deps)* Bump the npm_and_yarn group across 1 directory with 4 updates

## [5.9.0] - 2025-09-15

### 🚀 Features

- Add Smart card HSM support and bug fixes ([#538](https://github.com/Cosmian/kms/pull/538))
- CLI features:
    - added support for SHA1 in RSA key wrapping ([#541](https://github.com/Cosmian/kms/pull/541))
    - add Azure functionality to facilitate BYOK ([#541](https://github.com/Cosmian/kms/pull/541))
    - `attributes get` added support to retrieve Object tags only ([#541](https://github.com/Cosmian/kms/pull/541))
- *tracing*: print function names while using tracing macros. Use cosmian_logger instead of tracing crate ([#536](https://github.com/Cosmian/kms/pull/536))

### 🐛 Bug Fixes

- When wrapped with `No Encoding`, the RSA private key bytes and EC private key bytes are now the PKCS#8 DER bytes ([#541](https://github.com/Cosmian/kms/pull/541))
- CLI: fixed broken `attributes get` ([#541](https://github.com/Cosmian/kms/pull/541))

### 📚 Documentation

- Added Google CSEK and Google CMEK documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Added Azure BYOK documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Re-organized documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Fixing typo in Encrypt/Decrypt requests examples ([#545](https://github.com/Cosmian/kms/pull/545))

### 🧪 Testing

- Enable softhsm2 tests ([#539](https://github.com/Cosmian/kms/pull/539))
- Fix python installation on pykmip-tests GH workflow
- Fix race condition on test_privileged_users
- Add auth test with expired cert ([#547](https://github.com/Cosmian/kms/pull/547))

## [5.8.1] - 2025-09-05

### 🐛 Bug Fixes

- Server crate publish ([#534](https://github.com/Cosmian/kms/pull/534))

## [5.8.0] - 2025-09-05

### 🚀 Features

- Add KMIP operations `Sign` and `VerifySignature` for digital signature support ([#511](https://github.com/Cosmian/kms/pull/511))
- Add TLS cipher suites selection ([#524](https://github.com/Cosmian/kms/pull/524))

### 🐛 Bug Fixes

- *(google_cse)* Further restrict access to CSE privileged unwrap endpoint ([#517](https://github.com/Cosmian/kms/pull/517))
- Fix potential race condition in Google CSE migration key pair creation when multiple servers start simultaneously ([#519](https://github.com/Cosmian/kms/pull/519))
- Simplify clap JWT Auth configuration ([#531](https://github.com/Cosmian/kms/pull/531))
- Add non-fips UI build ([#532](https://github.com/Cosmian/kms/pull/532))
- Fix Credential parsing in KMIP Request Message ([#529](https://github.com/Cosmian/kms/pull/529))
- Use crypto core for db crypto ([#526](https://github.com/Cosmian/kms/pull/526))
- Cloudproof reexports ([#528](https://github.com/Cosmian/kms/pull/528))

### 📚 Documentation

- *(percona)* Add correction to percona doc ([#521](https://github.com/Cosmian/kms/pull/521))
- *(hsm)* Added KMS-HSM integration workflow graph ([#523](https://github.com/Cosmian/kms/pull/523))
- Fixes CLI Key Wrapping documentation on export ([#530](https://github.com/Cosmian/kms/pull/530))
- Clarify Gmail CSE CA authority usage ([#533](https://github.com/Cosmian/kms/pull/533))

### ⚙️ Miscellaneous Tasks

- Uniformize clippy lints on all crates ([#525](https://github.com/Cosmian/kms/pull/525))
- Create SECURITY.md with vulnerability tracking and reporting guidelines ([#527](https://github.com/Cosmian/kms/pull/527))

## [5.7.1] - 2025-08-22

### 🚀 Features

- Add support HTTP forward proxy (for intermediate CLI crate) ([#509](https://github.com/Cosmian/kms/pull/509))

### 📚 Documentation

- PKCS11: move PKCS#11 docs into cli repository ([#510](https://github.com/Cosmian/kms/pull/510))

### ⚙️ Miscellaneous Tasks

- Google CSE: save openssl commands to verify resource hash computation

## [5.7.0] - 2025-08-20

### 🚀 Features

- In JWT auth, change `audience` type from `String` to `Vec<String>`  ([#491](https://github.com/Cosmian/kms/pull/491))
- Support AES-CBC encryption without padding for Oracle TDE support ([#493](https://github.com/Cosmian/kms/pull/493))
- Add support for existing PKCS12 leaf certificates when creating Google CSE keypairs ([#505](https://github.com/Cosmian/kms/pull/505))
- Support debian 10 for old glibc compatibility (required for Oracle TDE) ([#508](https://github.com/Cosmian/kms/pull/508))
- Add GitHub Copilot instructions for KMS development workflow ([#504](https://github.com/Cosmian/kms/pull/504))

### 🐛 Bug Fixes

- Test docker container once generated by ci ([#481](https://github.com/Cosmian/kms/pull/481))

### ⚙️ Miscellaneous Tasks

- Use machete and publish crates on tags ([#499](https://github.com/Cosmian/kms/pull/499))
- Remove test data folder ([#497](https://github.com/Cosmian/kms/pull/497))
- Reorder crates in Cargo.toml
- Fix docker image name in tests ([#500](https://github.com/Cosmian/kms/pull/500))
- Automate CVE resolution (when possible) by mirroring deny.toml in .cargo/audit.toml

## [5.6.2] - 2025-07-29

### 🐛 Bug Fixes

- Remove useless and old UI files ([#487](https://github.com/Cosmian/kms/pull/487))
- Test_kms_server must remain dev-dependency ([#486](https://github.com/Cosmian/kms/pull/486))
- Enable native TLS support for OpenID Connect authentication ([#489](https://github.com/Cosmian/kms/pull/489))

## [5.6.1] - 2025-07-25

### 🚀 Features

- Display CSE information from UI ([#478](https://github.com/Cosmian/kms/pull/478))

### 🐛 Bug Fixes

- Fix outdated UI pkg
- Rocky package must be NON-FIPS ([#482](https://github.com/Cosmian/kms/pull/482))

### 📚 Documentation

- Add MongoDB documentation ([#483](https://github.com/Cosmian/kms/pull/483))
- Improve User Interface documentation

## [5.6.0] - 2025-07-23

### 🐛 Bug Fixes

- Support for TLS 1.3 on the HTTPS port of the KMIP server ([#458](https://github.com/Cosmian/kms/pull/458))
- Fixed RevocationReasonCode in KMIP 1.x ([#460](https://github.com/Cosmian/kms/pull/460))

### 🚀 Features

- Better support of PyKMIP client ([#438](https://github.com/Cosmian/kms/pull/438))
- Support for Percona PostgreSQL TDE (Transparent Data Encryption) ([#464](https://github.com/Cosmian/kms/pull/464))
- Support for Secret Data ([#398](https://github.com/Cosmian/kms/pull/398))

## [5.5.1] - 2025-07-09

### 🐛 Bug Fixes

- Fixed an issue with Locate failing when an HSM is present
- Fixed missing attributes when the wrapped object is not in the cache ([#462](https://github.com/Cosmian/kms/pull/462))
- Added support for SoftHsmV2 ([#457](https://github.com/Cosmian/kms/pull/457))

## [5.5.0] - 2025-07-08

### 🚀 Features

- Implement Register KMIP Operation
- ANSI colors in stdout are now disabled by default but can be re-enabled using a configuration flag
- Handle extension file to define x509 setup extensions for Google CSE keypairs create command

### 🐛 Bug Fixes

- Fix the default path for the `kms.toml` file on Windows
- Full configuration `kms.toml` file for Linux packaged distributions
- Handle KMIP Dates as OffsetDateTime instead of i64

### ⚙️ Miscellaneous Tasks

- Display items ID on Google keypairs creation command

### 📚 Documentation

- Missing documentation on the rolling file appender in the server configuration file
- Update README.md to reflect that the KMS now builds in FIPS mode by default

### 🧪 Testing

- Test custom JWT used from Google CSE migration endpoints
- Test Import and Register KMIP operations

## [5.4.1] - 2025-06-25

### 🐛 Bug Fixes

- Fix error on Google CSE migration authentication

## [5.4.0] - 2025-06-24

### 🚀 Features

- Support for daily rolling log files to a specified directory

### 🐛 Bug Fixes

- Invert fips feature ([#448](https://github.com/Cosmian/kms/pull/448))
- Google CSE - Added support for all algorithms in private_key_decrypt
- Google CSE - Added support for all algorithms in private_key_sign

### ⚙️ Miscellaneous Tasks

- Align UI version with Cargo workspace

## [5.3.3] - 2025-06-12

### 🐛 Bug Fixes

- In UI, fix `IvCounterNonce` ([#446](https://github.com/Cosmian/kms/pull/446))
- *(Linux packages)* Save and restore conf during installation
- Interoperability fixes with PyKMIP

### 📚 Documentation

- Remove reference of cosmian_gui
- Markdown fixes

### ⚙️ Miscellaneous Tasks

- Rename cli repo
- *(windows)* Reduce verbosity

## [5.3.2] - 2025-06-04

### 🐛 Bug Fixes

- Support for MySQL 8.0.42 and higher ([#443](https://github.com/Cosmian/kms/pull/443))

## [5.3.1] - 2025-06-04

### 🐛 Bug Fixes

- Fix clap error on cse keypair command

## [5.3.0] - 2025-06-02

### 🚀 Features

- Support for outbound proxy to fetch the JWKS (JSON Web Key Set) ([#439](https://github.com/Cosmian/kms/pull/439))

## [5.2.0] - 2025-05-27

### 🚀 Features

- Support for JWKS (JSON Web Key Set) that provides JWK not appropriate for OIDC authentication ([#433](https://github.com/Cosmian/kms/pull/433))

## [5.1.1] - 2025-05-23

### 🐛 Bug Fixes

- Safer handling of Google CSE authorization token decoding ([#431](https://github.com/Cosmian/kms/pull/431))

## [5.1.0] - 2025-05-22

### 🚀 Features

- Support custom JWT authentication for external KACLS using an RSA keypair in the Google CSE migration flow
- Expose the RSA public key via the new `/certs` endpoint
- Rewrite `/rewrap` endpoint to fully support the migration flow logic
- Rewrite `/privilegedunwrap` endpoint to properly integrate with the migration process
- Support for PKCE (Proof Key for Code Exchange) authentication from the CLI with the Cosmian KMS
- Concurrent multi-factor authentication with clear cascading rules (OIDC / Client Certificates / API Token)

### 🐛 Bug Fixes

- Unclear cascading rules in multi-factor authentication

### 🚜 Refactor

- Refactor server configuration to include a dedicated google_cse section
- Derive the Google CSE KACLS URL from the public_url configuration value for better flexibility

### ⚙️ Miscellaneous Tasks

- Expose user_id in the response from the /token endpoint for improved UI identification

### 🧪 Testing

- Add unit tests for Google CSE digest computation, validating against Google's official documentation appendix
- Test custom JWT generation and parsing to ensure compatibility and correctness

### 📚 Documentation

- Revise the Google CSE documentation section for clarity and accuracy
- Add a new section on migrating Google CSE data from Drive, including practical steps and examples
- PKCE documentation with configuration examples
- Improved authentication documentation, both client and server side

## [5.0.0] - 2025-05-07

**WARNING**: This is a breaking change release.
Databases created with version 4.x.x are not compatible with version 5.0.0.
Please export your keys using standard formats (PKCS#8, PEM, etc.) and re-import them after upgrading.

### 🚀 Features

- Support for KMIP 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1 ([#412](https://github.com/Cosmian/kms/pull/412))
- Binary TTLV for all KMIP versions on port 5696
- JSON TTLV for all KMIP versions on port 9998, endpoint /kmip
- VMware support
- Possible automatic key wrapping on Create and Import
- Better telemetry using OTLP and logs to syslog
- Run KMS server with privileged users ([#408](https://github.com/Cosmian/kms/pull/408)):
    - These users can grant or revoke create access rights for other users
    - Without `Create` access right or privileged status, users can't create or import objects to KMS

### 🚜 Refactor

- Rationalize SQL implementation ([#379](https://github.com/Cosmian/kms/issues/379))
- Rust KeyBlock implementation not fully compliant with KMIP 2.1 specs ([#76](https://github.com/Cosmian/kms/issues/76))

### 🐛 Bug Fixes

- Multiple fixes in KMIP 2.1 TTLV formats

### ⚙️ Miscellaneous Tasks

- More extensive coverage of KMIP attributes
- Database schema changes

## [4.24.0] - 2025-04-23

### 🚀 Features

- Add support for Oracle Transparent Database Encryption (TDE) using Oracle Key
  Vault ([#396](https://github.com/Cosmian/kms/pull/396))

### ⚙️ Miscellaneous Tasks

- Add missing artifacts on tags ([#407](https://github.com/Cosmian/kms/pull/407))
- Missing folder assets in DEB/RPM ([#406](https://github.com/Cosmian/kms/pull/406))
- Align Docker build image to the wasm-pack prebuild binary for ARM cross-build

## [4.23.0] - 2025-04-10

### 🚀 Features

- Add digest and MAC KMIP operations ([#370](https://github.com/Cosmian/kms/pull/370))
- Upgrade Covercrypt to v15 ([#382](https://github.com/Cosmian/kms/pull/382))
- Add CBC encryption mode ([#395](https://github.com/Cosmian/kms/pull/395))
- Add UI ([#391](https://github.com/Cosmian/kms/pull/391))

### 🐛 Bug Fixes

- Shrink docker images size using slim-bullseye base image ([#377](https://github.com/Cosmian/kms/pull/377))
- Clean unneeded test files ([#392](https://github.com/Cosmian/kms/pull/392))
- RUSTSEC-2025-0009: `ring`: Some AES functions may panic when overflow checking is enabled.
- RUSTSEC-2025-0022: `openssl`: Use-After-Free in Md::fetch and Cipher::fetch

### 🚜 Refactor

- Move all CLI relative crates on <https://github.com/Cosmian/cli> ([#383](https://github.com/Cosmian/kms/pull/383))

### 📚 Documentation

- Fix Google expected X509 extensions

### 🧪 Testing

- Add HSM tests using Utimaco simulator ([#380](https://github.com/Cosmian/kms/pull/380))

### ⚙️ Miscellaneous Tasks

- Reuse generic Github workflows ([#401](https://github.com/Cosmian/kms/pull/401))

## [4.22.1] - 2025-02-04

### 🧪 CI

- Fix rhel9 artifact name

## [4.22.0] - 2025-02-03

### 🚀 Features

- Utimaco General Purpose HSMs support ([#367](https://github.com/Cosmian/kms/pull/367))

### 🐛 Bug Fixes

- Fixed HSM base code dangling pointer issue in `release` mode
- Fixed unwanted `ValueEnum` in `cosmian sym encrypt`
- Remove ckms linux packages in favor of cosmian packages ([#366](https://github.com/Cosmian/kms/pull/366))
- Rename binary `cosmian_kms_server` to `cosmian_kms` - reuse the same name as marketplace images

### 📚 Documentation

- Clarified installation documentation
- Improved database configuration
- Improved HSM integration documentation

## [4.21.2] - 2025-01-21

### 📚 Documentation

- Add how to release doc ([#361](https://github.com/Cosmian/kms/pull/361))
- Change default port of KMS package from 8080 to 9998 ([#364](https://github.com/Cosmian/kms/pull/364))
- VM marketplace guide examples ([#365](https://github.com/Cosmian/kms/pull/365))
- *(google_cse)* Update authentication section ([#363](https://github.com/Cosmian/kms/pull/363))

### 🧪 CI

- Allow continue on error ([#362](https://github.com/Cosmian/kms/pull/362))

## [4.21.1] - 2025-01-16

### 🚀 Features

- Loading server conf with default system conf. fallback ([#360](https://github.com/Cosmian/kms/pull/360))
- Update crate config_utils ([#358](https://github.com/Cosmian/kms/pull/358))

### 📚 Documentation

- *(google_cse)* Typos in configuring .well-known file ([#359](https://github.com/Cosmian/kms/pull/359))

### ⚙️ Miscellaneous Tasks

- Fix publish on package.cosmian.com

## [4.21.0] - 2025-01-07

### 🚀 Features

- Add server param to disable (if needed) Google CSE JWT token
  validation ([#349](https://github.com/Cosmian/kms/pull/349))
- Add remove option to `Destroy` + Object not found error message fix ([#357](https://github.com/Cosmian/kms/pull/357))

### 🐛 Bug Fixes

- Save configuration file outside of clap actions ([#351](https://github.com/Cosmian/kms/pull/351))
- Fix an incorrect message on 'object not found' ([#353](https://github.com/Cosmian/kms/issues/353))

### 📚 Documentation

- Fix bad links and mkdocs formatting
- Simple review ([#358](https://github.com/Cosmian/kms/pull/358)
- Explain default KMS configuration on CVM ([#359](https://github.com/Cosmian/kms/pull/359)
- Better build with mkdocs; faster Mermaid support and better Katex support

## [4.20.1] - 2024-12-09

### 🚀 Features

- Add CLI bench command ([#348](https://github.com/Cosmian/kms/pull/348))

### 🚜 Refactor

- Re-expose clap actions for other CLIs (cosmian, ckms_gui) ([#339](https://github.com/Cosmian/kms/pull/339))

### 📚 Documentation

- Revisit the mkdocs documentation ([#339](https://github.com/Cosmian/kms/pull/339))

## [4.20.0] - 2024-11-30

### 🚀 Features

- HSM support ([#344](https://github.com/Cosmian/kms/pull/344))
    - support for the Proteccio HSM that provides both
        - the ability to perform the Create, Destroy, Export, Encrypt, and Decrypt operations on the HSM
        - the ability to create keys in the KMS that are wrapped by a key in the HSM
    - the database components are now in a separate crate `server_database`. They are now split in 2 implementations:
      Objects store and Permissions store
    - a new `interfaces` crate gathers interfaces to be implemented by new external components. Interfaces include:
        - Object Store
        - Permissions Store
        - Encryption Oracle
    - key unique identifiers now support prefixes. Object Stores, Permissions stores, and Encryption Oracles can be
      registered against the prefixes.
    - support for the `Sensitive` Attribute in addition to the ability to wrap a key by another key has been added to
      all
      keys creations
- Make keys non revocable on server ([#341](https://github.com/Cosmian/kms/pull/341))
- Docker for Linux ARM and keep support for MacOS Intel ([#343](https://github.com/Cosmian/kms/pull/343))

### 🐛 Bug Fixes

- The macOS-12 environment is now deprecated
- Better permissions checking on wrapping and unwrapping

### 📚 Documentation

- Add benchmarks on simultaneous encryptions/decryptions

## [4.19.3] - 2024-10-29

### 🐛 Bug Fixes

- Maturin build on macos arm - force forward compatibility ([#336](https://github.com/Cosmian/kms/pull/336))

## [4.19.2] - 2024-10-29

### 🐛 Bug Fixes

- Launch encrypted GMeet through GCal ([#334](https://github.com/Cosmian/kms/pull/334))
- **MacOS-maturin**: Upgrade python version from 3.12 to 3.13 ([#333](https://github.com/Cosmian/kms/pull/333))
- Dont panic on indexing slicing ([#331](https://github.com/Cosmian/kms/pull/331))

### 📚 Documentation

- `ckms` installation - specifically for Windows ([#332](https://github.com/Cosmian/kms/pull/332))

## [4.19.1] - 2024-10-11

### 🚀 Features

- Client `ckms`: merge attributes handling (set/get/delete) under `attributes`
  subcommand ([#329](https://github.com/Cosmian/kms/pull/329))

### 🐛 Bug Fixes

- Guard on size of ciphertexts for BulkData ([#330](https://github.com/Cosmian/kms/pull/330))
- KMIP Attributes: fix deletion on Links and Vendor Attributes ([#329](https://github.com/Cosmian/kms/pull/329))

## [4.19.0] - 2024-10-09

### 🚀 Features

- Google Workspace Client-Side-Encryption (CSE)
  updates ([#319](https://github.com/Cosmian/kms/pull/319))
    - Generate Google S/MIME key-pairs and identities and upload them to Gmail API from ckms
      CLI ([#270](https://github.com/Cosmian/kms/issues/270))
    - Server-side, export cert at PKCS7 format
    - Implement missing CSE endpoints
    - Wrap/unwrap CSE elements with authenticated encryption
    - Export wrapped keys from KMS specifying the cipher mode
    - Handle auth for guest users ([#271](https://github.com/Cosmian/kms/issues/271))
- Add SetAttribute/DeleteAttribute KMIP operations ([#303](https://github.com/Cosmian/kms/pull/303))
- Re-enable wrap/unwrap on ckms by linking statically on openssl ([#317](https://github.com/Cosmian/kms/pull/317))
- Added AES GCM-SIV and AES XTS ([#328](https://github.com/Cosmian/kms/pull/328))
- Added the ability to client side encrypt files with `ckms` and a hybrid
  scheme ([#328](https://github.com/Cosmian/kms/pull/328))
- Create Symmetric Key / Private keys with custom unique id ([#326](https://github.com/Cosmian/kms/pull/326))
- Add bulk encrypt / decrypt facility ([#318](https://github.com/Cosmian/kms/pull/318))
- Replace Debug derive trait of KMIP Object by a custom Display impl ([#327](https://github.com/Cosmian/kms/pull/327))

### 📚 Documentation

- Documentation: Migrating emails to Gmail CSE ([#316](https://github.com/Cosmian/kms/pull/316))
- Update CSE documentation (Gmail S/MIME) ([#316](https://github.com/Cosmian/kms/pull/316))
- Update KMS build instructions ([#320](https://github.com/Cosmian/kms/pull/320))

### 🧪 Testing

- Add test on database backends ([#311](https://github.com/Cosmian/kms/pull/311))
- Reduce CI pipeline duration in debug ([#315](https://github.com/Cosmian/kms/pull/315))
- Add CSE endpoints testing ([#319](https://github.com/Cosmian/kms/pull/319))

### ⚙️ Miscellaneous Tasks

- Clippy hardening in crate `kmip` ([#304](https://github.com/Cosmian/kms/pull/304))

## [4.18.0] - 2024-09-17

### 🚀 Features

- Add ReKey KMIP operation ([#294](https://github.com/Cosmian/kms/pull/294))
- Add API token authentication between server and
  clients ([#290](https://github.com/Cosmian/kms/pull/290))
- Build a generic database upgrade mechanism ([#299](https://github.com/Cosmian/kms/pull/299))
- Export of certificates can now be performed using the certificate id (instead of just the private
  key id)
- More intuitive PKCS#12 import ([#306](https://github.com/Cosmian/kms/pull/306))
- Support for export under legacy PKCS#12 format ([#306](https://github.com/Cosmian/kms/pull/306))
- Documentation (S/MIME)

### 🐛 Bug Fixes

- KMIP Attributes:
    - In get_attributes, use attributes from ObjectWithMetadata instead of
      Object.Attributes ([#278](https://github.com/Cosmian/kms/pull/278))
    - When inserting in db, force Object::Attributes to be synced with
      Attributes ([#279](https://github.com/Cosmian/kms/pull/279))
- Certificates handling/tasks:
    - **Validate** KMIP operation:
        - Simplify getting CRLs and get returned
          errors ([#268](https://github.com/Cosmian/kms/pull/268))
        - Validate certificate generation ([#283](https://github.com/Cosmian/kms/pull/283))
        - Use certificate file path in ckms
          arguments ([#292](https://github.com/Cosmian/kms/pull/292))
    - **Certify** KMIP operation: Server must sign x509 after adding X509
      extensions ([#282](https://github.com/Cosmian/kms/pull/282))
- Merge decrypt match in same function ([#295](https://github.com/Cosmian/kms/pull/295))
- Fix Public RSA Key size in get attributes ([#275](https://github.com/Cosmian/kms/pull/275))
- RUSTSEC:
    - **RUSTSEC-2024-0357**: MemBio::get_buf has undefined behavior with empty buffers: upgrade
      crate `openssl` from 1.0.64 to 1.0.66 ([#280](https://github.com/Cosmian/kms/pull/280))
    - **RUSTSEC-2024-0363**: Binary Protocol Misinterpretation caused by Truncating or Overflowing
      Casts: bump sqlx to 0.8.1 ([#291](https://github.com/Cosmian/kms/pull/291)
      and [#297](https://github.com/Cosmian/kms/pull/297))
- CLI doc fixes (certificates certify)
- Fix PKCS#12 export of self-signed cert ([#305](https://github.com/Cosmian/kms/issues/305))
- Fix serialization of `Attributes` in
  `redis-findex`  ([#307](https://github.com/Cosmian/kms/pull/307))

### ⚙️ Miscellaneous Tasks

- **clippy** tasks:
    - Only expose pub functions that need to be
      public ([#277](https://github.com/Cosmian/kms/pull/277))
    - Hardcode clippy lints ([#293](https://github.com/Cosmian/kms/pull/293))
- Rename MacOS artifacts giving CPU architecture
- Configure `ckms` to build reqwest with minimal idle connections
  reuse ([#272](https://github.com/Cosmian/kms/pull/272))
- Do not delete tags if none are provided ([#276](https://github.com/Cosmian/kms/pull/276))
- De-activated Google CSE tests when tokens are not supplied through env. var.
- Cleaned-up and improved certificates import tests
- Made test DB backend selectable using env. var. `KMS_TEST_URL`

## [4.17.0] - 2024-07-05

### 🚀 Features

- Add KMIP operation `Validate` for certificates ([#247](https://github.com/Cosmian/kms/pull/247))
- Added RSA benchmarks ([#251](https://github.com/Cosmian/kms/pull/251))
- Add OpenTelemetry OTLP protocol support to KMS
  server ([#253](https://github.com/Cosmian/kms/pull/253))
- Support for multiple certification scenarios and
  self-signing ([#248](https://github.com/Cosmian/kms/pull/248))

### 🐛 Bug Fixes

- Fix vulnerability RUSTSEC-2024-0336 ([#244](https://github.com/Cosmian/kms/pull/244))
- Fix vulnerability RUSTSEC-2024-0344 ([#254](https://github.com/Cosmian/kms/pull/254))
  and ([#255](https://github.com/Cosmian/kms/pull/255))

### ⚙️ Miscellaneous Tasks

- Create Debian/RPM packages for Ubuntu 2x.04 and RHEL
  9 ([#264](https://github.com/Cosmian/kms/pull/264))
- Drop Centos 7 support ([#265](https://github.com/Cosmian/kms/pull/265))
- Replace `cargo audit` with `cargo deny` ([#245](https://github.com/Cosmian/kms/pull/245))
- Replace Linux cross-compiling for Windows with compiling on Windows Github
  runner ([#249](https://github.com/Cosmian/kms/pull/249))
- Add support for build on MacOS ARM

## [4.16.0] - 2024-05-06

### 🐛 Bug Fixes

- Fixed import of symmetric key tag to '_kk' from '_sk'

### 🚀 Features

- Add support for LUKS via PKCS#11 module
- Add support for CKM_RSA_PKCS (PKCS#1 v1.5) for RSA encryption/decryption

## [4.15.2] - 2024-05-03

### 🚀 Features

- Create Gmail key pairs and identities with `ckms` via Gmail
  API ([#243](https://github.com/Cosmian/kms/pull/243))

### 🐛 Bug Fixes

- Comment out mermaid configuration

## [4.15.1] - 2024-05-02

### 🚀 Features

- Add Google Workspace CSE endpoints for **encrypted Gmail
  ** ([#192](https://github.com/Cosmian/kms/pull/192))

### 🐛 Bug Fixes

- RUSTSEC-2024-0336 ([#244](https://github.com/Cosmian/kms/pull/244))
- Remove everything related to GCP images build ([#241](https://github.com/Cosmian/kms/pull/241))

### 📚 Documentation

- Oauth2 OIDC doc fixes

## [4.15.0] - 2024-04-08

### 🐛 Bug Fixes

- Add license to KMS GCP image ([#235](https://github.com/Cosmian/kms/pull/235))
- Re-enable the validation of JWT Issuer URI
- Fix CSE error status code, propagating the right status code instead of generic server code error

### 🚀 Features

- Handle many identity providers in jwt authentication
- New command line argument `--key-usage` to define key or certificate usage on import
- Exhaustive verification that the key used to perform cryptographic operations is allowed to do
  them
- KMIP object creation can now precisely define the usage of the key it describes

## [4.14.2] - 2024-04-05

### 🧪 CI

- Add standalone workflow to test KMS in Cosmian
  VM ([#233](https://github.com/Cosmian/kms/pull/233))

### 🚀 Features

- Rebase KMS GCP image on Cosmian VM 1.1.0-rc.4

## [4.14.1] - 2024-04-04

### 🧪 CI

- Remove optimization RUSTFLAGS ([#227](https://github.com/Cosmian/kms/pull/227))

### 🚀 Features

- Rebase KMS GCP image on Cosmian VM 1.1.0-rc.3

## [4.14.0] - 2024-03-27

### 🐛 Bug Fixes

- Fixed double quotes problem in cosmian vm test (CI)
- Fixed trailing null byte bug for biguint/bytes
  conversions ([#224](https://github.com/Cosmian/kms/pull/224))
- Make the CLI compile on Windows and macOS (without openssl
  installed) ([#209](https://github.com/Cosmian/kms/pull/209))

### 🚀 Features

- Support Veracrypt PKCS11 provider library ([#208](https://github.com/Cosmian/kms/pull/208))

### Testing

- Update `test_kms.py` to use covercrypt `14.0.0` ([#217](https://github.com/Cosmian/kms/pull/217))

## [4.13.5] - 2024-03-20

### 🐛 Bug Fixes

- Add missing image_licenses in packer for GCP ([#219](https://github.com/Cosmian/kms/pull/219))

## [4.13.4] - 2024-03-18

### 🧪 CI

- Push GCP images based on Cosmian VM 1.1.0-rc2

## [4.13.3] - 2024-03-11

### 🐛 Bug Fixes

- `ckms` needs `kmip` dependency with
  features `openssl` ([#202](https://github.com/Cosmian/kms/pull/202))

### 🧪 CI

- Push GCP images on cosmian-dev and cosmian-public only
  once ([#203](https://github.com/Cosmian/kms/pull/203))

## [4.13.2] - 2024-03-09

### 🧪 CI

- Filter reboot test on GCP/RHEL instance.

## [4.13.1] - 2024-03-08

### 🧪 CI

- Add build of GCP images (ubuntu/redhat) [#191](https://github.com/Cosmian/kms/pull/191).

## [4.13.0] - 2024-03-08

### 🚀 Features

- Save KMIP Attributes in a proper column of `Objects`
  table [#166](https://github.com/Cosmian/kms/pull/166):
    - Remove all custom tags `_cert_spki`, `_cert_cn`, `_cert_issuer` and `_cert_sk`
- Add support for CoverCrypt `rekey`, `prune`, and `Policy` editing
  methods [#179](https://github.com/Cosmian/kms/pull/179):
    - Add CLI commands to perform these actions
- Accurate CryptographicUsageMask for KMIP creation (RSA and EC
  keys) [#189](https://github.com/Cosmian/kms/pull/189)
  and [#187](https://github.com/Cosmian/kms/pull/187).

### Refactor

- Rework utils/crypto [#178](https://github.com/Cosmian/kms/pull/178).

### 🧪 CI

- Add build on RHEL9 [#196](https://github.com/Cosmian/kms/pull/196).
- Add build of GCP images (ubuntu/redhat) [#191](https://github.com/Cosmian/kms/pull/191).

### 🐛 Bug Fixes

- Fixing inconsistent crypto consts [#190](https://github.com/Cosmian/kms/pull/190).
- Fix interpolation in error macros [#184](https://github.com/Cosmian/kms/pull/184).
- Move internal KMIP Objects into `Box` to avoid stack memory
  overflow [#200](https://github.com/Cosmian/kms/pull/200).

## [4.12.0] - 2024-02-08

### 🚀 Features

- Generalize the refresh of JWKS in the middleware [#150](https://github.com/Cosmian/kms/pull/150).
- CI speed up [#173](https://github.com/Cosmian/kms/pull/173).
- Add support for Microsoft Double Key Encryption (DKE)
  endpoints [#170](https://github.com/Cosmian/kms/pull/170).
- Re-organized crypto package by algorithm, removed duplicated
  code [#170](https://github.com/Cosmian/kms/pull/170).
- Add support for FIPS mode for the ckms client [#170](https://github.com/Cosmian/kms/pull/170).
- Documented TOML configuration file for the KMS
  server [#170](https://github.com/Cosmian/kms/pull/170).
- Overall improvements to the documentation on algorithms and FIPS
  mode [#170](https://github.com/Cosmian/kms/pull/170).

## [4.11.3] - 2024-01-26

### 🚀 Features

- CLI: allow multiple operations to be supplied at once for access
  control [#155](https://github.com/Cosmian/kms/pull/155).

### ⚙️ Miscellaneous Tasks

- Business Source License 1.1

## [4.11.2] - 2024-01-23

### 🧪 CI

- Test and deliver in CI missing FIPS binary (fips.so and openssl.cnf for
  FIPS) [#152](https://github.com/Cosmian/kms/issues/153)

## [4.11.1] - 2024-01-18

### 🐛 Bug Fixes

- Load correct openssl provider on run

### 🧪 CI

- Pypi now requires a token to publish [#148](https://github.com/Cosmian/kms/issues/148)

## [4.11.0] - 2024-01-17

### 🐛 Bug Fixes

- Fix AES decryption: tag invalid size [#133](https://github.com/Cosmian/kms/issues/133)
- Remove bootstrap server leftovers [#142](https://github.com/Cosmian/kms/issues/142)

### 🚀 Features

- X509 v3 extensions support [#120](https://github.com/Cosmian/kms/issues/120)
- Dynamic salt for password derivation, resolving
  issue [#124](https://github.com/Cosmian/kms/issues/124) [#128](https://github.com/Cosmian/kms/issues/128)
- Support Cosmian VM [#129](https://github.com/Cosmian/kms/issues/129)
- Make rsa oaep aes a generalized encryption system for use in all kms and not only for key
  wrapping [#130](https://github.com/Cosmian/kms/issues/130)
- ECIES implementation for Hybrid Encryption [#134](https://github.com/Cosmian/kms/issues/134)
- Add pyo3 methods for
  symmetric `create_key`, `encrypt`, `decrypt` [#135](https://github.com/Cosmian/kms/issues/135)
- Add RSA keys create key pair [#137](https://github.com/Cosmian/kms/issues/137)
- Upgrade Rust toolchain to 2024-01-09 [#141](https://github.com/Cosmian/kms/issues/141)
- Support keypair generation for curve448 Montgomery and edwards
  forms [#143](https://github.com/Cosmian/kms/issues/143)

## [4.10.1] - 2023-12-12

### 📚 Documentation

- Fix mkdocs formatting

## [4.10.0] - 2023-12-11

### 🚀 Features

- Support for certificate generation using the Certify KMIP operation and a PKCS#10 or a public key
- Support for most standardized encoding formats on import.export: PKCS#8, PKCS#1, SEC1, X509,
  PKCS#12
- Improvements to the Locate functionality for attributes and tags
- Support for the Get Attributes KMIP operation
- Database: support for atomic operations
- Replaced part of Rust Crypto with openssl for more standardized module support
- Deactivated automatic certificate verification, which will be reallocated
  for the future `Validate` KMIP operation support [#102](https://github.com/Cosmian/kms/issues/102)
- Deactivated the non KMIP compliant certificate "quick create feature",
  which can now be achieved using the `Certify` KMIP
  operation [#103](https://github.com/Cosmian/kms/issues/103)

### 🐛 Bug Fixes

- Redis-Findex: `create` now checks for the pre-existence of the object
- Better KMIP compliance:
    - improved KeyBlock definition [#76](https://github.com/Cosmian/kms/issues/76)
    - enforced KMIP default export formats [#78](https://github.com/Cosmian/kms/issues/78)
    - aligned `Unique Identifier` to KMIP definition but only the `TextString` variant is supported.
    - Use od standards attributes instead of Vendor attributes wherever possible

## [4.9.1] - 2023-11-14

### 🐛 Bug Fixes

- KMIP server operations only support DER format for certificates ([#89](https://github.com/Cosmian/kms/pull/89))

## [4.9.0] - 2023-11-10

### 🐛 Bug Fixes

- fix: migrate to num-bigint-dig for bigint ([#85](https://github.com/Cosmian/kms/pull/85))

### 🧪 CI

- Test KMS inside an SGX machine

### 🚀 Features

- Update Covercrypt version to support Policy V2 ([#63])
- Generalize bulk operations using KMIP `Messages` structure

## [4.8.2] - 2023-10-31

### 🐛 Bug Fixes

- Save certs as DER instead of PEM for KMIP compliance

## [4.8.1] - 2023-10-12

### 🐛 Bug Fixes

- Fix for [#64](https://github.com/Cosmian/kms/issues/64)

## [4.8.0] - 2023-10-07

### 🐛 Bug Fixes

- Fix container build on tags
- Serialize the header for each chunk for Covercrypt bulk encryption ([#59](https://github.com/Cosmian/kms/pull/59))

### 🚀 Features

- KMS running inside TEE (SGX or SEV)
    - review the `verify` subcommand
    - force checking the leaf TLS certificate when querying a KMS running inside a TEE
    - verify RA-TLS certificate before querying the bootstrap server
    - review the TLS certificate generation using the key tied to the TEE
    - remove libsgx and create a new dependence to tee_attestation crate
    - update KMS server argument regarding the TEE and certbot
    - review documentation regarding the KMS usage inside a TEE
- Activate tracing in CLI tests when binary is instrumented ([#56])

### 🧪 CI

- Trigger public_documentation build on tags

## [4.7.0] - 2023-10-02

### 🚀 Features

- Added the wildcard user `*` to grant access rights to all users on an object
- About certificates:
    - add validation of the complete chain instead of the leaf and parent certificates
    - add verifications before using a certificate:
        - check that each certificate is not expired (both chain and leaf certificates)
        - check that no certificate is revoked (both chain and leaf certificates)
        - check that each certificate has a valid signature (both chain and leaf certificates)
        - check that certificate CRL signature is valid
    - add RSA X509 certificate support
    - add Covercrypt bulk encryption
- KMS CLI `ckms`:
    - can import the Mozilla Common CA Database (CCADB)
    - can import a PKCS12 certificate (splitting in 2 KMIP objects: X509 certificate and private
      key)

### 🐛 Bug Fixes

- Improved database data structures using Maps and Sets instead of Vectors where uniqueness is
  required
- Enable bootstrap server for non "enclaves" servers

## [4.6.0] - 2023-09-01

### 🐛 Bug Fixes

- Filter Locate request by object type

### 📚 Documentation

- Remove merge leftovers

### 🚀 Features

- bootstrap: the KMS server now supports bootstrap mode to facilitate the secure input of secret
  components, including the database encryption secret and the HTTPS certificate key, directly into
  the encrypted machine memory, through a secure connection
- Add certificate support:
    - in cosmian_kms_server:
        - implement `Certify` KMIP operation
        - in addition, the KMS server will automatically add:
            - the system tag `_cert` on `Certificate` object
            - the system tag `_cert_uid=<certificate_uid>` where `certificate_uid` is used as the
              link between public/private key objects and the related certificate object
            - the system tag `_cert_spki=<Subject Public Key Info>` on `Certificate` object where
              SPKI refers
              to [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7). The SPKI
              value identifies uniquely the underlying certificate
            - the system tag `_cert_ca=<Subject Common Name>` on CA `Certificate` object
        - import X509 certificate as PEM and also import private key as PEM
        - export generic KMIP key `wrapped` by X509 certificate
        - import a wrapped key with unwrapping on the fly
        - encrypt with X509 certificate and decrypt with PKCS8 private key
    - in `ckms`, add:
        - create/destroy certificate
        - export/import certificate
        - revoke certificate
- Add the export wrapping with X509 certificate encryption

## [4.5.0] - 2023-08-21

### 🐛 Bug Fixes

- Documentation

### 🚀 Features

- tagging: the KMS server now supports user tagging of objects to facilitate their management.
  Specify as many user tags as needed when creating and importing objects.

In addition, the user server will automatically add a system tag based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key

Use the tags to export objects, locate them, or request data encryption and decryption.

- Added `locate` to the `ckms`client
- Added `Redis-Findex` backend support so that the KMS can encrypt the KMS server data and indexes
  at the application level.
- Added JWE support

## [4.4.3] - 2023-07-17

### 🐛 Bug Fixes

- Remove RUSTFLAGS for docker container and python package

### 🚀 Features

- Update sqlx to 0.7 + bitflags and base64-url to version 2

## [4.4.2] - 2023-06-13

### 🚀 Features

- Support glibc v2.17 when building ckms and cosmian_kms_server

## [4.4.1] - 2023-06-09

### 🐛 Bug Fixes

- Incorrect docker tag

### 📚 Documentation

- Add description on docker usage

## [4.4.0] - 2023-06-06

### 🚀 Features

- Added the ability to manipulate EC and Symmetric Keys
- Added ECIES encryption (using Curve 25519) and AES GCM encryption
- Added support for policy specifications
- Reworked Revoke and Destroy to be closer to KMIP definitions
- Revoking and Destroying a public/private key, revokes or destroy all the related keys
- Upgrading of SQLX
- Upgrading of PKCS12 support
- Removal of Eyre in the CLI
- Use of cloudproof_rust as a dependency rather than Covercrypt and Crypto Core directly to avoid
  version conflicts
- Authentication:
    - support for more JWT providers
    - support for certificate authentication
- Removal of global static conf and use of proper injection (was hindering testing)
- Authorization: re-factor of endpoints and fix delegation issues around revoke and destroy

### 📚 Documentation

- Add link to package.cosmian.com

### 🧪 CI

- Add github ci
- Publish python kms packages

### Refactor

- Refactored the server to simplify traits and separate the operations into smaller files

---

## [4.3.4] - 2023-03-09

### 🚀 Features

- Python KMS client (pyo3): export `database_secret` and `insecure` as parameters

### Testing

- Update cover crypt in python tests

---

## [4.3.3] - 2023-03-02

### 🚀 Features

- Use CoverCrypt v11

### Refactor

- Removed `mysql` crate used for EdgelessDB (compatible with client SSL connection)
- Use workspace dependencies to ease maintenance

---

## [4.3.2] - 2023-02-17

### 📚 Documentation

- mkdocs-merge could not run with `emoji_index` url

---

## [4.3.1] - 2023-02-16

### 🧪 CI

- Remove unused docker builds

---

## [4.3.0] - 2023-02-15

### 📚 Documentation

- Improves the installation doc and details the important options
- Makes wording coherent between doc and code

### 🚀 Features

- adds native HTTP/S support by providing certificates
- improves encrypted SQLite support

### ⚙️ Miscellaneous Tasks

- removes multiple features on the KMS server and makes them command-line options.
- There is now a single docker (115MB) that covers all cases (except SGX, which will come later)
- removes the use of crypto_base and makes use of cover-crypt 10.0

---

## [4.2.0] - 2023-01-30

### 🚀 Features

- Use CoverCrypt v9.0 (post-quantum cryptography) and AbePolicy v3.0
    - Write `Policy` as bytes and `AccessPolicy` as string in Vendor Attributes

### 🧪 CI

- Fix tag matching in `python_publish`

---

## [4.1.0] - 2023-01-19

### Added

- add python interface

### Changed

- CoverCrypt v9 / CryptoCore v5 / AbePolicy v3.0
- CLI Policy interface (format changed with AbePolicy v2.1)

---

## [4.0.1] - 2022-11-29

### Changed

- add authentication data in header too in encrypt operation

---

## [4.0.0] - 2022-11-28

### Added

### Changed

- data to encrypt with CoverCrypt is not a JSON anymore but a custom binary format (
  see `DataToEncrypt` struct)
- decrypted data with CoverCrypt is now a custom binary format (see `DecryptedData` struct)

### Fixed

### Removed

---

## [3.0.2] - 2022-11-16

### Added

### Changed

- Support `cover_crypt` 7.1.0

### Fixed

### Removed

---

## [3.0.1] - 2022-11-14

### Added

### Changed

### Fixed

- Rename KMS URL

### Removed

- Remove AVX flag

---

## [3.0.0] - 2022-11-09

### Added

### Changed

- Update `cover_crypt` to 7.0.1
- Update crates dependencies

### Fixed

### Removed

- GPSW support
- TFHE support
- DMCFE support

---

## [2.3.3] - 2022-10-25

### Added

- Handle CORS request

### Changed

- Update installation documentation

### Fixed

### Removed

---

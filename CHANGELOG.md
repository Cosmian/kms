# Changelog

All notable changes to this project will be documented in this file.

## [X.Y.Z] - 2025-10-15

### ✅ KMIP XML Vector Conformance (1.4 & 2.1)

- KMIP crate updates (DiscoverVersions types/fields, TTLV coercions, Attribute decoding), server routing parity, and CLI coverage align Create, Query/DiscoverVersions, and OpaqueObject revoke/destroy flows with the official XML test vectors.

### 🚀 Features

- kmip (crate)
    - kmip_operations.rs: Expanded Operation enum with Interop/PKCS11/Check/RNG Retrieve/Seed/GetAttributeList/MACVerify/ModifyAttribute/Log + responses; implemented Display via strum for cleaner debug output.
    - kmip_messages.rs: Request/Response batch items now Clone + structured Display; deserializer maps added for new ops including GetAttributeList, MACVerify, Sign/SignatureVerify, RNGRetrieve/Seed, ModifyAttribute, Check, Interop, Log, PKCS11.
    - kmip_types.rs: Added Vendor OpaqueDataType; implemented Display for CryptographicDomainParameters, ProtectionStorageMasks, and StorageStatusMask to improve diagnostics.
    - TTLV (deserializer.rs): More permissive coercions (Integer→i64, Interval→i64, Enumeration/LongInteger→u8), ByteString→hex for ShortUniqueIdentifier, relaxed Attribute enum decoding for VendorAttribute and AttributeName+Value forms.
    - TTLV (byte_string_deserializer.rs): Support deserialize_ignored_any as no-op to avoid loops in permissive paths.
    - DiscoverVersions: uses KMIP 0.x types with protocol_version_major/minor; Query advertises supported operations and objects.
    - XML serializer/deserializer for XML test vectors support.
- server
    - Added/validated routing for: DiscoverVersions, Query, RNG Retrieve/Seed, MACVerify, GetAttributeList; Revoke supports OpaqueObject; GetAttributeList ordering is deterministic.
    - Newly exposed KMIP operations:
        - DiscoverVersions
        - Query
        - RNGRetrieve
        - RNGSeed
        - MACVerify
        - GetAttributeList
    - Make optional the cascade mechanism for Destroy and Revoke operations.
- cli
    - New opaque-object subcommand: Create/Import/Export/Revoke/Destroy (no wrap/unwrap).
    - New rng (Retrieve/Seed), mac verify, discover-versions, and query commands.
- kms_client
    - Added facade methods for RNG Retrieve/Seed, MACVerify, Query, DiscoverVersions, Check, GetAttributeList, attribute ops, register, and crypto ops.

### 🐛 Bug Fixes

- Export OpaqueObject Raw/Base64 returns opaque bytes (no KeyBlock).
- DiscoverVersions type/field mismatches fixed by switching to KMIP 0.x (major/minor).
- TTLV deserializer: better errors and coercions (u8 from Enumeration/LongInteger; i64 widening from Integer/Interval; vendor Attribute decoding) for XML vector compatibility.
- GetAttributeList: unified, deterministic ordering across environments.

### 🧪 Testing

- Added CLI tests: OpaqueObject CRUD (create/import, export json/base64/raw, revoke, destroy), RNG Retrieve/Seed, MAC Verify, Query, and DiscoverVersions.

## [5.10.0] - 2025-10-21

### 🚀 Features

- Add HSM key search with basic filters (#552)
- Support wrapping SecretData object in export (#551)
- Support DeriveKey KMIP operation (#554)
- Add option to enable automatic unwrapping for Get and Export requests (#579)

### 🐛 Bug Fixes

- Enable workspace clippy lints for all crates (#553)
- Release HSM tests (#567)
- Keep error info on DBerror (#516)
- React CVE deps (#566)
- Remove min_specialization feature (#569)
- HSM key search fails after encountering incompatible key (#574)
- *(windows)* Socket server listen on localhost instead of 0.0.0.0 (#575)

### 📚 Documentation

- Add SmartCard HSM to README.md (#563)
- Added documentation for Smartcard HSM and SoftHSM2 (#570)
- Add server configs examples (#568)

### 🧪 Testing

- Filter tests with credentials and prerequisites (#571)
- Enable Google CSE on workspace

### ⚙️ Miscellaneous Tasks

- Add CLA Assistant GitHub Action configuration
- Create CLA.md and CONTRIBUTING.md
- About forks, skip Google CSE tests and docker build
- About dependabot branches, skip Google CSE tests and docker build (#559)
- Move CLA assistant workflow to correct path
- Skip public doc rebuild on forks and dependabot branches
- Skip CLA assistant on dependabot branches
- Integrate CLA signature in main_base.yml workflow - 2
- Trigger on issue comment
- Use an unprotected branch for CLA signing
- Remove trigger on pull_request_target
- Upgrade toolchain to nightly 2025-09-15 (#564)

### Build

- *(deps)* Bump actions/checkout from 4 to 5
- *(deps)* Bump the npm_and_yarn group across 1 directory with 4 updates

## [5.9.0] - 2025-09-15

### 🚀 Features

- Add Smart card HSM support and bug fixes (#538)
- CLI features:
    - added support for SHA1 in RSA key wrapping (#541)
    - add Azure functionality to facilitate BYOK (#541)
    - `attributes get` added support to retrieve Object tags only (#541)
- *tracing*: print function names while using tracing macros. Use cosmian_logger instead of tracing crate (#536)

### 🐛 Bug Fixes

- When wrapped with `No Encoding`, the RSA private key bytes and EC private key bytes are now the PKCS#8 DER bytes (#541)
- CLI: fixed broken `attributes get` (#541)

### 📚 Documentation

- Added Google CSEK and Google CMEK documentation (#541)
- Added Azure BYOK documentation (#541)
- Re-organized documentation (#541)
- Fixing typo in Encrypt/Decrypt requests examples (#545)

### 🧪 Testing

- Enable softhsm2 tests (#539)
- Fix python installation on pykmip-tests GH workflow
- Fix race condition on test_privileged_users
- Add auth test with expired cert (#547)

## [5.8.1] - 2025-09-05

### 🐛 Bug Fixes

- Server crate publish (#534)

## [5.8.0] - 2025-09-05

### 🚀 Features

- Add KMIP operations `Sign` and `VerifySignature` for digital signature support (#511)
- Add TLS cipher suites selection (#524)

### 🐛 Bug Fixes

- *(google_cse)* Further restrict access to CSE privileged unwrap endpoint (#517)
- Fix potential race condition in Google CSE migration key pair creation when multiple servers start simultaneously (#519)
- Simplify clap JWT Auth configuration (#531)
- Add non-fips UI build (#532)
- Fix Credential parsing in KMIP Request Message (#529)
- Use crypto core for db crypto (#526)
- Cloudproof reexports (#528)

### 📚 Documentation

- *(percona)* Add correction to percona doc (#521)
- *(hsm)* Added KMS-HSM integration workflow graph (#523)
- Fixes CLI Key Wrapping documentation on export (#530)
- Clarify Gmail CSE CA authority usage (#533)

### ⚙️ Miscellaneous Tasks

- Uniformize clippy lints on all crates (#525)
- Create SECURITY.md with vulnerability tracking and reporting guidelines (#527)

## [5.7.1] - 2025-08-22

### 🚀 Features

- Add support HTTP forward proxy (for intermediate CLI crate) (#509)

### 📚 Documentation

- PKCS11: move PKCS#11 docs into cli repository (#510)

### ⚙️ Miscellaneous Tasks

- Google CSE: save openssl commands to verify resource hash computation

## [5.7.0] - 2025-08-20

### 🚀 Features

- In JWT auth, change `audience` type from `String` to `Vec<String>`  (#491)
- Support AES-CBC encryption without padding for Oracle TDE support (#493)
- Add support for existing PKCS12 leaf certificates when creating Google CSE keypairs (#505)
- Support debian 10 for old glibc compatibility (required for Oracle TDE) (#508)
- Add GitHub Copilot instructions for KMS development workflow (#504)

### 🐛 Bug Fixes

- Test docker container once generated by ci (#481)

### ⚙️ Miscellaneous Tasks

- Use machete and publish crates on tags (#499)
- Remove test data folder (#497)
- Reorder crates in Cargo.toml
- Fix docker image name in tests (#500)
- Automate CVE resolution (when possible) by mirroring deny.toml in .cargo/audit.toml

## [5.6.2] - 2025-07-29

### 🐛 Bug Fixes

- Remove useless and old UI files (#487)
- Test_kms_server must remain dev-dependency (#486)
- Enable native TLS support for OpenID Connect authentication (#489)

## [5.6.1] - 2025-07-25

### 🚀 Features

- Display CSE information from UI (#478)

### 🐛 Bug Fixes

- Fix outdated UI pkg
- Rocky package must be NON-FIPS (#482)

### 📚 Documentation

- Add MongoDB documentation (#483)
- Improve User Interface documentation

## [5.6.0] - 2025-07-23

### 🐛 Bug Fixes

- Support for TLS 1.3 on the HTTPS port of the KMIP server (#458)
- Fixed RevocationReasonCode in KMIP 1.x (#460)

### 🚀 Features

- Better support of PyKMIP client (#438)
- Support for Percona PostgreSQL TDE (Transparent Data Encryption) (#464)
- Support for Secret Data (#398)

## [5.5.1] - 2025-07-09

### 🐛 Bug Fixes

- Fixed an issue with Locate failing when an HSM is present
- Fixed missing attributes when the wrapped object is not in the cache (#462)
- Added support for SoftHsmV2 (#457)

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

- Invert fips feature (#448)
- Google CSE - Added support for all algorithms in private_key_decrypt
- Google CSE - Added support for all algorithms in private_key_sign

### ⚙️ Miscellaneous Tasks

- Align UI version with Cargo workspace

## [5.3.3] - 2025-06-12

### 🐛 Bug Fixes

- In UI, fix `IvCounterNonce` (#446)
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

- Support for MySQL 8.0.42 and higher (#443)

## [5.3.1] - 2025-06-04

### 🐛 Bug Fixes

- Fix clap error on cse keypair command

## [5.3.0] - 2025-06-02

### 🚀 Features

- Support for outbound proxy to fetch the JWKS (JSON Web Key Set) (#439)

## [5.2.0] - 2025-05-27

### 🚀 Features

- Support for JWKS (JSON Web Key Set) that provides JWK not appropriate for OIDC authentication (#433)

## [5.1.1] - 2025-05-23

### 🐛 Bug Fixes

- Safer handling of Google CSE authorization token decoding (#431)

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

- KMIP server operations only support DER format for certificates (#89)

## [4.9.0] - 2023-11-10

### 🐛 Bug Fixes

- fix: migrate to num-bigint-dig for bigint (#85)

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
- Serialize the header for each chunk for Covercrypt bulk encryption (#59)

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

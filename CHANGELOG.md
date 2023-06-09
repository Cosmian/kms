# Changelog

All notable changes to this project will be documented in this file.

## [4.4.2] - 2023-06-13

### Features

- Support glibc v2.17 when building ckms and cosmian_kms_server

## [4.4.1] - 2023-06-09

### Bug Fixes

- Incorrect docker tag

### Documentation

- Add description on docker usage

## [4.4.0] - 2023-06-06

### Features

- Added the ability to manipulate EC and Symmetric Keys
- Added ECIES encryption (using Curve 25519) and AES GCM encryption
- Added support for policy specifications
- Reworked Revoke and Destroy to be closer to KMIP definitions
- Revoking and Destroying a public/private key, revokes or destroy all the related keys
- Upgrading of SQLX
- Upgrading of PKCS12 support
- Removal of Eyre in the CLI
- Use of cloudproof_rust as a dependency rather than Covercrypt and Crypto Core directly to avoid version conflicts
- Authentication:
  - support for more JWT providers
  - support for certificate authentication
- Removal of global static conf and use of proper injection (was hindering testing)
- Authorization: re-factor of endpoints and fix delegation issues around revoke and destroy

### Documentation

- Add link to package.cosmian.com

### Ci

- Add github ci
- Publish python kms packages

### Refactor

- Refactored the server to simplify traits and separate the operations into smaller files

---

## [4.3.4] - 2023-03-09

### Features

- Python KMS client (pyo3): export `database_secret` and `insecure` as parameters

### Testing

- Update cover crypt in python tests

---

## [4.3.3] - 2023-03-02

### Features

- Use CoverCrypt v11

### Refactor

- Removed `mysql` crate used for EdgelessDB (compatible with client SSL connection)
- Use workspace dependencies to ease maintenance

---

## [4.3.2] - 2023-02-17

### Documentation

- mkdocs-merge could not run with `emoji_index` url

---

## [4.3.1] - 2023-02-16

### Ci

- Remove unused docker builds

---

## [4.3.0] - 2023-02-15

### Documentation

- Improves the install doc and details the important options
- Makes wording coherent between doc and code

### Features

- adds native HTTP/S support by providing certificates
- improves encrypted SQLite support

### Miscellaneous Tasks

- removes multiple features on the KMS server and makes them command-line options.
- There is now a single docker (115MB) that covers all cases (except SGX, which will come later)
- removes the use of crypto_base and makes use of cover-crypt 10.0

---

## [4.2.0] - 2023-01-30

### Features

- Use CoverCrypt v9.0 (post-quantum cryptography) and AbePolicy v3.0
  - Write `Policy` as bytes and `AccessPolicy` as string in Vendor Attributes

### Ci

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

- data to encrypt with CoverCrypt is not a JSON anymore but a custom binary format (see `DataToEncrypt` struct)
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

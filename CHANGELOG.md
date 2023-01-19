# Changelog

All notable changes to this project will be documented in this file.

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

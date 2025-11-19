# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/main.yml/badge.svg?branch=main)
![Build status](https://github.com/Cosmian/kms/actions/workflows/main_release.yml/badge.svg?branch=main)

The **Cosmian KMS** is a high-performance,
source-available [FIPS 140-3 compliant](./documentation/docs/fips.md) server application
written in [Rust](https://www.rust-lang.org/).

Online [documentation](https://docs.cosmian.com/key_management_system/)

![KMS WebUI](./documentation/docs/images/kms-ui.png)

The Cosmian KMS presents some unique features, such as:

- large-scale encryption and decryption of
  data [see this documentation](./documentation/docs/encrypting_and_decrypting_at_scale.md)
- the ability to confidentially run in a public cloud, or any zero-trust environment, using
  Cosmian VM. See our cloud-ready confidential KMS on the
  [Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/)
  our [deployment guide](./documentation/docs/installation/marketplace_guide.md)
- support of state-of-the-art authentication mechanisms (see [authentication](./documentation/docs/authentication.md))
- out-of-the-box support of
  [Google Workspace Client Side Encryption (CSE)](./documentation/docs/google_cse/index.md)
- out-of-the-box support
  of [Microsoft Double Key Encryption (DKE)](./documentation/docs/ms_dke/index.md)
- support for the [CardContact SmartCard, Nitrokey HSM 2, Proteccio, Crypt2pay, Utimaco and other HSMs](./documentation/docs/hsms/index.md) with KMS keys wrapped by the HSM
- [Veracrypt](https://docs.cosmian.com/cosmian_cli/pkcs11/veracrypt/)
  and [LUKS](https://docs.cosmian.com/cosmian_cli/pkcs11/luks/) disk encryption support
- [FIPS 140-3](./documentation/docs/fips.md) mode gated behind the feature `fips`
- a [binary and JSON KMIP 1.0-1.4 and 2.0-2.1](./documentation/docs/kmip/index.md) compliant interface
- MongoDB (./documentation/docs/mongodb.md)
- Oracle DB [TDE support](https://docs.cosmian.com/cosmian_cli/pkcs11/oracle/tde/)
- Percona Postgresql DB (./documentation/docs/percona.md)
- VMWare [vCenter Trust Key Provider integration](./documentation/docs/vcenter.md)
- User Defined Functions for [Big Data](./documentation/docs/python_udf/index.md) including [snowflake](./documentation/docs/snowflake/index.md)
- a full-featured client [command line and graphical interface](https://docs.cosmian.com/cosmian_cli/)
- a [high-availability mode](documentation/docs/installation/high_availability_mode.md) with simple horizontal scaling
- a support of Python, JavaScript, Dart, Rust, C/C++, and Java clients (see the `cloudproof` libraries
  on [Cosmian Github](https://github.com/Cosmian))
- integrated with [OpenTelemetry](https://opentelemetry.io/)

The **Cosmian KMS** is both a Key Management System and a Public Key Infrastructure.
As a KMS, it is designed to manage the lifecycle of keys and provide scalable cryptographic
services such as on-the-fly key generation, encryption, and decryption operations.

The **Cosmian KMS** supports all the standard NIST cryptographic algorithms as well as advanced post-quantum
cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt).
Please refer to the list of [supported algorithms](./documentation/docs/algorithms.md).

As a **PKI** it can manage root and intermediate certificates, sign and verify certificates, use
their public keys to encrypt and decrypt data.
Certificates can be exported under various formats, including _PKCS#12_ modern and legacy flavor,
to be used in various applications, such as in _S/MIME_ encrypted emails.

The KMS has extensive online [documentation](https://docs.cosmian.com/key_management_system/)

- [Cosmian KMS](#cosmian-kms)
    - [Quick start](#quick-start)
        - [Example](#example)
    - [Repository content](#repository-content)
        - [Binaries](#binaries)
        - [Core Crates](#core-crates)
            - [Server Infrastructure](#server-infrastructure)
            - [Client Libraries](#client-libraries)
            - [Cryptographic Components](#cryptographic-components)
            - [Hardware Security Module (HSM) Support](#hardware-security-module-hsm-support)
            - [Database Interfaces](#database-interfaces)
            - [Development and Testing](#development-and-testing)
        - [Additional Directories](#additional-directories)
    - [Building and running the KMS](#building-and-running-the-kms)
        - [Features](#features)
        - [Linux or macOS](#linux-or-macos)
        - [Windows](#windows)
        - [Build the Docker Ubuntu container](#build-the-docker-ubuntu-container)
        - [Packaging (DEB/RPM/DMG) and hashes](#packaging-debrpmdmg-and-hashes)
    - [Running the unit and integration tests](#running-the-unit-and-integration-tests)
    - [Development: running the server with cargo](#development-running-the-server-with-cargo)
    - [Server parameters](#server-parameters)
    - [Use the KMS inside a Cosmian VM on SEV/TDX](#use-the-kms-inside-a-cosmian-vm-on-sevtdx)
    - [Releases](#releases)
    - [Benchmarks](#benchmarks)
    - [KMIP support by Cosmian KMS](#kmip-support-by-cosmian-kms)
        - [KMIP Baseline Profile Compliance](#kmip-baseline-profile-compliance)
        - [KMIP Coverage](#kmip-coverage)
            - [Messages](#messages)
            - [Operations by KMIP Version](#operations-by-kmip-version)
            - [Methodology](#methodology)
            - [Managed Objects](#managed-objects)
            - [Base Objects](#base-objects)
            - [Transparent Key Structures](#transparent-key-structures)
            - [Attributes](#attributes)

## Quick start

Pre-built binaries [are available](https://package.cosmian.com/kms/5.12.0/)
for Linux, MacOS, and Windows, as well as Docker images. To run the server binary, OpenSSL must be
available in your path (see "building the KMS" below for details); other binaries do not have this
requirement.

Using Docker to quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
inside the container, run the following command:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
```

Then, use the CLI to issue commands to the KMS. The CLI, called `cosmian`, can be either:

- installed with `cargo install cosmian_cli`
- downloaded from [Cosmian packages](https://package.cosmian.com/cli/)
- built and launched from the [GitHub project](https://github.com/Cosmian/cli) by running

    ```sh
    cargo build --bin cosmian
    ```

### Example

1. Create a 256-bit symmetric key

    ```sh
    ➜ cosmian sym keys create --number-of-bits 256 --algorithm aes --tag my-key-file
    ...
    The symmetric key was successfully generated.
      Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e

      Tags:
        - my-key-file
    ```

2. Encrypt the `image.png` file with AES GCM using the key

    ```sh
    ➜ cosmian sym encrypt --tag my-key-file --output-file image.enc image.png
    ...
    The encrypted file is available at "image.enc"
    ```

3. Decrypt the `image.enc` file using the key

    ```sh
    ➜ cosmian sym decrypt --tag my-key-file --output-file image2.png image.enc
    ...
    The decrypted file is available at "image2.png"
    ```

See the [documentation](https://docs.cosmian.com/key_management_system/) for more.

## Repository content

The **Cosmian KMS** is written in [Rust](https://www.rust-lang.org/) and organized as a Cargo workspace with multiple crates. The repository contains the following main components:

### Binaries

- **KMS Server** (`cosmian_kms`) - The main KMS server binary built from `crate/server`

### Core Crates

#### Server Infrastructure

- **`server`** - Main KMS server implementation with REST API, KMIP protocol support, and web UI
- **`server_database`** - Database abstraction layer supporting SQLite, PostgreSQL, MySQL, and Redis
- **`access`** - Permission and access control management system

#### Client Libraries

- **`kms_client`** - High-level Rust client library for KMS server communication
- **`client_utils`** - Shared utilities for client implementations
- **`wasm`** - WebAssembly bindings for browser-based clients

#### Cryptographic Components

- **`crypto`** - Core cryptographic operations and algorithm implementations
- **`kmip`** - Complete implementation of the KMIP (Key Management Interoperability Protocol) standard versions 1.0-2.1
- **`kmip-derive`** - Procedural macros for KMIP protocol serialization/deserialization

#### Hardware Security Module (HSM) Support

- **`hsm/base_hsm`** - Base HSM abstraction layer
- **`hsm/smartcardhsm`** - Nitrokey HSM 2 resp. CardContact SmartCard-HSM
- **`hsm/crypt2pay`** - Crypt2pay HSM integration
- **`hsm/proteccio`** - Proteccio HSM integration
- **`hsm/softhsm2`** - SoftHSM2 integration for testing and development
- **`hsm/utimaco`** - Utimaco HSM integration
- **`hsm/other`** - Other HSMs support

#### Database Interfaces

- **`interfaces`** - Database and storage backend abstractions

#### Development and Testing

- **`test_kms_server`** - Library for programmatic KMS server instantiation in tests
- **`cli`** - Legacy CLI crate (now primarily used for testing)

### Additional Directories

- **`documentation/`** - Comprehensive project documentation built with MkDocs
- **`examples/`** - Code examples and integration samples
- **`scripts/`** - Build and deployment scripts
- **`test_data/`** - Test fixtures and sample data
- **`ui/`** - Frontend web interface source code
- **`pkg/`** - Packaging configurations for Debian and RPM distributions

**Note:** Each crate contains its own README with detailed information. Please refer to these files for specific implementation details and usage instructions.

Find the [public documentation](https://docs.cosmian.com) of the KMS in the `documentation`
directory.

## Building and running the KMS

Two paths are supported:

- For production use, use deterministic Nix build: use the unified script `.github/scripts/nix.sh` for a pinned toolchain,
  reproducible builds, and packaging.
- For development purpose, use traditional `cargo` command: `cargo build...`, `cargo test`

### Features

- From 5.4.0 the server runs in FIPS mode by default. Enable non-FIPS with `--features non-fips` (Cargo) or
  `--variant non-fips` (Nix).
- OpenSSL v3.1.2 is required when building outside Nix. The Nix flow provides the pinned version automatically.

### Linux or macOS

Deterministic (Nix-first):

```sh
# Build (debug by default); add --profile release for optimized builds
bash .github/scripts/nix.sh build

# Run tests (defaults to 'all'; DB backends require services)
bash .github/scripts/nix.sh test

# Package artifacts (Linux → deb+rpm, macOS → dmg)
bash .github/scripts/nix.sh package
```

Simple (Cargo-only):

```sh
cargo build
cargo test
```

### Windows

Follow the prerequisites below, or use the provided PowerShell helpers.

Prerequisites (manual):

1. Install Visual Studio (C++ workload + clang), Strawberry Perl, and `vcpkg`.
2. Install OpenSSL 3.1.2 with vcpkg:

```powershell
vcpkg install --triplet x64-windows-static  # arm64-windows-static for ARM64
vcpkg integrate install
$env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
```

For FIPS builds (to build fips.dll):

```powershell
Copy-Item -Path "vcpkg_fips.json" -Destination "vcpkg.json"
vcpkg install
vcpkg integrate install
```

PowerShell helpers (non-FIPS by default):

```powershell
. .github/scripts/cargo_build.ps1
BuildProject -BuildType release   # or debug

. .github/scripts/cargo_test.ps1
TestProject -BuildType release    # or debug
```

### Build the Docker Ubuntu container

You can build a Docker image that contains the KMS server as follows:

```sh
docker buildx build . -t kms
```

Or, with FIPS support:

```sh
docker buildx build --build-arg FIPS="true" -t kms .
```

### Packaging (DEB/RPM/DMG) and hashes

Use the Nix entrypoint to build packages:

```sh
# Linux
bash .github/scripts/nix.sh package           # builds deb + rpm
bash .github/scripts/nix.sh package deb       # build deb only
bash .github/scripts/nix.sh package rpm       # build rpm only

# macOS
bash .github/scripts/nix.sh package dmg
```

On success, a SHA-256 checksum file (.sha256) is written next to each generated package
(.deb/.rpm/.dmg) to ease verification and artifact distribution.

## Running the unit and integration tests

Pull the test data using:

```sh
git submodule update --init --recursive
```

By default, tests are run using `cargo test` and an SQLCipher backend (called `sqlite`).
This can be influenced by setting the `KMS_TEST_DB` environment variable to

- `sqlite`, for plain SQLite
- `mysql` (requires a running MySQL or MariaDB server connected using a
  `"mysql://kms:kms@localhost:3306/kms"` URL)
- `postgresql` (requires a running PostgreSQL server connected using
  a `"postgresql://kms:kms@127.0.0.1:5432/kms"`URL)
- `redis-findex` (requires a running Redis server connected using a
  `"redis://localhost:6379"` URL)

Example: testing with a plain SQLite and some logging

```sh
RUST_LOG="error,cosmian_kms_server=info,cosmian_kms_cli=info" KMS_TEST_DB=sqlite cargo test
```

Alternatively, when writing a test or running a test from your IDE, the following can be inserted
at the top of the test:

```rust
unsafe {
set_var("RUST_LOG", "error,cosmian_kms_server=debug,cosmian_kms_cli=info");
set_var("RUST_BACKTRACE", "1");
set_var("KMS_TEST_DB", "redis-findex");
}
log_init(option_env!("RUST_LOG"));
```

## Development: running the server with cargo

To run the server with cargo, you need to set the `RUST_LOG` environment variable to the desired
log level and select the correct backend (which defaults to `sqlite`).

```sh
RUST_LOG="info,cosmian_kms_server=debug" \
cargo run --bin cosmian_kms --features non-fips -- \
--database-type redis-findex --database-url redis://localhost:6379 \
--redis-master-password secret --redis-findex-label label
```

## Server parameters

If a configuration file is provided, parameters are set following this order:

- conf file (env variable `COSMIAN_KMS_CONF` set by default to `/etc/cosmian/kms.toml`)
- default (set on struct)

Otherwise, the parameters are set following this order:

- args in the command line
- env var
- default (set on struct)

## Use the KMS inside a Cosmian VM on SEV/TDX

See the [Marketplace guide](documentation/docs/installation/marketplace_guide.md) for more details about Cosmian VM.

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/kms/).

## Benchmarks

To run benchmarks, go to the `crate/test_kms_server` directory and run:

```sh
cargo bench
```

Typical values for single-threaded HTTP KMIP 2.1 requests
(zero network latency) are as follows

```text
- RSA PKCSv1.5:
    - encrypt
            - 2048 bits: 128 microseconds
            - 4096 bits: 175 microseconds
    - decrypt
            - 2048 bits: 830 microseconds
            - 4096 bits: 4120 microseconds
- RSA PKCS OAEP:
    - encrypt
            - 2048 bits: 134 microseconds
            - 4096 bits: 173 microseconds
    - decrypt
            - 2048 bits: 849 microseconds
            - 4096 bits: 3823 microseconds
- RSA PKCS KEY WRP (AES):
    - encrypt
            - 2048 bits: 142 microseconds
            - 4096 bits: 198 microseconds
    - decrypt
            - 2048 bits: 824 microseconds
            - 4096 bits: 3768 microseconds
- RSA Keypair creation (saved in KMS DB)
    -  2048 bits: 33 milliseconds
    -  4096 bits: 322 milliseconds
```

<!-- KMIP_SUPPORT_START -->
<!-- This section is auto-generated from documentation/docs/kmip/support.md by scripts/update_readme_kmip.py. Do not edit manually. -->
## KMIP support by Cosmian KMS

This page summarizes the KMIP coverage in Cosmian KMS. The support status is
derived from the actual implementation in `crate/server/src/core/operations`.

**Cosmian KMS Server supports KMIP versions:** 2.1, 2.0, 1.4, 1.3, 1.2, 1.1, 1.0

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated
- N/A Not applicable (operation/attribute not defined in that KMIP version)

### KMIP Baseline Profile Compliance

**Baseline Server:** ✅ Compliant (all 9 required + 18/18 optional)

The Baseline Server profile (defined in KMIP Profiles v2.1 Section 4.1) requires:

- **Required operations:** Discover Versions, Query, Create, Register, Get, Destroy, Locate, Activate, Revoke
- **Optional operations:** Many additional operations for extended functionality

### KMIP Coverage

#### Messages

| Message          | Support |
| ---------------- | ------: |
| Request Message  |      ✅ |
| Response Message |      ✅ |

#### Operations by KMIP Version

The following table shows operation support across all KMIP versions.

| Operation | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Activate                       |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Add Attribute                  |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Archive                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Cancel                         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certify                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Check                          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Create                         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Key Pair                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Create Split Key               |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Decrypt                        |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Delete Attribute               |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DeriveKey                      |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Destroy                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Discover Versions              |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Encrypt                        |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Export                         |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Get                            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Attribute List             |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Get Attributes                 |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Get Usage Allocation           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Hash                           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Import                         |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |
| Join Split Key                 |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Locate                         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC                            |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| MAC Verify                     |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Modify Attribute               |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Notify                         |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Obtain Lease                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Poll                           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Put                            |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ❌    |    ❌    |
| Query                          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RNG Retrieve                   |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| RNG Seed                       |   N/A   |   N/A   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Re-certify                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Re-key                         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Re-key Key Pair                |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Recover                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Register                       |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Revoke                         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Set Attribute (Modify)         |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |
| Sign                           |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Signature Verify               |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Validate                       |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

#### Methodology

- Operations marked ✅ are backed by a Rust implementation file under `crate/server/src/core/operations`.
- Operations marked ❌ are defined in the KMIP specification but not implemented in Cosmian KMS.
- Operations marked N/A do not exist in that particular KMIP version.
- This documentation is auto-generated by analyzing source code and KMIP specifications.

If you spot a mismatch or want to extend coverage, please open an issue or PR.

#### Managed Objects

The following table shows managed object support across all KMIP versions.

| Managed Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| -------------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Certificate    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Symmetric Key  |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Public Key     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Private Key    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Split Key      |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Template       |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |   N/A   |   N/A   |
| Secret Data    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Opaque Object  |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |   N/A   |
| PGP Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |

Notes:

- Opaque Object import support is present (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.
- Template objects are deprecated in newer KMIP versions.

#### Base Objects

The following table shows base object support across all KMIP versions.

| Base Object | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| ----------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Attribute                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Credential                               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Block                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Value                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Wrapping Data                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Wrapping Specification               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Transparent Key Structures               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Template-Attribute Structures            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Extension Information                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Data                                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Data Length                              |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Signature Data                           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| MAC Data                                 |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Nonce                                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Correlation Value                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Init Indicator                           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Final Indicator                          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| RNG Parameter                            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Profile Information                      |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Validation Information                   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Capability Information                   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Authenticated Encryption Additional Data |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Authenticated Encryption Tag             |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.
- Base objects are fundamental structures present across all KMIP versions.

#### Transparent Key Structures

The following table shows transparent key structure support across all KMIP versions.

| Structure | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Symmetric Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DSA Private Key          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| DSA Public Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| RSA Private Key          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| RSA Public Key           |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| DH Private Key           |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| DH Public Key            |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| ECDSA Private Key        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDSA Public Key         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |   N/A   |   N/A   |
| ECDH Private Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECDH Public Key          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Private Key        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| ECMQV Public Key         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |   N/A   |   N/A   |
| EC Private Key           |   N/A   |   N/A   |   N/A   |    ✅    |    ✅    |    ✅    |    ✅    |
| EC Public Key            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

#### Attributes

| Attribute | 1.0 | 1.1 | 1.2 | 1.3 | 1.4 | 2.0 | 2.1 |
| --------- | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: | :-----: |
| Activation Date                     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Alternative Name                    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Always Sensitive                    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Application Specific Information    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Archive Date                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Attribute Index                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certificate Attributes              |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certificate Identifier              |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |
| Certificate Issuer                  |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |
| Certificate Length                  |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Certificate Subject                 |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |
| Certificate Type                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Comment                             |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Compromise Date                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Compromise Occurrence Date          |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Contact Information                 |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Critical                            |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Cryptographic Algorithm             |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Cryptographic Domain Parameters     |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Cryptographic Length                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Cryptographic Parameters            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Cryptographic Usage Mask            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Deactivation Date                   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Description                         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Destroy Date                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Digest                              |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Digital Signature Algorithm         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Extractable                         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Fresh                               |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Initial Date                        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Key Format Type                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Value Location                  |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Key Value Present                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Last Change Date                    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Lease Time                          |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Link                                |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Name                                |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Never Extractable                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Nist Key Type                       |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Object Group                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Object Group Member                 |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Object Type                         |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Opaque Data Type                    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Operation Policy Name               |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |    🚫    |
| Original Creation Date              |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| PKCS#12 Friendly Name               |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Process Start Date                  |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Protect Stop Date                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Protection Level                    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Protection Period                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Protection Storage Masks            |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Quantum Safe                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Random Number Generator             |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Revocation Reason                   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Rotate Date                         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Rotate Generation                   |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Rotate Interval                     |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Rotate Latest                       |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Rotate Name                         |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Rotate Offset                       |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Sensitive                           |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Short Unique Identifier             |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| State                               |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Unique Identifier                   |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| Usage Limits                        |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| Vendor Attribute                    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |    ❌    |
| X.509 Certificate Identifier        |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| X.509 Certificate Issuer            |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |
| X.509 Certificate Subject           |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |    ✅    |

Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- A ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, explicitly excluding the attribute-only handlers (Add/Delete/Get/Set Attribute).
- Most attributes are present across all KMIP versions with some additions in newer versions.

<!-- KMIP_SUPPORT_END -->

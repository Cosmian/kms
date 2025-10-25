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
- support for the [CardContact SmartCard, Nitrokey HSM 2, Proteccio, and Utimaco HSMs](./documentation/docs/hsms/index.md) with KMS keys wrapped by the HSM
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
        - [Linux or macOS (CPU Intel or macOS ARM)](#linux-or-macos-cpu-intel-or-macos-arm)
        - [Windows](#windows)
        - [Build the KMS](#build-the-kms)
        - [Build the Docker Ubuntu container](#build-the-docker-ubuntu-container)
    - [Running the unit and integration tests](#running-the-unit-and-integration-tests)
    - [Development: running the server with cargo](#development-running-the-server-with-cargo)
    - [Server parameters](#server-parameters)
    - [Use the KMS inside a Cosmian VM on SEV/TDX](#use-the-kms-inside-a-cosmian-vm-on-sevtdx)
    - [Releases](#releases)
    - [Benchmarks](#benchmarks)
- [KMIP support by Cosmian KMS (v4.23 → v5.9.0)](#kmip-support-by-cosmian-kms-v423--v590)
    - [KMIP coverage](#kmip-coverage)
        - [Messages](#messages)
        - [Operations](#operations)
        - [Methodology](#methodology)
        - [Managed Objects](#managed-objects)
        - [Base Objects](#base-objects)
        - [Transparent Key Structures](#transparent-key-structures)
        - [Attributes](#attributes)

## Quick start

Pre-built binaries [are available](https://package.cosmian.com/kms/5.10.0/)
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
- **`hsm/proteccio`** - Proteccio HSM integration
- **`hsm/softhsm2`** - SoftHSM2 integration for testing and development
- **`hsm/utimaco`** - Utimaco HSM integration

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

The Cosmian KMS is built using the [Rust](https://www.rust-lang.org/) programming language.
A Rust toolchain is required to build the KMS.

### Features

From version 5.4.0, the KMS runs in FIPS mode by default.
The non-FIPS mode can be enabled by passing the `--features non-fips` flag to `cargo build` or `cargo run`.

OpenSSL v3.2.0 is required to build the KMS.

### Linux or macOS (CPU Intel or macOS ARM)

Retrieve OpenSSL v3.2.0 (already built) with the following commands:

```sh
export OPENSSL_DIR=/usr/local/openssl
sudo mkdir -p ${OPENSSL_DIR}
sudo chown -R $USER ${OPENSSL_DIR}
bash .github/reusable_scripts/get_openssl_binaries.sh
```

### Windows

1. Install Visual Studio Community with the C++ workload and clang support.
2. Install Strawberry Perl.
3. Install `vcpkg` following
   [these instructions](https://github.com/Microsoft/vcpkg#quick-start-windows)

4. Then install OpenSSL 3.2.0:

The files `vcpkg.json` and `vcpkg_fips.json` are provided in the repository to install OpenSSL v3.2.0:

```powershell
vcpkg install --triplet x64-windows-static # arm64-windows-static for ARM64

vcpkg integrate install
$env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static" # openssl_arm64-windows-static for ARM64
```

For a FIPS-compliant build, use the following commands (to build fips.dll), also run:

```powershell
Copy-Item -Path "vcpkg_fips.json" -Destination "vcpkg.json"
vcpkg install
vcpkg integrate install
```

### Build the KMS

Once OpenSSL is installed, you can build the KMS. To avoid the _additive feature_ issues, the main artifacts - the CLI,
the KMS server and the PKCS11 provider should be directly built using `cargo build --release` within their crate,
not from the project root.

Build the server:

```sh
cd crate/server
cargo build --release
```

### Build the Docker Ubuntu container

You can build a Docker containing the KMS server as follows:

```sh
docker buildx build . -t kms
```

Or:

```sh
# Example with FIPS support
docker buildx build --build-arg FIPS="true" -t kms .
```

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
<!-- This section is auto-generated from documentation/docs/KMIP_support.md by scripts/update_readme_kmip.py. Do not edit manually. -->
# KMIP support by Cosmian KMS (v4.23 → v5.11.0)

This page summarizes the KMIP coverage in Cosmian KMS, using the OVHcloud guide as a layout
reference. Columns are KMS server versions grouped by identical support. Operation support is
derived from the presence of a dedicated implementation in
`crate/server/src/core/operations` for each version tag.

Legend:

- ✅ Fully supported
- ❌ Not implemented
- 🚫 Deprecated (not used here)
- 🚧 Partially supported (not used here)
- N/A Not applicable

Version columns (merged where identical):

- 4.23.0 – 4.24.0
- 5.0.0 – 5.4.1
- 5.5.0 – 5.5.1
- 5.6.0 – 5.7.1
- 5.8.0 – 5.10.0
- 5.11.0

Notes:

- The Operations table below is computed from the server source tree at each version tag.
- Prior to 5.10.0, some KMIP documents used "Modify Attribute" to refer to the server's
  Set Attribute handler. From 5.10.0, a dedicated Modify Attribute operation is implemented.
- "Discover" here refers to the KMIP Discover Versions operation.

## KMIP coverage

### Messages

| Message          | 4.23–4.24 | 5.0–5.11 |
| ---------------- | --------: | -------: |
| Request Message  |         ✅ |        ✅ |
| Response Message |         ✅ |        ✅ |

### Operations

| Operation              | 4.23–4.24 | 5.0–5.4.1 | 5.5–5.5.1 | 5.6–5.7.1 | 5.8–5.10 | 5.11.0 |
| ---------------------- | --------: | --------: | --------: | --------: | -------: | -----: |
| Create                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Create Key Pair        |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Register               |         ❌ |         ❌ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-key                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-key Key Pair        |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| DeriveKey              |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Certify                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Re-certify             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Locate                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Check                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Get                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Get Attributes         |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Get Attribute List     |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Add Attribute          |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Set Attribute (Modify) |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Modify Attribute       |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Delete Attribute       |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Obtain Lease           |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Get Usage Allocation   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Activate               |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Revoke                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Destroy                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Archive                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Recover                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Validate               |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Query                  |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cancel                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Poll                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Notify                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Put                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Discover Versions      |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Encrypt                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Decrypt                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Sign                   |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| Signature Verify       |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| MAC                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| MAC Verify             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| RNG Retrieve           |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| RNG Seed               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Hash                   |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Create Split Key       |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Join Split Key         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Export                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Import                 |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |

### Methodology

- Operations shown as ✅ are backed by a Rust implementation file under `crate/server/src/core/operations` at the corresponding version tag.
- If no implementation file exists at a tag for an operation, it is marked ❌ for that version range.
- Version ranges were merged when the set of supported operations did not change across the range:

    - 4.23.0–4.24.0
    - 5.0.0–5.4.1 (adds AddAttribute, Discover Versions, Query)
    - 5.5.0–5.5.1 (adds Register)
    - 5.6.0–5.7.1 (adds Activate, Digest internal support)
    - 5.8.0–5.10.0 (adds Sign, Signature Verify at 5.8)
    - 5.11.0 (adds DeriveKey, Check, Get Attribute List, RNG Retrieve, RNG Seed, MAC Verify, and a dedicated Modify Attribute)

If you spot a mismatch or want to extend coverage, please open an issue or PR.

### Managed Objects

| Managed Object | 4.23–4.24 | 5.0–5.11 |
| -------------- | --------: | -------: |
| Certificate    |         ✅ |        ✅ |
| Symmetric Key  |         ✅ |        ✅ |
| Public Key     |         ✅ |        ✅ |
| Private Key    |         ✅ |        ✅ |
| Split Key      |         ❌ |        ❌ |
| Template       |         🚫 |        🚫 |
| Secret Data    |         ✅ |        ✅ |
| Opaque Object  |         ❌ |        ✅ |
| PGP Key        |         ❌ |        ❌ |

Notes:

- Opaque Object import support is present from 5.0.0 (see `import.rs`).
- PGP Key types appear in digest and attribute handling but full object import/register is not implemented, hence ❌.

### Base Objects

| Base Object                              | 4.23–4.24 | 5.0–5.10 | 5.11.0 |
| ---------------------------------------- | --------: | -------: | -----: |
| Attribute                                |         ✅ |        ✅ |      ✅ |
| Credential                               |         ✅ |        ✅ |      ✅ |
| Key Block                                |         ✅ |        ✅ |      ✅ |
| Key Value                                |         ✅ |        ✅ |      ✅ |
| Key Wrapping Data                        |         ✅ |        ✅ |      ✅ |
| Key Wrapping Specification               |         ✅ |        ✅ |      ✅ |
| Transparent Key Structures               |         ✅ |        ✅ |      ✅ |
| Template-Attribute Structures            |         ✅ |        ✅ |      ✅ |
| Extension Information                    |         ✅ |        ✅ |      ✅ |
| Data                                     |         ❌ |        ❌ |      ❌ |
| Data Length                              |         ❌ |        ❌ |      ❌ |
| Signature Data                           |         ❌ |        ❌ |      ✅ |
| MAC Data                                 |         ❌ |        ❌ |      ✅ |
| Nonce                                    |         ✅ |        ✅ |      ✅ |
| Correlation Value                        |         ❌ |        ❌ |      ✅ |
| Init Indicator                           |         ❌ |        ❌ |      ✅ |
| Final Indicator                          |         ❌ |        ❌ |      ✅ |
| RNG Parameter                            |         ✅ |        ✅ |      ✅ |
| Profile Information                      |         ✅ |        ✅ |      ✅ |
| Validation Information                   |         ✅ |        ✅ |      ✅ |
| Capability Information                   |         ✅ |        ✅ |      ✅ |
| Authenticated Encryption Additional Data |         ✅ |        ✅ |      ✅ |
| Authenticated Encryption Tag             |         ✅ |        ✅ |      ✅ |

Notes:

- AEAD Additional Data and Tag are supported in encrypt/decrypt APIs.
- Nonce and RNG Parameter are used by symmetric encryption paths.

### Transparent Key Structures

| Structure                | 4.23–4.24 | 5.0–5.11 |
| ------------------------ | --------: | -------: |
| Symmetric Key            |         ✅ |        ✅ |
| DSA Private/Public Key   |         ❌ |        ❌ |
| RSA Private/Public Key   |         ✅ |        ✅ |
| DH Private/Public Key    |         ❌ |        ❌ |
| ECDSA Private/Public Key |         ✅ |        ✅ |
| ECDH Private/Public Key  |         ❌ |        ❌ |
| ECMQV Private/Public     |         ❌ |        ❌ |
| EC Private/Public        |         ✅ |        ✅ |

Note: EC/ECDSA support is present; DH/DSA/ECMQV are not implemented.

### Attributes

| Attribute                           | 4.23–4.24 | 5.0–5.4.1 | 5.5–5.5.1 | 5.6–5.7.1 | 5.8–5.10 | 5.11.0 |
| ----------------------------------- | --------: | --------: | --------: | --------: | -------: | -----: |
| Unique Identifier                   |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Name                                |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Object Type                         |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Algorithm             |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Length                |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Parameters            |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Cryptographic Domain Parameters     |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Certificate Type                    |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Certificate Identifier              |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Certificate Subject                 |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Certificate Issuer                  |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Digest                              |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Operation Policy Name               |         🚫 |         🚫 |         🚫 |         🚫 |        🚫 |      🚫 |
| Cryptographic Usage Mask            |         ✅ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Lease Time                          |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Usage Limits                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| State                               |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Initial Date                        |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Activation Date                     |         ✅ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Process Start Date                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Protect Stop Date                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Deactivation Date                   |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Destroy Date                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Compromise Occurrence Date          |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Compromise Date                     |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Revocation Reason                   |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Archive Date                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Object Group                        |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Link                                |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Application Specific Information    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Contact Information                 |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Last Change Date                    |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Custom Attribute (Vendor Attribute) |         ✅ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Certificate Length                  |         ✅ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| X.509 Certificate Identifier        |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| X.509 Certificate Subject           |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| X.509 Certificate Issuer            |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Digital Signature Algorithm         |         ❌ |         ❌ |         ❌ |         ❌ |        ✅ |      ✅ |
| Fresh                               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Alternative Name                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Key Value Present                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Key Value Location                  |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Original Creation Date              |         ❌ |         ❌ |         ❌ |         ✅ |        ✅ |      ✅ |
| Random Number Generator             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| PKCS#12 Friendly Name               |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Description                         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Comment                             |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |
| Sensitive                           |         ❌ |         ✅ |         ✅ |         ✅ |        ✅ |      ✅ |
| Always Sensitive                    |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Extractable                         |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ✅ |
| Never Extractable                   |         ❌ |         ❌ |         ❌ |         ❌ |        ❌ |      ❌ |

Notes:

- GetAttributes returns a union of metadata attributes and those embedded in KeyBlock structures.
- "Vendor Attributes" are available via the Cosmian vendor namespace and are accessible via GetAttributes.
- For the 5.x columns above, a ✅ indicates the attribute is used or updated by at least one KMIP operation implementation in `crate/server/src/core/operations`, explicitly excluding the attribute-only handlers (Add/Delete/Get/Set Attribute).
<!-- KMIP_SUPPORT_END -->

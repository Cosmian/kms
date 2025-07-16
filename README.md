# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/main.yml/badge.svg?branch=main)
![Build status](https://github.com/Cosmian/kms/actions/workflows/main_release.yml/badge.svg?branch=main)

The **Cosmian KMS** is a high-performance,
open-source [FIPS 140-3 compliant](./documentation/docs/fips.md) server application
written in [Rust](https://www.rust-lang.org/).

Online [documentation](https://docs.cosmian.com/key_management_system/)

![KMS WebUI](./documentation/docs/images/kms-ui.png)

The Cosmian KMS presents some unique features, such as:

- large-scale encryption and decryption of
  data [see this documentation](./documentation/docs/encrypting_and_decrypting_at_scale.md)
- the ability to confidentially run in a public cloud, or any zero-trust environment, using
  Cosmian VM. See our cloud-ready confidential KMS on the
  [Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/)
  our [deployment guide](documentation/docs/installation/marketplace_guide.md)
- support of state-of-the-art authentication mechanisms (see [authentication](./documentation/docs/authentication.md))
- out-of-the-box support of
  [Google Workspace Client Side Encryption (CSE)](./documentation/docs/google_cse/index.md)
- out-of-the-box support
  of [Microsoft Double Key Encryption (DKE)](./documentation/docs/ms_dke/index.md)
- support for the [Proteccio and Utimaco HSMs](./documentation/docs/hsms/index.md) with KMS keys wrapped by the HSM
- [Veracrypt](./documentation/docs/pkcs11/veracrypt.md)
  and [LUKS](./documentation/docs/pkcs11/luks.md) disk encryption support
- [FIPS 140-3](./documentation/docs/fips.md) mode gated behind the feature `fips`
- a [binary and JSON KMIP 1.0-1.4 and 2.0-2.1](./documentation/docs/kmip/index.md) compliant interface
- Oracle DB [TDE support](./documentation/docs/oracle/tde.md)
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

## Quick start

Pre-built binaries [are available](https://package.cosmian.com/kms/5.5.1/)
for Linux, MacOS, and Windows, as well as Docker images. To run the server binary, OpenSSL must be
available in your path (see "building the KMS" below for details); other binaries do not have this
requirement.

Using Docker to quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
inside the container, run the following command:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest
```

Then, use the CLI to issue commands to the KMS.
The CLI, called `cosmian`, can be either downloaded from [Cosmian packages](https://package.cosmian.com/kms/) or built
and
launched from this GitHub project by running

```sh
cargo run --bin cosmian --features non-fips -- --help
```

### Example

1. Create a 256-bit symmetric key

    ```sh
    ➜ cargo run --bin cosmian --features non-fips -- sym keys create --number-of-bits 256 --algorithm aes --tag my-key-file
    ...
    The symmetric key was successfully generated.
      Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e

      Tags:
        - my-key-file
    ```

2. Encrypt the `image.png` file with AES GCM using the key

    ```sh
    ➜ cargo run --bin cosmian --features non-fips -- sym encrypt --tag my-key-file --output-file image.enc image.png
    ...
    The encrypted file is available at "image.enc"
    ```

3. Decrypt the `image.enc` file using the key

    ```sh
    ➜ cargo run --bin cosmian --features non-fips -- sym decrypt --tag my-key-file --output-file image2.png image.enc
    ...
    The decrypted file is available at "image2.png"
    ```

See the [documentation](https://docs.cosmian.com/key_management_system/) for more.

## Repository content

The server is written in [Rust](https://www.rust-lang.org/) and is broken down into several
binaries:

- A server (`cosmian_kms`) which is the KMS itself
- A CLI (`cosmian`) to interact with this server

The most important crates are:

- `access` to handle permissions
- `client` to query the server
- `interfaces` to handle the interfaces with storage and encryption oracles
- `kmip`, which is an implementation of the KMIP standard
- `server_database` to handle the database
- `pkcs11_*` to handle PKCS11 support
- `test_kms_server`, a library that allows you to instantiate the KMS server programmatically.

**Please refer to the README files in the inner directories for more information.**

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

Build the server and CLI binaries:

```sh
cd crate/server
cargo build --release
cd ../..
cd crate/cli
cargo build --release
```

### Build the Docker Ubuntu container

You can build a Docker containing the KMS server as follows:

```sh
docker build . --network=host -t kms
```

Or:

```sh
# Example with FIPS support
docker build . --network=host \
               --build-arg FEATURES="--features=fips" \
               -t kms
```

## Running the unit and integration tests

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

To run benchmarks, go to the `crate/test_server` directory and run:

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

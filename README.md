# Cosmian CLI

![Build status](https://github.com/Cosmian/cli/actions/workflows/main_release.yml/badge.svg?branch=main)

Cosmian CLI (named `cosmian`) is the Command Line Interface to drive [KMS](https://github.com/Cosmian/kms) and [Findex server](https://github.com/Cosmian/findex-server).

Cosmian CLI provides a powerful interface to manage and secure your cryptographic keys and secrets using the [Cosmian Key Management System KMS](https://github.com/Cosmian/kms).
The KMS offers a high-performance, scalable solution with unique features such as confidential execution in zero-trust environments, compliance with KMIP 2.1, and support for various cryptographic algorithms and protocols.

Additionally, the CLI facilitates interaction with the [Findex server](https://github.com/Cosmian/findex-server), which implements Searchable Symmetric Encryption (SSE) via the [Findex protocol](https://github.com/Cosmian/findex). This allows for secure and efficient search operations over encrypted data, ensuring that sensitive information remains protected even during search queries.

By leveraging Cosmian CLI, users can seamlessly integrate advanced cryptographic functionalities and secure search capabilities into their applications, enhancing data security and privacy.

> [!NOTE]
> A graphical version of the CLI is also available as a separate tool called `cosmian_gui`.

## Installation

Please follow the installation instructions [here](./documentation/docs/installation.md).

Then you can run a Cosmian KMS server (using Docker image) on `http://localhost:9998` and use the CLI to issue commands to the KMS.
In that example, KMS stores its data inside the container:

```sh
docker run -p 9998:9998 --rm --name kms ghcr.io/cosmian/kms
```

> [!NOTE]
> The KMS server can also be installed using these [instructions](https://docs.cosmian.com/key_management_system/single_server_mode/#quick-start).

In the same manner, you can run a Findex server (using Docker image) on `http://localhost:6668`:

```sh
docker run -p 6668:6668 --rm --name kms ghcr.io/cosmian/findex-server
```

> [!NOTE]
> The Findex server can also be installed using these [instructions](./documentation/docs/installation.md).

### Example

1. Create a 256-bit symmetric key

   ```sh
   ➜ cosmian kms sym keys create --number-of-bits 256 --algorithm aes --tag my-key-file
   ...
   The symmetric key was successfully generated.
   Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e

   Tags:
      - my-key-file
   ```

2. Encrypt the `image.png` file with AES GCM using the key

   ```sh
   ➜ cosmian kms sym encrypt --tag my-key-file --output-file image.enc image.png
   ...
   The encrypted file is available at "image.enc"
   ```

3. Decrypt the `image.enc` file using the key

   ```sh
   ➜ cosmian kms sym decrypt --tag my-key-file --output-file image2.png image.enc
   ...
   The decrypted file is available at "image2.png"

   ...
   The decrypted file is available at "image2.png"
   ```

See the [documentation](https://docs.cosmian.com/key_management_system/) for more.

## [Configuration](./documentation/docs/configuration.md)

## Repository content

The server is written in [Rust](https://www.rust-lang.org/) and is broken down into several
binaries:

- The classic CLI (`cosmian_cli`)
- The graphical version of the CLI (`cosmian_gui`)

Find the [public documentation](https://docs.cosmian.com/cosmian_cli/) of the CLI in the `documentation`
directory.

## Building the CLI

OpenSSL v3.2.0 is required to build the KMS.

### Linux or MacOS (CPU Intel or MacOs ARM)

Retrieve OpenSSL v3.2.0 (already build) with the following commands:

```sh
export OPENSSL_DIR=/usr/local/openssl
sudo mkdir -p ${OPENSSL_DIR}
sudo chown -R $USER ${OPENSSL_DIR}
bash .github/scripts/get_openssl_binaries.sh
```

### Windows

1. Install Visual Studio Community with the C++ workload and clang support.
2. Install Strawberry Perl.
3. Install `vcpkg` following
   [these instructions](https://github.com/Microsoft/vcpkg#quick-start-windows)

4. Then install OpenSSL 3.2.0:

The file `vcpkg.json` is provided in the repository to install OpenSSL v3.2.0:

```powershell
vcpkg install --triplet x64-windows-static
vcpkg integrate install
$env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
```

### Build the CLI

Use `cargo`:

```sh
cargo build --release
```

## Running the unit and integration tests

By default, tests are run using `cargo test` which are using the KMS server and Findex server on Docker containers.

As a prerequisite, you need to have Docker installed (and docker compose plugin) on your machine and run in the root directory of the repository:

```sh
docker compose up -d
```

And then run the tests:

```sh
cargo test
```

Example: logs can be useful to debug:

```sh
RUST_LOG="cosmian_cli=trace,cosmian_findex_client=trace,cosmian_kmip=error,cosmian_kms_rest_client=info" cargo test
````

Alternatively, when writing a test or running a test from your IDE, the following can be inserted
at the top of the test:

```rust
unsafe {
set_var("RUST_LOG", "trace,cosmian_findex_client=trace,cosmian_kmip=error,cosmian_kms_rest_client=info");
set_var("RUST_BACKTRACE", "1");
}
log_init(None);
```

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/cli/).

# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/ci.yml/badge.svg?branch=main)

Cosmian KMS is an implementation of a high-performance, massively scalable, **Key
Management System** that presents some unique features, such as

- the ability to confidentially run in a public cloud — or any zero-trust environment — using
  Cosmian VM (see [Cosmian VM](https://docs.cosmian.com/compute/cosmian_vm/overview/))
  and application-level encryption
  (see [Redis-Findex](https://docs.cosmian.com/cosmian_key_management_system/replicated_mode/))
- a JSON KMIP 2.1 compliant interface
- support for object tagging to easily manage keys and secrets
- a full-featured command line and graphical
  interface ([CLI](https://docs.cosmian.com/cosmian_key_management_system/cli/cli/))
- Python, Javascript, Dart, Rust, C/C++, and Java clients (see the `cloudproof` libraries
  on [Cosmian Github](https://github.com/Cosmian))
- FIPS 140-2 mode gated behind the feature `fips`
- out-of-the-box support of
  [Google Workspace Client Side Encryption (CSE)](https://support.google.com/a/answer/14326936?fl=1&sjid=15335080317297331676-NA)
- out-of-the-box support
  of [Microsoft Double Key Encryption (DKE)](https://learn.microsoft.com/en-us/purview/double-key-encryption)
- [Veracrypt](https://veracrypt.fr/en/Home.html)
  and [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) disk encryption support

The KMS has extensive
online [documentation](https://docs.cosmian.com/cosmian_key_management_system/)

The KMS can manage keys and secrets used with a comprehensive list of common (AES, ECIES, ...) and
Cosmian advanced cryptographic stacks such as [Covercrypt](https://github.com/Cosmian/cover_crypt).
Keys can be wrapped and unwrapped using RSA, ECIES or RFC5649/AES KWP.

- [Cosmian KMS](#cosmian-kms)
  - [Quick start](#quick-start)
    - [Example](#example)
  - [Repository content](#repository-content)
  - [Building the KMS](#building-the-kms)
    - [Linux or MacOS (CPU Intel or MacOs ARM)](#linux-or-macos-cpu-intel-or-macos-arm)
    - [Windows](#windows)
    - [Build the KMS](#build-the-kms)
    - [Build the Docker Ubuntu container](#build-the-docker-ubuntu-container)
  - [Running the unit and integration tests](#running-the-unit-and-integration-tests)
  - [Development: running the server with cargo](#development-running-the-server-with-cargo)
  - [Setup as a `Supervisor` service](#setup-as-a-supervisor-service)
  - [Server parameters](#server-parameters)
  - [Use the KMS inside a Cosmian VM on SEV/TDX](#use-the-kms-inside-a-cosmian-vm-on-sevtdx)
  - [Releases](#releases)
  - [Benchmarks](#benchmarks)

## Quick start

Pre-built binaries [are available](https://package.cosmian.com/kms/4.19.3/)
for Linux, MacOS, and Windows, as well as Docker images. To run the server binary, OpenSSL must be
available in your path (see "building the KMS" below for details); other binaries do not have this
requirement.

Using Docker to quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
inside the container, run the following command:

```sh
docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.19.3
```

Then, use the CLI to issue commands to the KMS.
The CLI, called `ckms`, can be either downloaded from [Cosmian packages](https://package.cosmian.com/kms/) or built and launched from this GitHub project by running

```sh
cargo run --bin ckms -- --help
```

### Example

1. Create a 256-bit symmetric key

```sh
➜ cargo run --bin ckms -- sym keys create --number-of-bits 256 --algorithm aes --tag my-key-file
...
The symmetric key was successfully generated.
   Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e

  Tags:
    - my-key-file
```

2. Encrypt the `image.png` file with AES GCM using the key

```sh
➜ cargo run --bin ckms -- sym encrypt --tag my-key-file --output-file image.enc image.png
...
The encrypted file is available at "image.enc"
```

3. Decrypt the `image.enc` file using the key

```sh
➜ cargo run --bin ckms -- sym decrypt --tag my-key-file --output-file image2.png image.enc
...
The decrypted file is available at "image2.png"
```

See the [documentation](https://docs.cosmian.com/cosmian_key_management_system/) for more.

## Repository content

The server is written in [Rust](https://www.rust-lang.org/) and is broken down into several
binaries:

- A server (`cosmian_kms_server`) which is the KMS itself
- A CLI (`ckms`) to interact with this server

And also some libraries:

- `cosmian_kms_client` to query the server
- `cosmian_kmip` which is an implementation of the KMIP standard
- `cosmian_kms_pyo3` a KMS client in Python.

**Please refer to the README of the inner directories to have more information.**

Find the [public documentation](https://docs.cosmian.com) of the KMS in the `documentation`
directory.

## Building the KMS

OpenSSL v3.2.0 is required to build the KMS.

### Linux or MacOS (CPU Intel or MacOs ARM)

Build OpenSSL v3.2.0 with the following commands:

```sh
export OPENSSL_DIR=/usr/local/openssl
sudo mkdir -p ${OPENSSL_DIR}
sudo chown -R $USER ${OPENSSL_DIR}
bash .github/scripts/local_ossl_instl.sh ${OPENSSL_DIR}
```

### Windows

1. Install Visual Studio Community with the C++ workload and clang support.
2. Install Strawberry Perl.
3. Install `vcpkg` following
   [these instructions](https://github.com/Microsoft/vcpkg#quick-start-windows)

4. Then install OpenSSL 3.2.0:

The files `vcpkg.json` and `vcpkg_fips.json` are provided in the repository to install OpenSSL v3.2.0:

```powershell
vcpkg install --triplet x64-windows-static
vcpkg integrate install
$env:OPENSSL_DIR = "$env:VCPKG_INSTALLATION_ROOT\packages\openssl_x64-windows-static"
```

For a FIPS compliant build, use the following commands (in order to build fips.dll), run also:

```powershell
Copy-Item -Path "vcpkg_fips.json" -Destination "vcpkg.json"
vcpkg install
vcpkg integrate install
```

### Build the KMS

Once OpenSSL is installed, you can build the KMS. To avoid the _additive feature_ issues, the main artifacts - the CLI, the KMS server and the PKCS11 provider - should directly be built using `cargo build --release` within their own crate, not
from the project root.

Build the server and CLI binaries:

```sh
cd crate/server
cargo build --release
cd ../..
cd crate/ckms
cargo build --release
```

### Build the Docker Ubuntu container

You can build a docker containing the KMS server as follows:

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

By default, tests are run using `cargo test` and an SQLCipher backend (called `sqlite-enc`).
This can be influenced by setting the `KMS_TEST_DB` environment variable to

- `sqlite`, for plain SQLite
- `mysql` (requires a running MySQL or MariaDB server connected using a
  `"mysql://kms:kms@localhost:3306/kms"` URL)
- `postgresql`  (requires a running PostgreSQL server connected using
  a `"postgresql://kms:kms@127.0.0.1:5432/kms"`URL)
- `redis-findex` (requires a running Redis server connected using a
  `"redis://localhost:6379"` URL)

Example: testing with a plain SQLite and some logging

```sh
RUST_LOG="error,cosmian_kms_server=info,cosmian_kms_cli=info" KMS_TEST_DB=sqlite cargo test
````

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
log level and select the correct backend (which defaults to `sqlite-enc`).

```sh
RUST_LOG="info,cosmian_kms_server=debug" \
cargo run --bin cosmian_kms_server -- \
--database-type redis-findex --database-url redis://localhost:6379 \
--redis-master-password secret --redis-findex-label label
```

## Setup as a `Supervisor` service

Supervisor (A Process Control System) is a client/server system that allows its users to monitor and
control a number of processes on UNIX-like operating systems.

Concerning the KMS, copy the binary `target/release/cosmian_kms_server` to the remote machine folder
according to [cosmian_kms.ini](./resources/supervisor/cosmian_kms.ini) statement (i.e.:
`/usr/sbin/cosmian_kms_server`).

Copy the [cosmian_kms.ini](./resources/supervisor/cosmian_kms.ini) config file
as `/etc/supervisord.d/cosmian_kms.ini` in the remote machine.

Run:

```console
supervisorctl reload
supervisorctl start cosmian_kms
supervisorctl status cosmian_kms
```

## Server parameters

If a configuration file is provided, parameters are set following this order:

- conf file (env variable `COSMIAN_KMS_CONF` set by default to `/etc/cosmian_kms/kms.toml`)
- default (set on struct)

Otherwise, the parameters are set following this order:

- args in the command line
- env var
- default (set on struct)

## Use the KMS inside a Cosmian VM on SEV/TDX

See [this README](https://github.com/Cosmian/cosmian_vm) for more details about Cosmian VM.

To deploy the KMS inside a Cosmian VM, connect to the VM and follow these steps:

```console
# Copy from resources/supervisor/cosmian_kms.ini
$ sudo vi /etc/supervisord.d/cosmian_kms.ini

# Copy the KMS server binary
$ sudo cp some_location/cosmian_kms_server /usr/sbin/cosmian_kms

# Create a conf file for the KMS (from resources/server.toml)
# Instead of using default path `/etc/cosmian_kms/server.toml`,
# we are using a path within LUKS encrypted container
$ sudo vi /var/lib/cosmian_vm/data/app.conf
$ sudo export COSMIAN_KMS_CONF="/var/lib/cosmian_vm/data/app.conf"
$ sudo supervisorctl reload
$ sudo supervisorctl start cosmian_kms

# Check logs
$ sudo tail -f /var/log/cosmian_kms.err.log
$ sudo tail -f /var/log/cosmian_kms.out.log
```

Now you can interact with your KMS through the KMS CLI.

You can also interact with the Cosmian VM Agent through its own CLI as follows:

```console
# From your local machine
# Snapshot the VM (it could take a while)
$ ./cosmian_vm --url https://<DOMAIN_NAME>:<PORT> snapshot

# From time to time, verify it
$ ./cosmian_vm --url https://<DOMAIN_NAME>:<PORT> verify --snapshot ./cosmian_vm.snapshot
Reading the snapshot...
Fetching the collaterals...
[ OK ] Verifying TPM attestation
[ OK ] Verifying VM integrity (against N files)
[ OK ] Verifying TEE attestation
```

You can also provide the configuration file of the KMS through the Cosmian VM Agent and let it start
the KMS.

1. Check that the `/etc/supervisord.d/cosmian_kms.ini` contains the following line:
   `environment=COSMIAN_KMS_CONF=/var/lib/cosmian_vm/data/app.conf`
2. Add the following lines in `/etc/cosmian_vm/agent.toml`

```toml
[app]
service_type = "supervisor"
service_app_name = "cosmian_kms"
app_storage = "data/"
```

3. Provide the configuration (where `server.toml` is the configuration file of the KMS):

```console
$ ./cosmian_vm --url https://domain.name:port app init -c server.toml
Processing init of the deployed app...
The app has been configured
```

4. Save the printed key for further use
5. In case of reboot, you will need to restart the KMS manually by sending the configuration
   decryption key (the key saved at step 4):

```console
./cosmian_vm --url https://domain.name:port app restart --key 378f1f1b3b5cc92ed576edba265cc91de6872d61c00b0e01dba6d0ea80520820
```

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

# Cosmian KMS

![Build status](https://github.com/Cosmian/kms/actions/workflows/ci.yml/badge.svg?branch=main)

Cosmian KMS is an open-source implementation of a high-performance, massively scalable, **Key
Management System** that presents some unique features, such as

- the ability to run in a public cloud - or any zero-trust environment - using application-level
  encryption (
  see [Redis-Findex](https://docs.cosmian.com/cosmian_key_management_system/replicated_mode/))
- a JSON KMIP 2.1 compliant interface
- support for object tagging to easily manage keys and secrets
- a full-featured command line
  interface ([CLI](https://docs.cosmian.com/cosmian_key_management_system/cli/cli/))
- Python, Javascript, Dart, Rust, C/C++ and Java clients (see the `cloudproof` libraries
  on [Cosmian Github](https://github.com/Cosmian))
- FIPS 140-2 mode gated behind the feature `fips`
- support of Google Client Side Encryption (CSE)
- support of Microsoft Double Key Encryption (DKE)

It has extensive [documentation](https://docs.cosmian.com/cosmian_key_management_system/) and is
also available packaged as docker images (`docker pull ghcr.io/cosmian/kms`) to get you started
quickly.

The KMS can manage keys and secrets used with a comprehensive list of common (AES, ECIES, ...) and
Cosmian advanced cryptographic stacks such as [Covercrypt](https://github.com/Cosmian/cover_crypt).
Keys can be wrapped and unwrapped using ECIES or RFC5649.

## Table of contents

<!-- TOC -->

* [Cosmian KMS](#cosmian-kms)
    * [Table of contents](#table-of-contents)
    * [Repository content](#repository-content)
    * [Building the KMS](#building-the-kms)
        * [Linux](#linux)
        * [MacOS](#macos)
        * [Windows](#windows)
        * [Cargo build](#cargo-build)
        * [Build the Docker container](#build-the-docker-container)
    * [Releases](#releases)
    * [Setup as a `Supervisor` service](#setup-as-a-supervisor-service)
    * [Server parameters](#server-parameters)
    * [Use the KMS inside a Cosmian VM on SEV/TDX](#use-the-kms-inside-a-cosmian-vm-on-sevtdx)
    * [Use the KMS inside a Cosmian VM on SGX](#use-the-kms-inside-a-cosmian-vm-on-sgx)

<!-- TOC -->

## Repository content

The server is written in [Rust](https://www.rust-lang.org/) and is broken down into several
binaries:

- A server (`cosmian_kms_server`) which is the KMS itself
- A CLI (`ckms`) to interact with this server

And also some libraries:

- `cosmian_kms_client` to query the server
- `cosmian_kms_utils` to create KMIP requests for the crypto-systems designed by _Cosmian_
- `cosmian_kmip` which is an implementation of the KMIP standard
- `cosmian_kms_pyo3` a KMS client in Python.

**Please refer to the README of the inner directories to have more information.**

Find the [public documentation](https://docs.cosmian.com) of the KMS in the `documentation`
directory.

## Building the KMS

The KMS must be built against a local installation of OpenSSL 3. This is required to support FIPS
mode.

#### Linux

Unless you require a FIPS certified cryptographic module, the distribution provided OpenSSL should
be
sufficient and the builder should find it automatically.

#### MacOS

Install OpenSSL 3 with Homebrew:

```sh
brew install openssl@3
```

The builder should find it automatically; if not, you can set the `OPENSSL_DIR` environment variable
to the OpenSSL installation directory.

#### Windows

Install Visual Studio Community with the C++ workload and clang support.
Install perl from [Strawberry Perl](http://strawberryperl.com/).

Install `vcpkg` following
[these instructions](https://github.com/Microsoft/vcpkg#quick-start-windows)

Then install OpenSSL 3:

```powershell
vcpkg.exe install openssl[fips]
vcpkg.exe integrate install
set VCPKGRS_DYNAMIC=1
$env:OPENSSL_DIR="<vcpkg>\installed\<archi>>"
```

where `<vcpkg>` is the path to the vcpkg installation directory,
and `<archi>` is the architecture e.g `x64-windows`, `arm64-windows`, etc..

### Cargo build

```sh
cargo build --no-default-features
cargo test --no-default-features
```

### Build the Docker container

You can build a docker containing the KMS server as follow:

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

## Setup as a `Supervisor` service

Supervisor (A Process Control System) is a client/server system that allows its users to monitor and
control a number of processes on UNIX-like operating systems.

Concerning the KMS, copy the binary `target/release/cosmian_kms_server` to the remote machine folder
according to [cosmian_kms.ini](./resources/supervisor/cosmian_kms.ini) statement (
ie: `/usr/sbin/cosmian_kms_server`).

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

- conf file (env variable `COSMIAN_KMS_CONF` set by default to `/etc/cosmian_kms/server.toml`)
- default (set on struct)

Otherwise the parameters are set following this order:

- args in command line
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

You can also interact with the Cosmian VM Agent through its own CLI as follow:

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

## Use the KMS inside a Cosmian VM on SGX

Follow [this README](https://github.com/Cosmian/cosmian_vm/blob/main/resources/sgx/README.md) to
setup Cosmian VM tools.

In a nutshell, copy the KMS server binary (renamed as `app`) and the KMS server configuration file.
Edit `cosmian_vm.manifest.template` and replace the following line:

```jinja
    { path = "/etc/app/server.toml", uri = "file:etc/app/server.toml" },
```

by that one:

```jinja
    { path = "/etc/cosmian_kms/server.toml", uri = "file:etc/app/server.toml" },
```

Then run the entrypoint script.

The `etc/app/server.toml` file contains:

```toml
[http]
port = 3000
hostname = "0.0.0.0"

[workspace]
root_data_path = "/var/lib/app"
```

## GCP Images Correspondence

The GCP KMS images are based on GCP Cosmian VM images.

This table shows the minimum version correspondence between the various components.

| `Cosmian VM` | KMS    |
| ------------ | ------ |
| 1.1.0-rc1    | 4.13.3 |
| 1.1.0-rc2    | 4.13.4 |

## Releases

All releases can be found in the public URL [package.cosmian.com](https://package.cosmian.com/kms/).

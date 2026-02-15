# Cosmian KMS

The **Cosmian KMS** is a high-performance, [**source available**](https://github.com/Cosmian/kms), [**FIPS 140-3 compliant**](./fips.md) server application written in [**Rust**](https://www.rust-lang.org/) with unique capabilities.

## High-scale, secure encryption, anywhere

- **High-performance**: Delivers encryption and decryption services at up to **millions of operations per second**,
  with master keys held in a secure HSM-backed environment.
- **Flexible pricing**: Per-CPU pricing with no hidden costs, all connectors are included; deploying any number of
  servers.
- **Runs securely in public clouds**:  or zero-trust environments using Cosmian VMs available on [Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/). See our [deployment guide](installation/marketplace_guide.md).

## Standards' compliance

- [FIPS 140-3](./fips.md) mode
- KMIP support (versions 1.0-1.4, 2.0-2.1) in both binary and JSON formats - see [KMIP documentation](./kmip/index.md)
- [HSM support](./hsms/index.md) for Trustway Proteccio & Crypt2Pay, Utimaco general purpose, Nitrokey HSM 2, Smartcard HSMs, etc. with KMS keys wrapped by the HSM
- Developed in Rust, a memory safe language, with the source code available on [GitHub](https://github.com/Cosmian/kms)
- 100% developed in the European Union

## Modern technology

- [Source Available](https://github.com/Cosmian/kms) server application written in [Rust](https://www.rust-lang.org/)
- Full-featured [Web UI](#user-interface) with client [command line and graphical interface](../cosmian_cli/index.md)
- Advanced [authentication mechanisms](./authentication.md)
- [High-availability mode](installation/high_availability_mode.md) with simple horizontal scaling
- Multi-language client support: Python, JavaScript, Dart, Rust, C/C++, and Java (see the `cloudproof` libraries on [Cosmian GitHub](https://github.com/Cosmian))
- Advanced logging with [OpenTelemetry](https://opentelemetry.io/)

## Integrations

- **Cloud integrations**:
    - [Azure BYOK](./azure/byok.md)
    - [GCP CSEK](./google_gcp/csek.md) and [Google CMEK](./google_gcp/cmek.md)
    - ...
- **Workplace security**:
    - [Google Workspace Client Side Encryption (CSE)](./google_cse/index.md)
    - [Microsoft 365 Double Key Encryption (DKE)](./ms_dke/index.md)
- **Transparent data encryption**:
    - [Veracrypt](../cosmian_cli/pkcs11/veracrypt.md)
    - [LUKS](../cosmian_cli/pkcs11/luks.md)
    - [VMware](./vcenter.md)
    - [Oracle Database TDE](../cosmian_cli/pkcs11/oracle/tde.md),
    - [MongoDB](./mongodb.md),
    - [Mysql Enterprise](./mysql.md)
    - [PostgreSQL](./percona.md)
    - and more
- **Big Data encryption**:
    - [Snowflake](./snowflake/index.md)
    - [Databricks, Spark,..  UDFs](./python_udf/index.md)

## Three-in-one: Key lifecycle management + Encryption oracle + Public key infrastructure

The **Cosmian KMS** combines the functions of a Key Management System, an Encryption Oracle, and a Public Key
Infrastructure:

- **Key Management System**: Manages the full key lifecycle, including on-the-fly generation and revocation, including for [connected HSMs](./hsms/index.md).
- **Encryption Oracle**: Provides high-availability, high-scalability encryption and decryption operations at **millions of operations per second** with [HSM-backed security](./hsms/index.md).
- **PKI**: Manages root and intermediate certificates, signs and verifies certificates, and uses public keys for encryption/decryption. Certificates can be exported in various formats (including _PKCS#12_) for applications like
  _S/MIME_ encrypted emails.

The **Cosmian KMS** supports all standard NIST cryptographic algorithms as well as advanced post-quantum cryptography algorithms like [Covercrypt](https://github.com/Cosmian/cover_crypt).
See the complete [supported algorithms list](./algorithms.md).

## Deployment options

The **Cosmian KMS** is available as:

- Linux packages: [Debian](https://package.cosmian.com/kms/5.16.0/debian/) or [RPM](https://package.cosmian.com/kms/5.16.0/rpm/)
- Windows installer: [Windows](https://package.cosmian.com/kms/5.16.0/windows/)
- macOS installer: [macOS](https://package.cosmian.com/kms/5.16.0/dmg/)
- Docker: [Standard image](https://github.com/Cosmian/kms/pkgs/container/kms) and [FIPS image](https://github.com/Cosmian/kms/pkgs/container/kms)

## User Interface

The **Cosmian KMS** includes an intuitive graphical user interface (GUI) with support for client certificate and OIDC
token authentication.

![Cosmian KMS UI](./images/kms-ui.png)

## Client CLI

The [Cosmian CLI](../cosmian_cli/index.md) provides a powerful command-line interface for managing the server, handling keys, and performing encryption/decryption operations. It features integrated help and is available for multiple operating systems.

The **[Cosmian CLI](../cosmian_cli/index.md)** is packaged as:

- [Debian](https://package.cosmian.com/kms/5.16.0/ubuntu-22.04/) or [RPM](https://package.cosmian.com/kms/5.16.0/rockylinux9/) package
- [Pre-built binaries](https://package.cosmian.com/cli/) for Linux, Windows, and macOS

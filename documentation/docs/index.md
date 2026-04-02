# Cosmian KMS

The **Cosmian KMS** is a high-performance, [**source available**](https://github.com/Cosmian/kms), [**FIPS 140-3 compliant**](./certifications_and_compliance/fips.md) server application written in [**Rust**](https://www.rust-lang.org/) with unique capabilities.

## High-scale, secure encryption, anywhere

- **High-performance**: Delivers encryption and decryption services at up to **millions of operations per second**,
  with master keys held in a secure HSM-backed environment.
- **Flexible pricing**: Per-CPU pricing with no hidden costs, all connectors are included; deploying any number of
  servers.
- **Runs securely in public clouds**:  or zero-trust environments using Cosmian VMs available on [Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/). See our [deployment guide](installation/marketplace_guide.md).

## Standards' compliance

- [FIPS 140-3](./certifications_and_compliance/fips.md) mode
- KMIP support (versions 1.0-1.4, 2.0-2.1) in both binary and JSON formats - see [KMIP documentation](./kmip_support/introduction/index.md).
- [HSM support](./hsm_support/introduction/index.md) for Trustway Proteccio & Crypt2Pay, Utimaco general purpose, Nitrokey HSM 2, Smartcard HSMs, etc. with KMS keys wrapped by the HSM.
- Developed in Rust, a memory safe language, with the source code available on [GitHub](https://github.com/Cosmian/kms).
- 100% developed in the European Union.

## Modern technology

- [Source Available](https://github.com/Cosmian/kms) server application written in [Rust](https://www.rust-lang.org/)
- Full-featured [Web UI](#user-interface) with client [command line and graphical interface](../kms_clients/index.md)
- Advanced [authentication mechanisms](./configuration/authentication.md)
- [High-availability mode](installation/high_availability_mode.md) with simple horizontal scaling
- Multi-language client support: Python, JavaScript, Dart, Rust, C/C++, and Java (see the `cloudproof` libraries on [Cosmian GitHub](https://github.com/Cosmian))
- Advanced logging with [OpenTelemetry](https://opentelemetry.io/)

## Integrations

- **Cloud integrations**:
    - [Azure BYOK](./integrations/cloud_providers/azure/byok.md)
    - [GCP CSEK](./integrations/cloud_providers/google_gcp/csek.md) and [Google CMEK](./integrations/cloud_providers/google_gcp/cmek.md)
    - [AWS BYOK](./integrations/cloud_providers/aws/byok.md) and [AWS Fargate](./integrations/cloud_providers/aws/fargate.md)
    - ...
- **Workplace security**:
    - [Google Workspace Client Side Encryption (CSE)](./integrations/cloud_providers/google_workspace_client_side_encryption_cse/getting_started/index.md)
    - [Microsoft 365 Double Key Encryption (DKE)](./integrations/cloud_providers/microsoft_365_double_key_encryption_dke/index.md)
- **Transparent data encryption**:
    - [Veracrypt](./integrations/disk_encryption/veracrypt.md)
    - [LUKS](./integrations/disk_encryption/luks.md)
        - [VMware](./integrations/vcenter.md)
    - [Oracle Database TDE](./integrations/databases/oracle_tde.md)
    - [MongoDB](./integrations/databases/mongodb.md)
    - [Mysql Enterprise](./integrations/databases/mysql.md)
    - [Microsoft SQL Server External (EKM)](./integrations/databases/ms_sql_server.md)
    - [PostgreSQL](./integrations/databases/percona.md)
    - [OpenSSH](./integrations/openssh.md)
        - and more
- **Big Data encryption**:
    - [Snowflake](./integrations/databases/snowflake_native_app/index.md)
        - [Databricks, Spark,..  UDFs](./integrations/user_defined_function_for_pyspark_databricks_in_python/index.md)

## Three-in-one: Key lifecycle management + Encryption oracle + Public key infrastructure

The **Cosmian KMS** combines the functions of a Key Management System, an Encryption Oracle, and a Public Key
Infrastructure:

- **Key Management System**: Manages the full key lifecycle, including on-the-fly generation and revocation, including for [connected HSMs](./hsm_support/introduction/index.md).
- **Encryption Oracle**: Provides high-availability, high-scalability encryption and decryption operations at **millions of operations per second** with [HSM-backed security](./hsm_support/introduction/index.md).
- **PKI**: Manages root and intermediate certificates, signs and verifies certificates, and uses public keys for encryption/decryption. Certificates can be exported in various formats (including _PKCS#12_) for applications like
  _S/MIME_ encrypted emails.

The **Cosmian KMS** supports all standard NIST cryptographic algorithms as well as advanced post-quantum cryptography algorithms like [Covercrypt](https://github.com/Cosmian/cover_crypt).
See the complete [supported algorithms list](./certifications_and_compliance/cryptographic_algorithms/algorithms.md).

## Deployment options

The **Cosmian KMS** is available as:

- Linux packages: [Debian](https://package.cosmian.com/kms/5.19.0/debian/) or [RPM](https://package.cosmian.com/kms/5.19.0/rpm/)
- Windows installer: [Windows](https://package.cosmian.com/kms/5.19.0/windows/)
- macOS installer: [macOS](https://package.cosmian.com/kms/5.19.0/dmg/)
- Docker: [Standard image](https://github.com/Cosmian/kms/pkgs/container/kms) and [FIPS image](https://github.com/Cosmian/kms/pkgs/container/kms)

## User Interface

The **Cosmian KMS** includes an intuitive graphical user interface (GUI) with support for client certificate and OIDC
token authentication.

![Cosmian KMS UI](./images/kms-ui.png)

The UI can be [fully customized](./configuration/ui_branding.md) to match your organization's branding.

## Client CLI

The [KMS CLI](../kms_clients/index.md) provides a powerful command-line interface for managing the server, handling keys, and performing encryption/decryption operations. It features integrated help and is available for multiple operating systems.

The **[KMS CLI](../kms_clients/index.md)** is packaged as:

- [Debian](https://package.cosmian.com/kms/5.19.0/ubuntu-22.04/) or [RPM](https://package.cosmian.com/kms/5.19.0/rockylinux9/) package
- [Pre-built binaries](https://package.cosmian.com/kms/) for Linux, Windows, and macOS

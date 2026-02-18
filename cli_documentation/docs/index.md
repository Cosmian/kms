# Cosmian Command Line Interface (CLI)

Cosmian CLI is the Command Line Interface to drive [KMS](https://github.com/Cosmian/kms) and [Findex server](https://github.com/Cosmian/findex-server).

Cosmian CLI provides a powerful interface to manage and secure your cryptographic keys and secrets using the [Cosmian Key Management System KMS](https://github.com/Cosmian/kms).
The KMS offers a high-performance, scalable solution with unique features such as confidential execution in zero-trust environments, compliance with KMIP 2.1, and support for various cryptographic algorithms and protocols.

Additionally, the CLI facilitates interaction with the [Findex server](https://github.com/Cosmian/findex-server), which implements Searchable Symmetric Encryption (SSE) via the [Findex protocol](https://github.com/Cosmian/findex). This allows for secure and efficient search operations over encrypted data, ensuring that sensitive information remains protected even during search queries.

Beyond the CLI interface, Cosmian also provides a **PKCS#11 library** (`libcosmian_pkcs11.so`) that enables seamless integration with existing cryptographic infrastructure. This library acts as a bridge between applications requiring PKCS#11 interfaces and the Cosmian KMS, providing:

- **Database Encryption Support**: Integration with Oracle Database Transparent Data Encryption ([TDE](./pkcs11/oracle/tde.md)) for automatic encryption of data at rest, either through Oracle Key Vault or direct HSM communication
- **Disk Encryption Support**: Compatible with popular disk encryption solutions including [VeraCrypt](./pkcs11/veracrypt.md), [LUKS](./pkcs11/luks.md), and [Cryhod](./pkcs11/cryhod.md) for protecting data on storage devices

The PKCS#11 library enables organizations to leverage Cosmian's advanced cryptographic capabilities while maintaining compatibility with their existing security infrastructure and workflows.

By leveraging Cosmian CLI, users can seamlessly integrate advanced cryptographic functionalities and secure search capabilities into their applications, enhancing data security and privacy.

!!! important
    A Web UI version of the CLI is also available when installing the KMS server.

- [Cosmian Command Line Interface (CLI)](#cosmian-command-line-interface-cli)
    - [Version correspondence](#version-correspondence)
    - [Configuration](#configuration)
    - [Usage](#usage)

!!! info "Download cosmian"

    Please download the latest versions for your Operating System from
    the [Cosmian public packages repository](https://package.cosmian.com/cli/5.16.1/)
    See below for installation instructions.

## Version correspondence

!!! warning
    The versions of the CLI, KMS, and Findex server must be compatible.
    The following table shows the compatibility between the versions:

| CLI version | KMS version      | Findex server version |
| ----------- | ---------------- | --------------------- |
| 1.9.*       | 5.16.1           | 0.4.14                |
| 1.9.*       | 5.16.0           | 0.4.13                |
| 1.8.*       | 5.15.0           | 0.4.12                |
| 1.8.0       | 5.14.1           | 0.4.11                |
| 1.7.0       | 5.14.0           | 0.4.10                |
| 1.6.0       | 5.13.*           | 0.4.*                 |
| 1.5.2       | 5.12.*           | 0.4.*                 |
| 1.5.1       | 5.11.*           | 0.4.*                 |
| 1.5.0       | 5.10.*           | 0.4.*                 |
| 1.4.1       | 5.9.*            | 0.4.*                 |
| 1.4.0       | 5.8.*            | 0.4.*                 |
| 1.3.0       | 5.7.*            | 0.4.*                 |
| 1.2.0       | 5.6.*            | 0.4.*                 |
| 1.1.0       | 5.6.*            | 0.3.0                 |
| 0.4.1       | 5.1.*            | 0.3.0                 |
| 0.4.0       | 5.0.*            | 0.3.0                 |
| 0.3.1       | 4.24.*           | 0.3.0                 |
| 0.3.0       | 4.23.*           | 0.3.0                 |
| 0.2.0       | 4.22.*           | 0.2.0                 |
| 0.1.*       | 4.20.\*, 4.21.\* | 0.1.0                 |

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `installation.md` -->
{!../cli/documentation/docs/installation.md!}

## Configuration

To communicate with KMS and Findex server, the clients `cosmian` expect the same configuration file. Please read the [configuration](./configuration.md) section.

## Usage

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `usage.md` -->
{!../cli/documentation/docs/usage.md!}

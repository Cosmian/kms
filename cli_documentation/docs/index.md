# Cosmian Command Line Interface (CLI)

KMS CLI is the Command Line Interface to drive [KMS](https://github.com/Cosmian/kms).

KMS CLI provides a powerful interface to manage and secure your cryptographic keys and secrets using the [Cosmian Key Management System KMS](https://github.com/Cosmian/kms).
The KMS offers a high-performance, scalable solution with unique features such as confidential execution in zero-trust environments, compliance with KMIP 2.1, and support for various cryptographic algorithms and protocols.

Beyond the CLI interface, Cosmian also provides a **PKCS#11 library** (`libcosmian_pkcs11.so`) that enables seamless integration with existing cryptographic infrastructure. This library acts as a bridge between applications requiring PKCS#11 interfaces and the Cosmian KMS, providing:

- **Database Encryption Support**: Integration with Oracle Database Transparent Data Encryption ([TDE](./pkcs11/oracle/tde.md)) for automatic encryption of data at rest, either through Oracle Key Vault or direct HSM communication
- **Disk Encryption Support**: Compatible with popular disk encryption solutions including [VeraCrypt](./pkcs11/veracrypt.md), [LUKS](./pkcs11/luks.md), and [Cryhod](./pkcs11/cryhod.md) for protecting data on storage devices

The PKCS#11 library enables organizations to leverage Cosmian's advanced cryptographic capabilities while maintaining compatibility with their existing security infrastructure and workflows.

By leveraging KMS CLI, users can seamlessly integrate advanced cryptographic functionalities and secure search capabilities into their applications, enhancing data security and privacy.

!!! important
    A Web UI version of the CLI is also available when installing the KMS server.

[TOC]

!!! info Download cosmian

    Please download the latest versions for your Operating System from
    the [Cosmian public packages repository](https://package.cosmian.com/kms/5.16.2/)
    See below for installation instructions.

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `installation.md` -->
{!../cli_documentation/docs/installation.md!}

## Configuration

To communicate with the KMS, the clients `cosmian` expect the same configuration file. Please read the [configuration](./configuration.md) section.

## Usage

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `usage.md` -->
{!../cli_documentation/docs/usage.md!}

# Cosmian Command Line Interface (CLI)

Cosmian CLI is the Command Line Interface to drive [KMS](https://github.com/Cosmian/kms) and [Findex server](https://github.com/Cosmian/findex-server).

Cosmian CLI provides a powerful interface to manage and secure your cryptographic keys and secrets using the [Cosmian Key Management System KMS](https://github.com/Cosmian/kms).
The KMS offers a high-performance, scalable solution with unique features such as confidential execution in zero-trust environments, compliance with KMIP 2.1, and support for various cryptographic algorithms and protocols.

Additionally, the CLI facilitates interaction with the [Findex server](https://github.com/Cosmian/findex-server), which implements Searchable Symmetric Encryption (SSE) via the [Findex protocol](https://github.com/Cosmian/findex). This allows for secure and efficient search operations over encrypted data, ensuring that sensitive information remains protected even during search queries.

By leveraging Cosmian CLI, users can seamlessly integrate advanced cryptographic functionalities and secure search capabilities into their applications, enhancing data security and privacy.

!!! important
    A graphical version of the CLI is also available as a separate tool called `cosmian_gui`.

- [Cosmian Command Line Interface (CLI)](#cosmian-command-line-interface-cli)
  - [Version correspondence](#version-correspondence)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [KMS objects access rights](#kms-objects-access-rights)
  - [Usage](#usage)

!!! info "Download cosmian and cosmian_gui"

    Please download the latest versions for your Operating System from
    the [Cosmian public packages repository](https://package.cosmian.com/cli/0.2.0/)
    See below for installation instructions.

## Version correspondence

!!! warning
    The versions of the CLI, KMS, and Findex server must be compatible.
    The following table shows the compatibility between the versions:

| CLI version | KMS version   | Findex server version |
| ----------- | ------------- | --------------------- |
| 0.1.*       | 4,20,*,4.21.* | 0.1.0                 |
| 0.2.0       | 4.22.*        | 0.2.0                 |

## Installation

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `installation.md` -->
{!../cli/documentation/docs/installation.md!}

## Configuration

To communicate with KMS and Findex server, the clients `cosmian` and `cosmian_gui` expect the same configuration file. Please read the [configuration](./configuration.md) section.

## KMS objects access rights

When [authentication](./authentication.md) is enabled, each KMS object requires explicit authorization from its owner to be accessed or used by others.
The Cosmian CLI then [allows to manage the access rights](./authorization.md) of users to cryptographic objects stored in the KMS.

## Usage

<!-- Warning: this doc is merged with `mkdocs merge` in the repository `public_documentation`. -->
<!-- To test locally, test with path `usage.md` -->
{!../cli/documentation/docs/usage.md!}

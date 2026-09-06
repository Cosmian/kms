# Cosmian Command Line Interface (CLI)

KMS CLI is the Command Line Interface to drive [KMS](https://github.com/Cosmian/kms).

KMS CLI provides a powerful interface to manage and secure your cryptographic keys and secrets using the [Cosmian Key Management System KMS](https://github.com/Cosmian/kms).
The KMS offers a high-performance, scalable solution with unique features such as confidential execution in zero-trust environments, compliance with KMIP 2.1, and support for various cryptographic algorithms and protocols.

Beyond the CLI interface, Cosmian also provides a **PKCS#11 library** (`libcosmian_pkcs11.so`) that enables seamless integration with existing cryptographic infrastructure. This library acts as a bridge between applications requiring PKCS#11 interfaces and the Eviden KMS, providing:

- **Database Encryption Support**: Integration with Oracle Database Transparent Data Encryption ([TDE](../integrations/databases/oracle_tde.md)) for automatic encryption of data at rest, either through Oracle Key Vault or direct HSM communication
- **Disk Encryption Support**: Compatible with popular disk encryption solutions including [VeraCrypt](../integrations/disk_encryption/veracrypt.md), [LUKS](../integrations/disk_encryption/luks.md), and [Cryhod](../integrations/disk_encryption/cryhod.md) for protecting data on storage devices

The PKCS#11 library enables organizations to leverage Cosmian's advanced cryptographic capabilities while maintaining compatibility with their existing security infrastructure and workflows.

By leveraging KMS CLI, users can seamlessly integrate advanced cryptographic functionalities and secure search capabilities into their applications, enhancing data security and privacy.

!!! info Download cosmian

    Please download the latest versions for your Operating System from
    the [Cosmian public packages repository](https://package.cosmian.com/kms/5.27.0/)
    See below for installation instructions.

<!-- Warning: this doc is merged in the repository `public_documentation`. -->
{!kms_clients/installation.md!}

## Configuration

To communicate with the KMS, the client `ckms` reads a TOML configuration file at
`~/.cosmian/ckms.toml` (or the path set by `CKMS_CONF`).

The fastest way to create or update this file is the built-in interactive wizard:

```bash
ckms configure
```

The wizard prompts for the KMS server URL, the authentication method (access token,
client certificate in PEM or PKCS#12 format, or both), and optional proxy settings,
then writes the result to `~/.cosmian/ckms.toml`.

For a full description of all authentication methods and the manual configuration format,
see the [CLI authentication guide](./authentication.md).

<!-- Warning: this doc is merged in the repository `public_documentation`. -->
{!kms_clients/usage.md!}

## Web UI

The KMS server ships with a built-in **browser-based client** that covers the same operations as the `ckms` CLI. It is available at:

```plaintext
https://YOUR_KMS_URL/ui
```

No installation is required — the UI is served directly by the KMS server.

**Authentication** is handled automatically: the UI detects the server's configured method and adapts its login flow accordingly:

- **OIDC / JWT**: a **LOGIN** button redirects to the identity provider.
- **mTLS (client certificate)**: the browser negotiates the TLS handshake using a certificate installed in the system or browser store. No extra configuration is needed on the client side.
- **No authentication**: direct access, with a warning banner indicating that the server is unsecured.

For server-side configuration and browser certificate installation steps, see the [KMS User Interface configuration guide](../configuration/ui.md).

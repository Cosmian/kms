# Usage

```sh
CLI used to manage the Cosmian KMS.

Usage: cosmian [OPTIONS] <COMMAND>

Commands:
  kms   Handle KMS actions
  help  Print this message or the help of the given subcommand(s)

Options:
  -c, --conf-path <CONF_PATH>    Configuration file location [env: CKMS_CONF_PATH=]
      --kms-url <KMS_URL>        The URL of the KMS [env: KMS_DEFAULT_URL=]
      --kms-accept-invalid-certs Allow to connect using a self-signed cert or untrusted cert chain
      --kms-print-json           Output the KMS JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint
  -h, --help                     Print help (see more with '--help')
  -V, --version                  Print version
```

## KMS commands

```sh
Handle KMS actions

Usage: ckms <COMMAND>

Commands:
  access-rights   Manage the users' access rights to the cryptographic objects
  attributes      Get/Set/Delete the KMIP object attributes
  cc              Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data
  certificates    Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
  ec              Manage elliptic curve keys. Encrypt and decrypt data using ECIES
  google          Manage google elements. Handle key pairs and identities from Gmail API
  locate          Locate cryptographic objects inside the KMS
  login           Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.
  logout          Logout from the Identity Provider.
  new-database    Initialize a new user encrypted database and return the secret (`SQLCipher` only).
  rsa             Manage RSA keys. Encrypt and decrypt data using RSA keys
  server-version  Print the version of the server
  sym             Manage symmetric keys. Encrypt and decrypt data
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

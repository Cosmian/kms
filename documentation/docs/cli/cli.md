# Cosmian KMS CLI Documentation

The Cosmian Key Management System (KMS) is a command line interface (CLI) used to manage cryptographic objects inside the KMS.

## Installing

Please download the latest version of the CLI for your OS from the [releases page]

## Configuration

The CLI expects a configuration file to be located at `~/.cosmian/kms.json` where `~` is you home folder.

The configuration file is created automatically when the CLI is used for the first time with the following values 
```json
{
  "kms_server_url": "http://localhost:9998",
}
```
The configuration file should be edited manually to reflect the actual configuration of the KMS.

 - `kms_server_url` is MANDATORY and is the URL of the KMS server
 - `kms_access_token` is OPTIONAL and is the access token used to authenticate to the KMS server. If the server runs without authentication, you can let `kms_access_token` be an empty string.
 - `ssl_client_pkcs12_path`: is OPTIONAL and is the path to the PKCS12 file containing the client certificate and private key to use when authenticating to a KMS using a certificate.
  - `ssl_client_pkcs12_password`: is OPTIONAL and is the password to use to open the PKCS12 file when authenticating to a KMS using a certificate.
 - `kms_database_secret` is OPTIONAL and is the base 64 encoded secret to use when connecting to a KMS using an encrypted database
 - `accept_invalid_certs` is OPTIONAL and should be set to "true" to allow the CLI to connect to a KMS using an "invalid" certificate such as a self-signed SSL certificate. For instance, it could be the case when running tests with the on-premise version.


## Main commands

```
ckms <COMMAND>
```


### [cc](covercrypt/covercrypt.md)

Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data.

```
ckms cc [SUBCOMMAND]
```

**subcommands:**
```
keys     Create, destroy, import, export CoverCrypt master and user keys
policy   Extract or view policies of existing keys, 
           and create a binary policy from specifications
rotate   Rotate attributes and rekey the master and user keys.
encrypt  Encrypt a file using Covercrypt
decrypt  Decrypt a file using Covercrypt
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](covercrypt/covercrypt.md)

### [ec](ec/ec.md)

Manage elliptic curve keys and policies. Encrypt and decrypt data.

```
ckms ec [SUBCOMMAND]
```

**subcommands:**
```
keys     Create, destroy, import, export elliptic curve key pairs
encrypt  Encrypt a file with the given public key using ECIES
decrypt  Decrypts a file with the given private key using ECIES
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](ec/ec.md)

### [sym](sym/sym.md)

Manage symmetric keys and salts. Encrypt and decrypt data.

```
ckms sym [SUBCOMMAND]
```

**subcommands:**
```
keys     Create, destroy, import, and export symmetric keys
encrypt  Encrypt a file using AES GCM
decrypt  Decrypts a file using AES GCM
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](sym/sym.md)

### [permission](./permissions.md)

Manage the permission of objects.

```
ckms permission [SUBCOMMAND]
```

### [trust](./enclaves.md)

Query the enclave to check its trustworthiness.

```
ckms trust
```

### [configure](./enclaves.md)

Query the KMS to initialize a new database (enclave mode only).

```
ckms configure
```

### help

Print the help message or the help of the given subcommand(s).

```
ckms help [SUBCOMMAND]
```


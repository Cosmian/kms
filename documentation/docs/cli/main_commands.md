The `ckms` client expects command with parameters and optional options.

```sh
ckms <COMMAND>
```

At any time the online help for the CLI or a `COMMAND`, can be displayed using the `--help` option.

```sh
> ckms --help
*
CLI used to manage the Cosmian KMS.

Usage: ckms <COMMAND>

Commands:
  access-rights    Manage the users' access rights to the cryptographic objects
  bootstrap-start  Provide configuration and start the KMS server via the bootstrap server.
  cc               Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data
  certificates     Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
  ec               Manage elliptic curve keys. Encrypt and decrypt data using ECIES
  locate           Locate cryptographic objects inside the KMS
  new-database     Initialize a new user encrypted database and return the secret (`SQLCipher` only).
  server-version   Print the version of the server
  sym              Manage symmetric keys and salts. Encrypt and decrypt data
  verify           Query the KMS to check its trustworthiness. Validate the TLS certificate to use in any further queries
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### [access-rights](./access_rights.md)

Manage the users' access rights to the cryptographic objects.

```sh
ckms access-rights [SUBCOMMAND]
```

**subcommands:**

```sh
grant     Grant another user an access right to an object
revoke    Revoke another user access right to an object
list      List the access rights granted on an object to other users
owned     List the objects owned by the calling user
obtained  List the access rights obtained by the calling user
help      Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./access_rights.md)

### bootstrap-start

Configure and start a KMS server configured in [bootstrap mode](../bootstrap.md).

To contact the bootstrap server, `ckms` uses the `bootstrap_server_url` value configured in the `~/.cosmian/kms.json` configuration file. If the URL is not specified, the `kms_server_url` is used, replacing `http` with `https` if need be.

A database must be configured for for the KMS server to launch. If no PKCS#12 file is provided, the KMS server will start in HTTP mode.

**Usage:**

```sh
ckms bootstrap-start [OPTIONS]
```

**Options:**

```sh
--database-type <DATABASE_TYPE>
    The database type of the KMS server:
    - postgresql: PostgreSQL. The database url must be provided
    - mysql: MySql or MariaDB. The database url must be provided
    - sqlite: SQLite. The data will be stored at the sqlite_path directory
    - sqlite-enc: SQLite encrypted at rest. The data will be stored at the sqlite_path directory.
    A key must be supplied on every call
    - redis-findex: and redis database with encrypted data and encrypted indexes thanks to Findex.
    The Redis database url must be provided, as well as the redis-master-password and the redis-findex-label
    _

    [possible values: postgresql, mysql, sqlite, sqlite-enc, redis-findex]

--database-url <DATABASE_URL>
    The url of the database for postgresql, mysql or findex-redis

--sqlite-path <SQLITE_PATH>
    The directory path of the sqlite or sqlite-enc

    [default: ./sqlite-data]

--redis-master-password <REDIS_MASTER_PASSWORD>
    redis-findex: a master password used to encrypt the Redis data and indexes

--redis-findex-label <REDIS_FINDEX_LABEL>
    redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key

--clear-database
    Clear the database on start.
    WARNING: This will delete ALL the data in the database

--https-p12-file <HTTPS_P12_FILE>
    The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode

--https-p12-password <HTTPS_P12_PASSWORD>
    The password to open the PKCS#12 Certificates and Key file if not an empty string

    [default: ]
```

### [cc](covercrypt/covercrypt.md)

Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data.

```sh
ckms cc [SUBCOMMAND]
```

**subcommands:**

```sh
keys     Create, destroy, import, export Covercrypt master and user keys
policy   Extract or view policies of existing keys, and create a binary policy from specifications
rotate   Rotate attributes and rekey the master and user keys.
encrypt  Encrypt a file using Covercrypt
decrypt  Decrypt a file using Covercrypt
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](covercrypt/covercrypt.md)

### [certificates](certificates/certificates.md)

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

```sh
ckms certificates [SUBCOMMAND]
```

**subcommands:**

```sh
create   Create a new certificate
decrypt  Decrypt a file using the private key of a certificate
encrypt  Encrypt a file using the certificate public key
export   Export a certificate from the KMS
import   Import a certificate or a private/public keys the KMS.
revoke   Revoke a certificate
destroy  Destroy a certificate
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](certificates/certificates.md)

### [ec](ec/ec.md)

Manage elliptic curve keys and policies. Encrypt and decrypt data.

```sh
ckms ec [SUBCOMMAND]
```

**subcommands:**

```sh
keys     Create, destroy, import, and export elliptic curve key pairs
encrypt  Encrypt a file with the given public key using ECIES
decrypt  Decrypts a file with the given private key using ECIES
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](ec/ec.md)

### locate

Locate cryptographic objects inside the KMS

**Usage:**

```sh
ckms locate [OPTIONS]
```

**Options:**

```sh
-t, --tag <TAG>
        User tags or system tags to locate the object.
        To specify multiple tags, use the option multiple times.

-a, --algorithm <CRYPTOGRAPHIC_ALGORITHM>
        Cryptographic algorithm (case insensitive)

        The list of algorithms is the one specified by KMIP 2.1 in addition to "Covercrypt".
        Possible values include "Covercrypt", "ECDH", "ChaCha20Poly1305", "AES", "Ed25519"

        Running the locate sub-command with a wrong value will list all the possible values.
        e.g. `ckms locate --algorithm WRONG`

-l, --cryptographic-length <CRYPTOGRAPHIC_LENGTH>
        Cryptographic length (e.g. key size) in bits

-f, --key-format-type <KEY_FORMAT_TYPE>
        Key format type (case insensitive)

        The list is the one specified by KMIP 2.1
        in addition to the two Covercrypt formats: "CoverCryptSecretKey" and "CoverCryptPublicKey"
        Possible values also include: "TransparentECPrivateKey", "TransparentECPublicKey" and "TransparentSymmetricKey"

        Running the locate sub-command with a wrong value will list all the possible values.
        e.g. `ckms locate --key-format-type WRONG`

-h, --help
        Print help (see a summary with '-h')

-h, --help                 Print help
```

### [new-database](enclaves.md)

Initialize a new user encrypted database and return the secret (SQLCipher only).

This secret is only displayed once and is not stored anywhere on the server.
To use the encrypted database, the secret must be set in the `kms_database_secret`
property of the CLI `kms.json` configuration file.

Passing the correct secret "auto-selects" the correct encrypted database:
multiple encrypted databases can be used concurrently on the same KMS server.

Note: this action create a new database: it will not return the secret
of the last created database and will not overwrite it.

**Usage:**

```sh
ckms new-database
```

### verify

When running the KMS inside a secure environment (TEE), before any query,
the user needs to verify the trustworthiness of the KMS.

First, edit the CLI configuration file by adding the measurements in the `tee_conf` section.

Then, run the following command:

```sh
ckms verify
```

If the verification fails, *DO NOT* use this KMS instance.

If the verification succeeds, the CLI will update the configuration by adding the TLS certificate used to communicate
with the KMS during the verification stage.

This certificate will then be the only allowed for any further requests to the KMS.

The user can then used the CLI with full trust and does not need
to restart the verification process as long as the KMS is not updated.

If a query to the KMS fails because the certificates don't match, proceed a new verification. Otherwise, call the KMS administrator.

### [sym](sym/sym.md)

Manage symmetric keys and salts. Encrypt and decrypt data.

```sh
ckms sym [SUBCOMMAND]
```

**subcommands:**

```sh
keys     Create, destroy, import, and export symmetric keys
encrypt  Encrypt a file using AES GCM
decrypt  Decrypts a file using AES GCM
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](sym/sym.md)

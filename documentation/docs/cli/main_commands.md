
The `ckms` client expects command with parameters and optional options.

```sh
ckms <COMMAND>
```

At any time the online help for the CLI or a `COMMAND`, can be displayed using the `--help` option.

```sh
> ckms --help

CLI used to manage the Cosmian KMS.

Usage: ckms <COMMAND>

Commands:
  cc              Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data
  ec              Manage elliptic curve keys. Encrypt and decrypt data using ECIES
  sym             Manage symmetric keys and salts. Encrypt and decrypt data
  access-rights   Manage the users' access rights to the cryptographic objects
  locate          Locate cryptographic objects inside the KMS
  new-database    Initialize a new client-secret encrypted database and return the secret (SQLCipher only).
  server-version  Print the version of the server
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
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


### new-database

Initialize a new client-secret encrypted database and return the secret (SQLCipher only).

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

**Options:**

```sh
-h, --help                 Print help
```


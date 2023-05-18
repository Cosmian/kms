
The `ckms` client expects command with parameters and optional options.


```
ckms <COMMAND>
```

At any time the online help for the COMMAND, can be displayed using the `--help` option.

```
ckms <COMMAND> --help
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

**subcommands:**
```
remove  Remove an access authorization for an object to a user
add     Add an access authorization for an object to a user
list    List granted access authorizations for an object
owned   List objects owned by the current user
shared  List objects shared for the current user
help    Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./permissions.md)

### new-database

Initialize a new client-secret encrypted database and return the secret.

This secret is only displayed once and is not stored anywhere on the server.
To use the encrypted database, the secret must be set in the `kms_database_secret`
property of the CLI `kms.json` configuration file.

Passing the correct secret "auto-selects" the correct encrypted database:
multiple encrypted databases can be used concurrently on the same KMS server.

Note: this action create a new database: it will not return the secret
of the last created database and will not overwrite it.

**Usage:**
```
ckms new-database
```

**Options:**
```
-h, --help                 Print help
```

### trust

Query the enclave to check its trustworthiness

**Usage:**
```
ckms trust --mr-enclave <MR_ENCLAVE> <EXPORT_PATH>
```

**Arguments:**
```
<EXPORT_PATH>  The path to store exported files (quote, manifest, certificate, remote attestation, ...)
```

**Options:**
```
--mr-enclave <MR_ENCLAVE>  The value of the MR_ENCLAVE obtained by running the KMS docker on your local machine
-h, --help                 Print help
```


### help

Print the help message or the help of the given subcommand(s).

```
ckms help [SUBCOMMAND]
```


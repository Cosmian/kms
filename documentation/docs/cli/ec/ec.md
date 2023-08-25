# Elliptic Curve Commands

Manage elliptic curve keys. Encrypt and decrypt data using ECIES.

```sh
ckms ec <COMMAND>
```

## [keys](./keys.md)

Create, destroy, import, and export elliptic curve key pairs.

```sh
ckms ec keys [SUBCOMMAND]
```

**subcommands:**

```sh
create   Create a new X25519 key pair
export   Export a key from the KMS
import   Import a key in the KMS.
wrap     Locally wrap a key in KMIP JSON TTLV format.
unwrap   Locally unwrap a key in KMIP JSON TTLV format.
revoke   Revoke a public or private key
destroy  Destroy a public or private key
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./keys.md)

## encrypt

Encrypt a file with the given public key using ECIES.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.

**Usage:**

```sh
ckms ec encrypt [OPTIONS] <FILE>
```

**Arguments:**

```sh
<FILE>
        The file to encrypt
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The public key unique identifier. 
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified. 
        To specify multiple tags, use the option multiple times

-o, --output-file <OUTPUT_FILE>
        The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
        Optional authentication data. This data needs to be provided back for decryption

-h, --help
        Print help (see a summary with '-h')
```

## decrypt

Decrypt a file with the given private key using ECIES.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.

**Usage:**

```sh
ckms ec decrypt [OPTIONS] <FILE>
```

**Arguments:**

```sh
<FILE>
        The file to decrypt
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The public key unique identifier. 
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified. 
        To specify multiple tags, use the option multiple times

-o, --output-file <OUTPUT_FILE>
        The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
        Optional authentication data that was supplied during encryption

-h, --help
        Print help (see a summary with '-h')
```

## help

Print the help message or the help of the given subcommand(s).

```sh
ckms ec help [SUBCOMMAND]
```

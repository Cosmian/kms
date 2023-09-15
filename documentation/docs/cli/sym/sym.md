# Symmetric Encryption Commands

Manage symmetric keys and salts. Encrypt and decrypt data.

```sh
ckms sym <COMMAND>
```

## [keys](./keys.md)

Create, destroy, import, export symmetric keys and salts.

```sh
ckms sym keys [SUBCOMMAND]
```

### subcommands

```sh
create   Create a new symmetric key or a new salt
export   Export a key from the KMS
import   Import a key in the KMS.
wrap     Locally wrap a key in KMIP JSON TTLV format.
unwrap   Locally unwrap a key in KMIP JSON TTLV format.
revoke   Revoke a symmetric key
destroy  Destroy a symmetric key
help     Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./keys.md)

## encrypt

Encrypt a file using AES GCM.

The resulting bytes are the concatenation of

- the nonce (12 bytes)
- the encrypted data (same size as the plaintext)
- the authentication tag (16 bytes)

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.

**Usage:**

```sh
ckms sym encrypt [OPTIONS] <FILE>
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

Decrypts a file using AES GCM

The content of the file must be the concatenation of

- the nonce (12 bytes)
- the encrypted data (same size as the plaintext)
- the authentication tag (16 bytes)

This is not a streaming call: the file is entirely loaded in memory before being sent for decryption.

**Usage:**

```sh
ckms sym decrypt [OPTIONS] <FILE>
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
ckms sym help [SUBCOMMAND]
```

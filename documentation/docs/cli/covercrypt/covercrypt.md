# Covercrypt Commands

Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data.

```sh
ckms cc <COMMAND>
```

## [keys](./keys.md)

Create, destroy, import, export Covercrypt master and user keys.

```sh
ckms cc keys [SUBCOMMAND]
```

**subcommands:**

```sh
create-master-key-pair  Create a new master key pair for a given policy and return the key IDs.
create-user-key         Create a new user decryption key given an access policy expressed as a boolean expression.
export                  Export a key from the KMS
import                  Import a key in the KMS.
wrap                    Locally wrap a key in KMIP JSON TTLV format.
unwrap                  Locally unwrap a key in KMIP JSON TTLV format.
revoke                  Revoke a Covercrypt master or user decryption key
destroy                 Destroy a Covercrypt master or user decryption key
help                    Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./keys.md)

## [policy](./policy.md)

Extract or view policies of existing keys, create a binary policy from specifications.

```sh
ckms cc policy [SUBCOMMAND]
```

**subcommands:**

```sh
create-master-key-pair  Create a new master key pair for a given policy and return the key IDs.
create-user-key         Create a new user decryption key given an access policy expressed as a boolean expression.
export                  Export a key from the KMS
import                  Import a key in the KMS.
wrap                    Locally wrap a key in KMIP JSON TTLV format.
unwrap                  Locally unwrap a key in KMIP JSON TTLV format.
revoke                  Revoke a Covercrypt master or user decryption key
destroy                 Destroy a Covercrypt master or user decryption key
help                    Print this message or the help of the given subcommand(s)
```

[> view subcommands details](./policy.md)

## rotate

Rotate attributes and rekey the master and user keys.

Data encrypted with the rotated attributes
cannot be decrypted by user decryption keys unless they have been re-keyed.

Active user decryption keys are automatically re-keyed.
Revoked or destroyed user decryption keys are not re-keyed.

User keys that have not been rekeyed can still decrypt data encrypted
with the old attribute values.

**Usage:**

```sh
 ckms cc rotate <SECRET_KEY_ID> <ATTRIBUTES>...
```

**Arguments:**

```sh
<SECRET_KEY_ID>
        The private master key unique identifier stored in the KMS

<ATTRIBUTES>...
        The policy attributes to rotate.
        Example: `department::marketing level::confidential`
```

**Options:**

```sh
-h, --help
        Print help (see a summary with '-h')
```

## encrypt

Encrypt a file using Covercrypt.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.

**Usage:**

```sh
 ckms cc encrypt [OPTIONS] <FILE> <PUBLIC_KEY_ID> <ENCRYPTION_POLICY>
```

**Arguments:**

```sh
<FILE>
        The file to encrypt

<PUBLIC_KEY_ID>
        The identifier public key unique identifier stored in the KMS

<ENCRYPTION_POLICY>
        The encryption policy to encrypt the file with
        Example: "department::marketing && level::confidential"`
```

**Options:**

```sh
-o, --output-file <OUTPUT_FILE>
        The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
        Optional authentication data.
        This data needs to be provided back for decryption

-h, --help
        Print help (see a summary with '-h')
```

## decrypt

Decrypt a file using Covercrypt.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.

**Usage:**

```sh
ckms cc decrypt [OPTIONS] <FILE> <USER_KEY_ID>
```

**Arguments:**

```sh
<FILE>
        The file to decrypt

<USER_KEY_ID>
        The identifier of the user decryption key stored in the KMS
```

**Options:**

```sh
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
ckms cc help [SUBCOMMAND]
```

# Symmetric Encryption Commands

Manage symmetric keys and salts. Encrypt and decrypt data.


```
ckms sym <COMMAND>
```


### [keys](./keys.md)

Create, destroy, import, export symmetric keys and salts.

```
ckms sym keys [SUBCOMMAND]
```

**subcommands**

```
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


### encrypt

Encrypt a file using AES GCM.

The resulting bytes are the concatenation of

  - the nonce (12 bytes)
  - the encrypted data (same size as the plaintext)
  - the authentication tag (16 bytes)

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.

**Usage:**
```
ckms sym encrypt [OPTIONS] <FILE> <KEY_ID>
```

**Arguments:**
```
<FILE>
        The file to encrypt

<KEY_ID>
        The symmetric key unique identifier stored in the KMS
```

**Options:**
```
-o, --output-file <OUTPUT_FILE>
        The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
        Optional authentication data. This data needs to be provided back for decryption

-h, --help
        Print help (see a summary with '-h')
```

### decrypt

Decrypts a file using AES GCM

The content of the file must be the concatenation of

  - the nonce (12 bytes)
  - the encrypted data (same size as the plaintext)
  - the authentication tag (16 bytes)

This is not a streaming call: the file is entirely loaded in memory before being sent for decryption.

**Usage:**
```
ckms sym decrypt [OPTIONS] <FILE> <KEY_ID>
```

**Arguments:**
```
<FILE>
        The file to decrypt

<KEY_ID>
        The symmetric key unique identifier stored in the KMS
```

**Options:**
```
-o, --output-file <OUTPUT_FILE>
        The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
        Optional authentication data that was supplied during encryption

-h, --help
        Print help (see a summary with '-h')
```

### help

Print the help message or the help of the given subcommand(s).

```
ckms sym help [SUBCOMMAND]
```


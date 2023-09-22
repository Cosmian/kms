# Symmetric Keys Management

Create, destroy, import, and export symmetric keys.

```sh
ckms sym keys <COMMAND>
```

## create

Create a new symmetric key

When the `--bytes-b64` option is specified, the key will be created from the provided bytes;
otherwise, the key will be randomly generated with a length of `--number-of-bits`.

If no options are specified, a fresh 256-bit AES key will be created.

**Usage:**

```sh
ckms sym keys create [OPTIONS]
```

**Options:**

```sh
-l, --number-of-bits <NUMBER_OF_BITS>
        The length of the generated random key or salt in bits

        [default: 256]

-k, --bytes-b64 <WRAP_KEY_B64>
        The symmetric key bytes or salt as a base 64 string

-a, --algorithm <ALGORITHM>
        The algorithm

        [default: aes]
        [possible values: aes, chacha20, sha3, shake]

-t, --tag <TAG>
        The tag to associate with the key.
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## export

Export a key from the KMS

The key is exported in JSON KMIP TTLV format
unless the `--bytes` option is specified, in which case
the key bytes are exported without metadata, such as

- the links between the keys in a pair
- other metadata: policies, etc.

Key bytes are sufficient to perform local encryption or decryption.

The key can be wrapped or unwrapped when exported.
If nothing is specified, it is returned as it is stored.
Wrapping a key that is already wrapped is an error.
Unwrapping a key that is not wrapped is ignored and returns the unwrapped key.

When using tags to retrieve the key, rather than the key id,
an error is returned if multiple keys matching the tags are found.

**Usage:**

```sh
ckms sym keys export [OPTIONS] <KEY_FILE>
```

**Arguments:**

```sh
<KEY_FILE>
        The ile to export the key to
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The public key unique identifier.
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified.
        To specify multiple tags, use the option multiple times

-b, --bytes
        Export the key bytes only

-u, --unwrap
        Unwrap the key if it is wrapped before export

-w, --wrap-key-id <WRAP_KEY_ID>
        The id of key/certificate to use to wrap this key before export

-i, --allow-revoked
        Allow exporting revoked and destroyed keys. The user must be the owner of the key. Destroyed keys have their key material removed

-h, --help
        Print help (see a summary with '-h')
```

## import

Import a key in the KMS.

The key must be in KMIP JSON TTLV format.
When no key unique id is specified a random UUID v4 is generated.

The key can be wrapped when imported. Wrapping using:

- a password or a supplied key in base64 is done locally
- a symmetric key id is performed server side

A password is first converted to a 256 bit key using Argon 2.
Wrapping is performed according to RFC 5649.

Tags can later be used to retrieve the key. Tags are optional.

**Usage:**

```sh
ckms sym keys import [OPTIONS] <KEY_FILE> [KEY_ID]
```

**Arguments:**

```sh
<KEY_FILE>
        The KMIP JSON TTLV key file

[KEY_ID]
        The unique id of the key; a random UUID v4 is generated if not specified
```

**Options:**

```sh
-u, --unwrap
        Unwrap the object if it is wrapped before storing it

-r, --replace
        Replace an existing key under the same id

-t, --tag <TAG>
        The tag to associate with the key.
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## wrap

Locally wrap a key in KMIP JSON TTLV format.

The key can be wrapped using either:

- a password derived into a symmetric key using Argon2
- symmetric key bytes in base64
- a key in the KMS (which will be exported first)
- a key in a KMIP JSON TTLV file

For the latter 2 cases, the key may be a symmetric key
and RFC 5649 will be used or a curve 25519 public key
and ECIES will be used.

**Usage:**

```sh
ckms sym keys wrap [OPTIONS] <KEY_FILE_IN> [KEY_FILE_OUT]
```

**Arguments:**

```sh
<KEY_FILE_IN>
        The KMIP JSON TTLV input key file to wrap

[KEY_FILE_OUT]
        The KMIP JSON output file. When not specified the input file is overwritten
```

**Options:**

```sh
-p, --wrap-password <WRAP_PASSWORD>
        A password to wrap the imported key

-k, --wrap-key-b64 <WRAP_KEY_B64>
        A symmetric key as a base 64 string to wrap the imported key

-i, --wrap-key-id <WRAP_KEY_ID>
        The id of a wrapping key in the KMS that will be exported and used to wrap the key

-f, --wrap-key-file <WRAP_KEY_FILE>
        A wrapping key in a KMIP JSON TTLV file used to wrap the key

-h, --help
        Print help (see a summary with '-h')
```

## unwrap

Locally unwrap a key in KMIP JSON TTLV format.

The key can be unwrapped using either:

- a password derived into a symmetric key using Argon2
- symmetric key bytes in base64
- a key in the KMS (which will be exported first)
- a key in a KMIP JSON TTLV file

For the latter 2 cases, the key may be a symmetric key
and RFC 5649 will be used or a curve 25519 private key
and ECIES will be used.

**Usage:**

```sh
ckms sym keys unwrap [OPTIONS] <KEY_FILE_IN> [KEY_FILE_OUT]
```

**Arguments:**

```sh
<KEY_FILE_IN>
        The KMIP JSON TTLV input key file to unwrap

[KEY_FILE_OUT]
        The KMIP JSON output file. When not specified the input file is overwritten
```

**Options:**

```sh
-p, --unwrap-password <UNWRAP_PASSWORD>
        A password to unwrap the imported key

-k, --unwrap-key-b64 <UNWRAP_KEY_B64>
        A symmetric key as a base 64 string to unwrap the imported key

-i, --unwrap-key-id <UNWRAP_KEY_ID>
        The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

-f, --unwrap-key-file <UNWRAP_KEY_FILE>
        A unwrapping key in a KMIP JSON TTLV file used to unwrap the key

-h, --help
        Print help (see a summary with '-h')
```

## revoke

Revoke a symmetric key.

When a key is revoked, it can only be exported by the owner of the key, using the --allow-revoked flag on the export function.

**Usage:**

```sh
ckms sym keys revoke <REVOCATION_REASON>
```

**Arguments:**

```sh
<REVOCATION_REASON>
        The reason for the revocation as a string
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The public key unique identifier.
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified.
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## destroy

Destroy a symmetric key.

The key must have been revoked first.

When a key is destroyed, it can only be exported by the owner of the key, and without its key material

**Usage:**

```sh
ckms sym keys destroy [OPTIONS]
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The public key unique identifier.
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified.
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## help

Print the help message or the help of the given subcommand(s).

```sh
ckms sym keys help [SUBCOMMAND]
```

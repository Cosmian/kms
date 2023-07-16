# Covercrypt Keys Management

Create, destroy, import, export Covercrypt master and user keys.

```sh
ckms cc keys <COMMAND>
```

## create-master-key-pair

Create a new master key pair for a given policy and return the key IDs.

- The master public key is used to encrypt the files and can be safely shared.
- The master secret key is used to generate user decryption keys and must be kept confidential.

The policy specifications must be passed as a JSON in a file, for example:

```json
{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}
```

These specifications create a policy where:

- the policy is defined with 2 policy axes: `Security Level` and `Department`
- the `Security Level` axis is hierarchical as indicated by the `::<` suffix,
- the `Security Level` axis has 3 possible values: `Protected`, `Confidential`, and `Top Secret`,
- the `Department` axis has 4 possible values: `R&D`, `HR`, `MKG`, and `FIN`,
- all partitions which are `Top Secret` will be encrypted using post-quantum hybridized cryptography, as indicated by the `::+` suffix on the value,
- all other partitions will use classic cryptography.

Tags can later be used to retrieve the keys. Tags are optional.

**Usage:**

```sh
ckms cc keys create-master-key-pair [OPTIONS]
```

**Options:**

```sh
-s, --policy-specifications <POLICY_SPECIFICATIONS_FILE>
        The JSON policy specifications file to use to generate the master keys.

-b, --policy-binary <POLICY_BINARY_FILE>
        When not using policy specifications, a policy binary file can be used instead.
        See the `policy` command, to create this binary file from policy specifications
        or to extract it from existing keys

-t, --tag <TAG>
        The tag to associate with the master key pair. 
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## create-user-key

Create a new user decryption key given an access policy expressed as a boolean expression.

The access policy is a boolean expression over the attributes of the policy axis.
For example, for the policy below, the access policy expression

   `Department::HR && Security Level::Confidential`

gives decryption access to all ciphertexts in the HR/Protected partition,
   as well as those in the HR/Protected partition, since the `Security Level` axis
   is hierarchical.

A more complex access policy giving access to the 3 partitions MKG/Confidential,
MKG/Protected, and HR/Protected would be

   `(Department::MKG && Security Level::Confidential) || (Department::HR && Security Level::Protected)`

The policy used in this example is

```json
{
    "Security Level::<": [
        "Protected",
        "Confidential",
        "Top Secret::+"
    ],
    "Department": [
        "R&D",
        "HR",
        "MKG",
        "FIN"
    ]
}
```

Tags can later be used to retrieve the key. Tags are optional.

**Usage:**

```sh
ckms cc keys create-user-key <MASTER_PRIVATE_KEY_ID> <ACCESS_POLICY>
```

**Arguments:**

```sh
<MASTER_PRIVATE_KEY_ID>
        The master private key unique identifier

<ACCESS_POLICY>
        The access policy as a boolean expression combining policy attributes.

        Example: "(Department::HR || Department::MKG) && Security Level::Confidential"
```

**Options:**

```sh
-t, --tag <TAG>
        The tag to associate with the user decryption key. 
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## export

Export a key from the KMS.

The key is exported in JSON KMIP TTLV format
unless the `--bytes` option is specified, in which case
the key bytes are exported without meta data, such as

- the policy for the master keys
- the links between the keys

Key bytes are sufficient to perform local encryption or decryption.

The key can be wrapped or unwrapped when exported.
If nothing is specified, it is returned as it is stored.
Wrapping a key that is already wrapped is an error.
Unwrapping a key that is not wrapped is ignored and returns the unwrapped key.

When using tags to retrieve the key, rather than the key id,
an error is returned if multiple keys matching the tags are found.

**Usage:**

```sh
ckms cc keys export [OPTIONS] <KEY_FILE>
```

**Arguments:**

```sh
<KEY_ID>
        The object unique identifier stored in the KMS

<KEY_FILE>
        The JSON file to export the object to
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The key unique identifier stored in the KMS.
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

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
When no key unique id is specified, a random UUID v4 is generated.

The key can be wrapped when imported. Wrapping using:

- a password or a supplied key in base64 is done locally
- a symmetric key id is performed server-side

A password is first converted to a 256-bit key using Argon 2.
Wrapping is performed according to RFC 5649.

Tags can later be used to retrieve the key. Tags are optional.

**Usage:**

```sh
ckms cc keys import [OPTIONS] <KEY_FILE> [KEY_ID]
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
        Unwrap the object it is wrapped before storing it

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
- a symmetric key bytes in base64
- a key in the KMS (which will be exported first)
- a key in a KMIP JSON TTLV file

For the latter 2 cases, the key may be a symmetric key
and RFC 5649 will be used or a curve 25519 public key
and ECIES will be used.

**Usage:**

```sh
ckms cc keys wrap [OPTIONS] <KEY_FILE_IN> [KEY_FILE_OUT]
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

For the latter 2 cases, the key may be a symmetric key,
and RFC 5649 will be used, or a curve 25519 private key
and ECIES will be used.

**Usage:**

```sh
ckms cc keys unwrap [OPTIONS] <KEY_FILE_IN> [KEY_FILE_OUT]
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

Revoke a Covercrypt master or user decryption key.

Once a key is revoked, it can only be exported by the owner of the key, using the `--allow-revoked` flag on the export function.

Revoking a master public or private key will revoke the whole key pair and all the associated user decryption keys present in the KMS.

Once a user decryption key is revoked, it will no longer be rekeyed when attributes are rotated on the master key.

When using tags to revoke the key, rather than the key id, an error is returned if multiple keys matching the tags are found.

**Usage:**

```sh
ckms cc keys revoke [OPTIONS] <REVOCATION_REASON>
```

**Arguments:**

```sh
<REVOCATION_REASON>
        The reason for the revocation as a string
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The key unique identifier of the key to revoke. 
        If not specified, tags should be specified

-t, --tag <TAG>
        Tag to use to retrieve the key when no key id is specified. 
        To specify multiple tags, use the option multiple times

-h, --help
        Print help (see a summary with '-h')
```

## destroy

Destroy a Covercrypt master or user decryption key.

The key must have been revoked first.

When a key is destroyed, it can only be exported by the owner of the key, and without its key material

Destroying a master public or private key will destroy the whole key pair and all the associated decryption keys present in the KMS.

When using tags to revoke the key, rather than the key id, an error is returned if multiple keys matching the tags are found.

**Usage:**

```sh
ckms cc keys destroy [OPTIONS]
```

**Options:**

```sh
-k, --key-id <KEY_ID>
        The key unique identifier. 
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
ckms cc keys help [SUBCOMMAND]
```

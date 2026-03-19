
##  ckms

Command Line Interface used to manage the Cosmian KMS server.

If any assistance is needed, please either visit the Cosmian technical documentation at https://docs.cosmian.com
or contact the Cosmian support team on Discord https://discord.com/invite/7kPMNtHpnz


### Usage
`ckms <subcommand> [options]`
### Arguments
`--conf-path [-c] <CONF_PATH>` Configuration file location

`--url <URL>` The URL of the KMS

`--print-json <PRINT_JSON>` Output the KMS JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint

Possible values:  `"true", "false"`

`--accept-invalid-certs <ACCEPT_INVALID_CERTS>` Allow to connect using a self-signed cert or untrusted cert chain

Possible values:  `"true", "false"`

`--header [-H] <NAME: VALUE>` Add a custom HTTP header to every request sent to the KMS server.

`--proxy-url <PROXY_URL>` The proxy URL:

  - e.g., `https://secure.example` for an HTTP proxy
  - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy

`--proxy-basic-auth-username <PROXY_BASIC_AUTH_USERNAME>` Set the Proxy-Authorization header username using Basic auth.

`--proxy-basic-auth-password <PROXY_BASIC_AUTH_PASSWORD>` Set the Proxy-Authorization header password using Basic auth.

`--proxy-custom-auth-header <PROXY_CUSTOM_AUTH_HEADER>` Set the Proxy-Authorization header to a specified value.

`--proxy-exclusion-list <PROXY_EXCLUSION_LIST>` The No Proxy exclusion list to this Proxy


### Subcommands

**`access-rights`** [[1]](#1-ckms-access-rights)  Manage the users' access rights to the cryptographic objects

**`attributes`** [[2]](#2-ckms-attributes)  Get/Set/Delete/Modify the KMIP object attributes

**`azure`** [[3]](#3-ckms-azure)  Support for Azure specific interactions

**`bench`** [[4]](#4-ckms-bench)  Run a set of benches to check the server performance

**`cc`** [[5]](#5-ckms-cc)  Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data

**`kem`** [[6]](#6-ckms-kem)  Manage Configurable KEM keys. Encrypt and decrypt data

**`certificates`** [[7]](#7-ckms-certificates)  Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

**`derive-key`** [[8]](#8-ckms-derive-key)  Derive a new key from an existing key

**`ec`** [[9]](#9-ckms-ec)  Manage elliptic curve keys. Encrypt and decrypt data using ECIES

**`google`** [[10]](#10-ckms-google)  Manage google elements. Handle key pairs and identities from Gmail API

**`locate`** [[11]](#11-ckms-locate)  Locate cryptographic objects inside the KMS

**`login`** [[12]](#12-ckms-login)  Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

**`logout`** [[13]](#13-ckms-logout)  Logout from the Identity Provider

**`hash`** [[14]](#14-ckms-hash)  Hash arbitrary data.

**`mac`** [[15]](#15-ckms-mac)  MAC utilities: compute or verify a MAC value.

**`rng`** [[16]](#16-ckms-rng)  RNG utilities: retrieve random bytes or seed RNG

**`discover-versions`** [[17]](#17-ckms-discover-versions)  Discover KMIP protocol versions supported by the server

**`query`** [[18]](#18-ckms-query)  Query server capabilities and metadata (KMIP Query)

**`rsa`** [[19]](#19-ckms-rsa)  Manage RSA keys. Encrypt and decrypt data using RSA keys

**`opaque-object`** [[20]](#20-ckms-opaque-object)  Create, import, export, revoke and destroy Opaque Objects

**`secret-data`** [[21]](#21-ckms-secret-data)  Create, import, export and destroy secret data

**`server-version`** [[22]](#22-ckms-server-version)  Print the version of the server

**`sym`** [[23]](#23-ckms-sym)  Manage symmetric keys. Encrypt and decrypt data

**`markdown`** [[24]](#24-ckms-markdown)  Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

**`configure`** [[25]](#25-ckms-configure)  Configure the KMS CLI (create ckms.toml)

---

## 1 ckms access-rights

Manage the users' access rights to the cryptographic objects

### Usage
`ckms access-rights <subcommand>`

### Subcommands

**`grant`** [[1.1]](#11-ckms-access-rights-grant)  Grant another user one or multiple access rights to an object

**`revoke`** [[1.2]](#12-ckms-access-rights-revoke)  Revoke another user one or multiple access rights to an object

**`list`** [[1.3]](#13-ckms-access-rights-list)  List the access rights granted on an object to other users

**`owned`** [[1.4]](#14-ckms-access-rights-owned)  List the objects owned by the calling user

**`obtained`** [[1.5]](#15-ckms-access-rights-obtained)  List the access rights obtained by the calling user

---

## 1.1 ckms access-rights grant

Grant another user one or multiple access rights to an object

### Usage
`ckms access-rights grant [options] <USER>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user identifier to allow

`--object-uid [-i] <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`, `get_attributes`)



---

## 1.2 ckms access-rights revoke

Revoke another user one or multiple access rights to an object

### Usage
`ckms access-rights revoke [options] <USER>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user to revoke access to

`--object-uid [-i] <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to revoke (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)



---

## 1.3 ckms access-rights list

List the access rights granted on an object to other users

### Usage
`ckms access-rights list [options] <OBJECT_UID>
`
### Arguments
` <OBJECT_UID>` The object unique identifier



---

## 1.4 ckms access-rights owned

List the objects owned by the calling user

### Usage
`ckms access-rights owned`


---

## 1.5 ckms access-rights obtained

List the access rights obtained by the calling user

### Usage
`ckms access-rights obtained`



---

## 2 ckms attributes

Get/Set/Delete/Modify the KMIP object attributes

### Usage
`ckms attributes <subcommand>`

### Subcommands

**`get`** [[2.1]](#21-ckms-attributes-get)  Get the KMIP object attributes and tags.

**`set`** [[2.2]](#22-ckms-attributes-set)  Set the KMIP object attributes.

**`delete`** [[2.3]](#23-ckms-attributes-delete)  Delete the KMIP object attributes.

**`modify`** [[2.4]](#24-ckms-attributes-modify)  Modify existing KMIP object attributes.

---

## 2.1 ckms attributes get

Get the KMIP object attributes and tags.

### Usage
`ckms attributes get [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--attribute [-a] <ATTRIBUTE>` The KMIP attribute to retrieve.
To specify multiple attributes, use the option multiple times.
If not specified, all possible attributes are returned.
To retrieve the tags, use `Tag` as an attribute value.

`--link-type [-l] <LINK_TYPE>` Filter on retrieved links. Only if KMIP tag `LinkType` is used in `attribute` parameter.
To specify multiple attributes, use the option multiple times.
If not specified, all possible link types are returned.

Possible values:  `"certificate", "public-key", "private-key", "derivation-base-object", "derived-key", "replacement-object", "replaced-object", "parent", "child", "previous", "next", "pkcs12-certificate", "pkcs12-password", "wrapping-key"`

`--output-file [-o] <OUTPUT_FILE>` An optional file where to export the attributes.
The attributes will be in JSON TTLV format.



---

## 2.2 ckms attributes set

Set the KMIP object attributes.

### Usage
`ckms attributes set [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--activation-date [-d] <ACTIVATION_DATE>` Set the activation date of the key. Epoch time (or Unix time) in milliseconds

`--cryptographic-algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` The cryptographic algorithm used by the key

Possible values:  `"aes", "rsa", "ecdsa", "ecdh", "ec", "chacha20", "chacha20-poly1305", "sha3224", "sha3256", "sha3384", "sha3512", "ed25519", "ed448", "covercrypt", "covercrypt-bulk"`

`--cryptographic-length <CRYPTOGRAPHIC_LENGTH>` The length of the cryptographic key

`--key-usage [-u] <KEY_USAGE>` The key usage. Add multiple times to specify multiple key usages

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--public-key-id <PUBLIC_KEY_ID>` The link to the corresponding public key id if any

`--private-key-id <PRIVATE_KEY_ID>` The link to the corresponding private key id if any

`--certificate-id <CERTIFICATE_ID>` The link to the corresponding certificate id if any

`--p12-id <PKCS12_CERTIFICATE_ID>` The link to the corresponding PKCS12 certificate id if any

`--p12-pwd <PKCS12_PASSWORD_CERTIFICATE>` The link to the corresponding PKCS12 password certificate if any

`--parent-id <PARENT_ID>` The link to the corresponding parent id if any

`--child-id <CHILD_ID>` The link to the corresponding child id if any

`--name <NAME>` The name of the object (standard KMIP Name attribute). The name is stored as an `UninterpretedTextString` by default

`--vendor-identification [-v] <VENDOR_IDENTIFICATION>` The vendor identification

`--attribute-name [-n] <ATTRIBUTE_NAME>` The attribute name

`--attribute-value <ATTRIBUTE_VALUE>` The attribute value (in hex format)



---

## 2.3 ckms attributes delete

Delete the KMIP object attributes.

### Usage
`ckms attributes delete [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--activation-date [-d] <ACTIVATION_DATE>` Set the activation date of the key. Epoch time (or Unix time) in milliseconds

`--cryptographic-algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` The cryptographic algorithm used by the key

Possible values:  `"aes", "rsa", "ecdsa", "ecdh", "ec", "chacha20", "chacha20-poly1305", "sha3224", "sha3256", "sha3384", "sha3512", "ed25519", "ed448", "covercrypt", "covercrypt-bulk"`

`--cryptographic-length <CRYPTOGRAPHIC_LENGTH>` The length of the cryptographic key

`--key-usage [-u] <KEY_USAGE>` The key usage. Add multiple times to specify multiple key usages

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--public-key-id <PUBLIC_KEY_ID>` The link to the corresponding public key id if any

`--private-key-id <PRIVATE_KEY_ID>` The link to the corresponding private key id if any

`--certificate-id <CERTIFICATE_ID>` The link to the corresponding certificate id if any

`--p12-id <PKCS12_CERTIFICATE_ID>` The link to the corresponding PKCS12 certificate id if any

`--p12-pwd <PKCS12_PASSWORD_CERTIFICATE>` The link to the corresponding PKCS12 password certificate if any

`--parent-id <PARENT_ID>` The link to the corresponding parent id if any

`--child-id <CHILD_ID>` The link to the corresponding child id if any

`--name <NAME>` The name of the object (standard KMIP Name attribute). The name is stored as an `UninterpretedTextString` by default

`--vendor-identification [-v] <VENDOR_IDENTIFICATION>` The vendor identification

`--attribute-name [-n] <ATTRIBUTE_NAME>` The attribute name

`--attribute-value <ATTRIBUTE_VALUE>` The attribute value (in hex format)

`--attribute <ATTRIBUTE>` The attributes or tags to retrieve.
To specify multiple attributes, use the option multiple times.



---

## 2.4 ckms attributes modify

Modify existing KMIP object attributes.

### Usage
`ckms attributes modify [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--activation-date [-d] <ACTIVATION_DATE>` Set the activation date of the key. Epoch time (or Unix time) in milliseconds

`--cryptographic-algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` The cryptographic algorithm used by the key

Possible values:  `"aes", "rsa", "ecdsa", "ecdh", "ec", "chacha20", "chacha20-poly1305", "sha3224", "sha3256", "sha3384", "sha3512", "ed25519", "ed448", "covercrypt", "covercrypt-bulk"`

`--cryptographic-length <CRYPTOGRAPHIC_LENGTH>` The length of the cryptographic key

`--key-usage [-u] <KEY_USAGE>` The key usage. Add multiple times to specify multiple key usages

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--public-key-id <PUBLIC_KEY_ID>` The link to the corresponding public key id if any

`--private-key-id <PRIVATE_KEY_ID>` The link to the corresponding private key id if any

`--certificate-id <CERTIFICATE_ID>` The link to the corresponding certificate id if any

`--p12-id <PKCS12_CERTIFICATE_ID>` The link to the corresponding PKCS12 certificate id if any

`--p12-pwd <PKCS12_PASSWORD_CERTIFICATE>` The link to the corresponding PKCS12 password certificate if any

`--parent-id <PARENT_ID>` The link to the corresponding parent id if any

`--child-id <CHILD_ID>` The link to the corresponding child id if any

`--name <NAME>` The name of the object (standard KMIP Name attribute). The name is stored as an `UninterpretedTextString` by default

`--vendor-identification [-v] <VENDOR_IDENTIFICATION>` The vendor identification

`--attribute-name [-n] <ATTRIBUTE_NAME>` The attribute name

`--attribute-value <ATTRIBUTE_VALUE>` The attribute value (in hex format)




---

## 3 ckms azure

Support for Azure specific interactions

### Usage
`ckms azure <subcommand>`

### Subcommands

**`byok`** [[3.1]](#31-ckms-azure-byok)  Azure BYOK support. See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

---

## 3.1 ckms azure byok

Azure BYOK support. See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

### Usage
`ckms azure byok <subcommand>`

### Subcommands

**`import`** [[3.1.1]](#311-ckms-azure-byok-import)  Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>

**`export`** [[3.1.2]](#312-ckms-azure-byok-export)  Wrap a KMS key with an Azure Key Encryption Key (KEK),
previously imported using the `ckms azure byok import` command.
Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

---

## 3.1.1 ckms azure byok import

Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>

### Usage
`ckms azure byok import [options] <KEK_FILE>
 <KID>
 [KEY_ID]
`
### Arguments
` <KEK_FILE>` The RSA Key Encryption Key (KEK) file exported from the Azure Key Vault in PKCS#8 PEM format

` <KID>` The Azure Key ID (kid). It should be something like:
<https://mypremiumkeyvault.vault.azure.net/keys/KEK-BYOK/664f5aa2797a4075b8e36ca4500636d8>

` <KEY_ID>` The unique ID of the key in this KMS; a random UUID is generated if not specified



---

## 3.1.2 ckms azure byok export

Wrap a KMS key with an Azure Key Encryption Key (KEK),
previously imported using the `ckms azure byok import` command.
Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

### Usage
`ckms azure byok export [options] <WRAPPED_KEY_ID>
 <KEK_ID>
 [BYOK_FILE]
`
### Arguments
` <WRAPPED_KEY_ID>` The unique ID of the KMS private key that will be wrapped and then exported

` <KEK_ID>` The Azure KEK ID in this KMS

` <BYOK_FILE>` The file path to export the `.byok` file to. If not specified, the file will be called `<wrapped_key_id>.byok`





---

## 4 ckms bench

Run a set of benches to check the server performance

### Usage
`ckms bench [options]`
### Arguments
`--number-of-threads [-t] <NUM_THREADS>` The number of parallel threads to use

`--batch-size [-b] <BATCH_SIZE>` The size of an encryption/decryption batch.
A size of 1 does not use the `BulkData` API

`--num-batches [-n] <NUM_BATCHES>` The number of batches to run

`--wrapped-key [-w] <WRAPPED_KEY>` Use a wrapped key (by a 4096 RSA key) to encrypt the symmetric key

Possible values:  `"true", "false"` [default: `"false"`]

`--verbose [-v] <VERBOSE>` Display batch results details

Possible values:  `"true", "false"` [default: `"false"`]



---

## 5 ckms cc

Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data

### Usage
`ckms cc <subcommand>`

### Subcommands

**`keys`** [[5.1]](#51-ckms-cc-keys)  Create, destroy, import, export, and rekey `Covercrypt` master and user keys

**`access-structure`** [[5.2]](#52-ckms-cc-access-structure)  Extract, view, or edit policies of existing keys

**`encrypt`** [[5.3]](#53-ckms-cc-encrypt)  Encrypt a file using Covercrypt

**`decrypt`** [[5.4]](#54-ckms-cc-decrypt)  Decrypt a file using Covercrypt

---

## 5.1 ckms cc keys

Create, destroy, import, export, and rekey `Covercrypt` master and user keys

### Usage
`ckms cc keys <subcommand>`

### Subcommands

**`create-master-key-pair`** [[5.1.1]](#511-ckms-cc-keys-create-master-key-pair)  Create a new master keypair for a given access structure and return the key
IDs.

**`create-user-key`** [[5.1.2]](#512-ckms-cc-keys-create-user-key)  Create a new user secret key for an access policy, and index it under some
(optional) tags, that can later be used to retrieve the key.

**`export`** [[5.1.3]](#513-ckms-cc-keys-export)  Export a key or secret data from the KMS

**`import`** [[5.1.4]](#514-ckms-cc-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[5.1.5]](#515-ckms-cc-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[5.1.6]](#516-ckms-cc-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[5.1.7]](#517-ckms-cc-keys-revoke)  Revoke a Covercrypt master or user decryption key

**`destroy`** [[5.1.8]](#518-ckms-cc-keys-destroy)  Destroy a Covercrypt master or user decryption key

**`rekey`** [[5.1.9]](#519-ckms-cc-keys-rekey)  Rekey the given access policy.

**`prune`** [[5.1.10]](#5110-ckms-cc-keys-prune)  Prune all keys linked to an MSK w.r.t an given access policy.

---

## 5.1.1 ckms cc keys create-master-key-pair

Create a new master keypair for a given access structure and return the key
IDs.

### Usage
`ckms cc keys create-master-key-pair [options]`
### Arguments
`--specification [-s] <SPECIFICATION>` The JSON access structure specifications file to use to generate the keys. See the inline doc of the `create-master-key-pair` command for details

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

`--sensitive <SENSITIVE>` Sensitive: if set, the private key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 5.1.2 ckms cc keys create-user-key

Create a new user secret key for an access policy, and index it under some
(optional) tags, that can later be used to retrieve the key.

### Usage
`ckms cc keys create-user-key [options] <MASTER_SECRET_KEY_ID>
 <ACCESS_POLICY>
`
### Arguments
` <MASTER_SECRET_KEY_ID>` The master secret key unique identifier

` <ACCESS_POLICY>` The access policy should be expressed as a boolean expression of attributes. For example (provided the corresponding attributes are defined in the MSK):

`--tag [-t] <TAG>` The tag to associate with the user decryption key. To specify multiple tags, use the option multiple times

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 5.1.3 ckms cc keys export

Export a key or secret data from the KMS

### Usage
`ckms cc keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 5.1.4 ckms cc keys import

Import a secret data or a key in the KMS.

### Usage
`ckms cc keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 5.1.5 ckms cc keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms cc keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into an AES-256 symmetric key. For security reasons, a fresh salt is internally generated by `cosmian` and handled, and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The ID of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 5.1.6 ckms cc keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms cc keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 5.1.7 ckms cc keys revoke

Revoke a Covercrypt master or user decryption key

### Usage
`ckms cc keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 5.1.8 ckms cc keys destroy

Destroy a Covercrypt master or user decryption key

### Usage
`ckms cc keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]



---

## 5.1.9 ckms cc keys rekey

Rekey the given access policy.

### Usage
`ckms cc keys rekey [options] <ACCESS_POLICY>
`
### Arguments
` <ACCESS_POLICY>` The access policy should be expressed as a boolean expression of attributes. For example (provided the corresponding attributes are defined in the MSK):

`--key-id [-k] <MSK_UID>` The MSK UID stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the MSK when no key id is specified. To specify multiple tags, use the option multiple times



---

## 5.1.10 ckms cc keys prune

Prune all keys linked to an MSK w.r.t an given access policy.

### Usage
`ckms cc keys prune [options] <ACCESS_POLICY>
`
### Arguments
` <ACCESS_POLICY>` The access policy should be expressed as a boolean expression of attributes. For example (provided the corresponding attributes are defined in the MSK):

`--key-id [-k] <MSK_UID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 5.2 ckms cc access-structure

Extract, view, or edit policies of existing keys

### Usage
`ckms cc access-structure <subcommand>`

### Subcommands

**`view`** [[5.2.1]](#521-ckms-cc-access-structure-view)  View the access structure of an existing public or private master key.

**`add-attribute`** [[5.2.2]](#522-ckms-cc-access-structure-add-attribute)  Add an attribute to the access structure of an existing private master key.

**`remove-attribute`** [[5.2.3]](#523-ckms-cc-access-structure-remove-attribute)  Remove an attribute from the access structure of an existing private master key.
Permanently removes the ability to use this attribute in both encryptions and decryptions.

**`disable-attribute`** [[5.2.4]](#524-ckms-cc-access-structure-disable-attribute)  Disable an attribute from the access structure of an existing private master
key.

**`rename-attribute`** [[5.2.5]](#525-ckms-cc-access-structure-rename-attribute)  Rename an attribute in the access structure of an existing private master key.

---

## 5.2.1 ckms cc access-structure view

View the access structure of an existing public or private master key.

### Usage
`ckms cc access-structure view [options]`
### Arguments
`--key-id [-i] <KEY_ID>` The public or private master key ID if the key is stored in the KMS

`--key-file [-f] <KEY_FILE>` If `key-id` is not provided, use `--key-file` to provide the file containing the public or private master key in TTLV format



---

## 5.2.2 ckms cc access-structure add-attribute

Add an attribute to the access structure of an existing private master key.

### Usage
`ckms cc access-structure add-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to create. Example: `department::rnd`

`--hybridized <HYBRIDIZED>` Hybridize this qualified attribute

Possible values:  `"true", "false"` [default: `"false"`]

`--key-id [-k] <SECRET_KEY_ID>` The master secret key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 5.2.3 ckms cc access-structure remove-attribute

Remove an attribute from the access structure of an existing private master key.
Permanently removes the ability to use this attribute in both encryptions and decryptions.

### Usage
`ckms cc access-structure remove-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to remove. Example: `department::marketing` Note: prevents ciphertexts only targeting this qualified attribute to be decrypted

`--key-id [-k] <MASTER_SECRET_KEY_ID>` The master secret key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 5.2.4 ckms cc access-structure disable-attribute

Disable an attribute from the access structure of an existing private master
key.

### Usage
`ckms cc access-structure disable-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to disable. Example: `department::marketing`

`--key-id [-k] <MASTER_SECRET_KEY_ID>` The master secret key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 5.2.5 ckms cc access-structure rename-attribute

Rename an attribute in the access structure of an existing private master key.

### Usage
`ckms cc access-structure rename-attribute [options] <ATTRIBUTE>
 <NEW_NAME>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to rename. Example: `department::mkg`

` <NEW_NAME>` The new name for the attribute. Example: `marketing`

`--key-id [-k] <MASTER_SECRET_KEY_ID>` The master secret key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 5.3 ckms cc encrypt

Encrypt a file using Covercrypt

### Usage
`ckms cc encrypt [options] <FILE>...
 <ENCRYPTION_POLICY>
`
### Arguments
` <FILE>` The files to encrypt

` <ENCRYPTION_POLICY>` The encryption policy to encrypt the file with Example: "`department::marketing` && `level::confidential`"

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data. This data needs to be provided back for decryption



---

## 5.4 ckms cc decrypt

Decrypt a file using Covercrypt

### Usage
`ckms cc decrypt [options] <FILE>...
`
### Arguments
` <FILE>` The files to decrypt

`--key-id [-k] <KEY_ID>` The user key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption




---

## 6 ckms kem

Manage Configurable KEM keys. Encrypt and decrypt data

### Usage
`ckms kem <subcommand>`

### Subcommands

**`key-gen`** [[6.1]](#61-ckms-kem-key-gen)  Create a new Configurable-KEM keypair and return the key IDs.

**`encrypt`** [[6.2]](#62-ckms-kem-encrypt)  Encapsulate a new symmetric key

**`decrypt`** [[6.3]](#63-ckms-kem-decrypt)  Open a Configurable-KEM encapsulation

---

## 6.1 ckms kem key-gen

Create a new Configurable-KEM keypair and return the key IDs.

### Usage
`ckms kem key-gen [options]`
### Arguments
`--access-structure [-s] <ACCESS_STRUCTURE>` The JSON access structure specifications file to use to generate the keys. See the inline doc of the `create-master-key-pair` command for details

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

`--sensitive <SENSITIVE>` Sensitive: if set, the private key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--kem [-k] <KEM_ALGORITHM>` The KEM algorithm to use for key pair generation

Possible values:  `"ml-kem-512", "ml-kem-768", "p256", "curve25519", "ml-kem-512-p256", "ml-kem-768-p256", "ml-kem-512-curve25519", "ml-kem-768-curve25519", "cover-crypt"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 6.2 ckms kem encrypt

Encapsulate a new symmetric key

### Usage
`ckms kem encrypt [options] [ENCRYPTION_POLICY]
`
### Arguments
`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

` <ENCRYPTION_POLICY>` The encryption policy to use. Example: "`department::marketing` && `level::confidential`"

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path for the encapsulation



---

## 6.3 ckms kem decrypt

Open a Configurable-KEM encapsulation

### Usage
`ckms kem decrypt [options] <FILE>
`
### Arguments
` <FILE>` The encapsulation file to decrypt

`--key-id [-k] <KEY_ID>` The user key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The decrypted output file path




---

## 7 ckms certificates

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

### Usage
`ckms certificates <subcommand>`

### Subcommands

**`certify`** [[7.1]](#71-ckms-certificates-certify)  Issue or renew a X509 certificate

**`decrypt`** [[7.2]](#72-ckms-certificates-decrypt)  Decrypt a file using the private key of a certificate

**`encrypt`** [[7.3]](#73-ckms-certificates-encrypt)  Encrypt a file using the certificate public key

**`export`** [[7.4]](#74-ckms-certificates-export)  Export a certificate from the KMS

**`import`** [[7.5]](#75-ckms-certificates-import)  Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

**`revoke`** [[7.6]](#76-ckms-certificates-revoke)  Revoke a certificate

**`destroy`** [[7.7]](#77-ckms-certificates-destroy)  Destroy a certificate

**`validate`** [[7.8]](#78-ckms-certificates-validate)  Validate a certificate

---

## 7.1 ckms certificates certify

Issue or renew a X509 certificate

### Usage
`ckms certificates certify [options]`
### Arguments
`--certificate-id [-c] <CERTIFICATE_ID>` The unique identifier of the certificate to issue or renew. If not provided, a random one will be generated when issuing a certificate, or the original one will be used when renewing a certificate

`--certificate-signing-request [-r] <CERTIFICATE_SIGNING_REQUEST>` The path to a certificate signing request

`--certificate-signing-request-format [-f] <CERTIFICATE_SIGNING_REQUEST_FORMAT>` The format of the certificate signing request

Possible values:  `"pem", "der"` [default: `"pem"`]

`--public-key-id-to-certify [-p] <PUBLIC_KEY_ID_TO_CERTIFY>` The id of a public key to certify

`--certificate-id-to-re-certify [-n] <CERTIFICATE_ID_TO_RE_CERTIFY>` The id of a certificate to re-certify

`--generate-key-pair [-g] <GENERATE_KEY_PAIR>` Generate a keypair then sign the public key and generate a certificate

Possible values:  `"true", "false"`

`--subject-name [-s] <SUBJECT_NAME>` When certifying a public key, or generating a keypair,
the subject name to use.

`--algorithm [-a] <ALGORITHM>` The algorithm to use for the keypair generation

Possible values:  `"nist-p192", "nist-p224", "nist-p256", "nist-p384", "nist-p521", "ed25519", "ed448", "rsa1024", "rsa2048", "rsa3072", "rsa4096"` [default: `"rsa4096"`]

`--issuer-private-key-id [-k] <ISSUER_PRIVATE_KEY_ID>` The unique identifier of the private key of the issuer. A certificate must be linked to that private key if no issuer certificate id is provided

`--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID>` The unique identifier of the certificate of the issuer. A private key must be linked to that certificate if no issuer private key id is provided

`--days [-d] <NUMBER_OF_DAYS>` The requested number of validity days The server may grant a different value

`--certificate-extensions [-e] <CERTIFICATE_EXTENSIONS>` The path to a X509 extension's file, containing a `v3_ca` paragraph
with the x509 extensions to use. For instance:

`--tag [-t] <TAG>` The tag to associate to the certificate. To specify multiple tags, use the option multiple times



---

## 7.2 ckms certificates decrypt

Decrypt a file using the private key of a certificate

### Usage
`ckms certificates decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <PRIVATE_KEY_ID>` The private key unique identifier related to certificate If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` Optional encryption algorithm.
This is only available for RSA keys for now.
The default for RSA is `PKCS_OAEP`.

Possible values:  `"ckm-rsa-pkcs", "ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"`



---

## 7.3 ckms certificates encrypt

Encrypt a file using the certificate public key

### Usage
`ckms certificates encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data. This data needs to be provided back for decryption

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` Optional encryption algorithm.
This is only available for RSA keys for now.
The default for RSA is `PKCS_OAEP`.

Possible values:  `"ckm-rsa-pkcs", "ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"`



---

## 7.4 ckms certificates export

Export a certificate from the KMS

### Usage
`ckms certificates export [options] <CERTIFICATE_FILE>
`
### Arguments
` <CERTIFICATE_FILE>` The file to export the certificate to

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate/private key when no unique id is specified.
To specify multiple tags, use the option multiple times.

`--format [-f] <OUTPUT_FORMAT>` Export the certificate in the selected format

Possible values:  `"json-ttlv", "pem", "pkcs12", "pkcs12-legacy", "pkcs7"` [default: `"json-ttlv"`]

`--pkcs12-password [-p] <PKCS12_PASSWORD>` Password to use to protect the PKCS#12 file

`--allow-revoked [-r] <ALLOW_REVOKED>` Allow exporting revoked and destroyed certificates or private key (for PKCS#12).
The user must be the owner of the certificate.
Destroyed objects have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]



---

## 7.5 ckms certificates import

Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

### Usage
`ckms certificates import [options] [CERTIFICATE_FILE]
 [CERTIFICATE_ID]
`
### Arguments
` <CERTIFICATE_FILE>` The input file in PEM, KMIP-JSON-TTLV or PKCS#12 format

` <CERTIFICATE_ID>` The unique id of the leaf certificate; a unique id
based on the key material is generated if not specified.
When importing a PKCS12, the unique id will be that of the private key.

`--format [-f] <INPUT_FORMAT>` Import the certificate in the selected format

Possible values:  `"json-ttlv", "pem", "der", "chain", "pkcs12", "ccadb"` [default: `"json-ttlv"`]

`--private-key-id [-k] <PRIVATE_KEY_ID>` The corresponding private key id if any. Ignored for PKCS12 and CCADB formats

`--public-key-id [-q] <PUBLIC_KEY_ID>` The corresponding public key id if any. Ignored for PKCS12 and CCADB formats

`--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID>` The issuer certificate id if any. Ignored for PKCS12 and CCADB formats

`--pkcs12-password [-p] <PKCS12_PASSWORD>` PKCS12 password: only available for PKCS12 format

`--replace [-r] <REPLACE_EXISTING>` Replace an existing certificate under the same id

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the certificate. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` For what operations should the certificate be used

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`



---

## 7.6 ckms certificates revoke

Revoke a certificate

### Usage
`ckms certificates revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 7.7 ckms certificates destroy

Destroy a certificate

### Usage
`ckms certificates destroy [options]`
### Arguments
`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the certificate should be removed from the database
If not specified, the certificate will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]



---

## 7.8 ckms certificates validate

Validate a certificate

### Usage
`ckms certificates validate [options]`
### Arguments
`--certificate-id [-k] <CERTIFICATE_ID>` One or more Unique Identifiers of Certificate Objects

`--validity-time [-t] <VALIDITY_TIME>` A Date-Time object indicating when the certificate chain needs to be valid. If omitted, the current date and time SHALL be assumed




---

## 8 ckms derive-key

Derive a new key from an existing key

### Usage
`ckms derive-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The unique identifier of the base key to derive from Mutually exclusive with --password

`--password [-p] <PASSWORD>` UTF-8 password to use as base material for key derivation Will create a `SecretData` of type Password internally Mutually exclusive with --key-id

`--derivation-method [-m] <DERIVATION_METHOD>` The derivation method to use (PBKDF2 or HKDF)

`--salt [-s] <SALT>` Salt for key derivation (in hex format)

`--iteration-count [-i] <ITERATION_COUNT>` Number of iterations for PBKDF2 derivation

`--initialization-vector [-v] <INITIALIZATION_VECTOR>` Initialization vector for derivation (in hex format)

`--digest-algorithm [-d] <DIGEST_ALGORITHM>` Digest algorithm for derivation

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"SHA256"`]

`--algorithm [-a] <ALGORITHM>` The algorithm

Possible values:  `"chacha20", "aes", "sha3", "shake"` [default: `"aes"`]

`--length [-l] <CRYPTOGRAPHIC_LENGTH>` Length of the derived key in bits

`--derived-key-id <DERIVED_KEY_ID>` Optional unique identifier for the derived key



---

## 9 ckms ec

Manage elliptic curve keys. Encrypt and decrypt data using ECIES

### Usage
`ckms ec <subcommand>`

### Subcommands

**`keys`** [[9.1]](#91-ckms-ec-keys)  Create, destroy, import, and export elliptic curve key pairs

**`encrypt`** [[9.2]](#92-ckms-ec-encrypt)  Encrypt a file with the given public key using ECIES

**`decrypt`** [[9.3]](#93-ckms-ec-decrypt)  Decrypts a file with the given private key using ECIES

**`sign`** [[9.4]](#94-ckms-ec-sign)  Sign a file using elliptic curve digital signature algorithms (ECDSA)

**`sign-verify`** [[9.5]](#95-ckms-ec-sign-verify)  Verify an ECDSA signature for a given data file

---

## 9.1 ckms ec keys

Create, destroy, import, and export elliptic curve key pairs

### Usage
`ckms ec keys <subcommand>`

### Subcommands

**`create`** [[9.1.1]](#911-ckms-ec-keys-create)  Create an elliptic curve key pair

**`export`** [[9.1.2]](#912-ckms-ec-keys-export)  Export a key or secret data from the KMS

**`import`** [[9.1.3]](#913-ckms-ec-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[9.1.4]](#914-ckms-ec-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[9.1.5]](#915-ckms-ec-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[9.1.6]](#916-ckms-ec-keys-revoke)  Revoke a public or private key

**`destroy`** [[9.1.7]](#917-ckms-ec-keys-destroy)  Destroy a public or private key

---

## 9.1.1 ckms ec keys create

Create an elliptic curve key pair

### Usage
`ckms ec keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p256", "nist-p384", "nist-p521", "x25519", "ed25519", "x448", "ed448", "secp256k1", "secp224k1"` [default: `"nist-p256"`]

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 9.1.2 ckms ec keys export

Export a key or secret data from the KMS

### Usage
`ckms ec keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 9.1.3 ckms ec keys import

Import a secret data or a key in the KMS.

### Usage
`ckms ec keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 9.1.4 ckms ec keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms ec keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into an AES-256 symmetric key. For security reasons, a fresh salt is internally generated by `cosmian` and handled, and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The ID of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 9.1.5 ckms ec keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms ec keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 9.1.6 ckms ec keys revoke

Revoke a public or private key

### Usage
`ckms ec keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 9.1.7 ckms ec keys destroy

Destroy a public or private key

### Usage
`ckms ec keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 9.2 ckms ec encrypt

Encrypt a file with the given public key using ECIES

### Usage
`ckms ec encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 9.3 ckms ec decrypt

Decrypts a file with the given private key using ECIES

### Usage
`ckms ec decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 9.4 ckms ec sign

Sign a file using elliptic curve digital signature algorithms (ECDSA)

### Usage
`ckms ec sign [options] <FILE>
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p256", "nist-p384", "nist-p521", "x25519", "ed25519", "x448", "ed448", "secp256k1", "secp224k1"` [default: `"nist-p256"`]

` <FILE>` The file to sign

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The signature output file path

`--digested <DIGESTED>` Treat input as already-digested data (pre-hash)

Possible values:  `"true", "false"`



---

## 9.5 ckms ec sign-verify

Verify an ECDSA signature for a given data file

### Usage
`ckms ec sign-verify [options] <FILE>
 <SIGNATURE_FILE>
`
### Arguments
` <FILE>` The data that was signed

` <SIGNATURE_FILE>` The signature file

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` Optional output file path

`--digested <DIGESTED>` Treat data input as already-digested (pre-hash)

Possible values:  `"true", "false"`




---

## 10 ckms google

Manage google elements. Handle key pairs and identities from Gmail API

### Usage
`ckms google <subcommand>`

### Subcommands

**`key-pairs`** [[10.1]](#101-ckms-google-key-pairs)  Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

**`identities`** [[10.2]](#102-ckms-google-identities)  Insert, get, list, patch and delete identities from Gmail API

---

## 10.1 ckms google key-pairs

Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

### Usage
`ckms google key-pairs <subcommand>`

### Subcommands

**`get`** [[10.1.1]](#1011-ckms-google-key-pairs-get)  Retrieves an existing client-side encryption key pair.

**`list`** [[10.1.2]](#1012-ckms-google-key-pairs-list)  Lists client-side encryption key pairs for a user.

**`enable`** [[10.1.3]](#1013-ckms-google-key-pairs-enable)  Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

**`disable`** [[10.1.4]](#1014-ckms-google-key-pairs-disable)  Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

**`obliterate`** [[10.1.5]](#1015-ckms-google-key-pairs-obliterate)  Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

**`create`** [[10.1.6]](#1016-ckms-google-key-pairs-create)  Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

---

## 10.1.1 ckms google key-pairs get

Retrieves an existing client-side encryption key pair.

### Usage
`ckms google key-pairs get [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to retrieve

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 10.1.2 ckms google key-pairs list

Lists client-side encryption key pairs for a user.

### Usage
`ckms google key-pairs list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 10.1.3 ckms google key-pairs enable

Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

### Usage
`ckms google key-pairs enable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to enable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 10.1.4 ckms google key-pairs disable

Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

### Usage
`ckms google key-pairs disable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to disable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 10.1.5 ckms google key-pairs obliterate

Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

### Usage
`ckms google key-pairs obliterate [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to obliterate

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 10.1.6 ckms google key-pairs create

Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

### Usage
`ckms google key-pairs create [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address

`--cse-key-id <CSE_KEY_ID>` CSE key ID to wrap exported user private key

`--subject-name [-s] <SUBJECT_NAME>` When certifying a public key, or generating a keypair,
the subject name to use.
For instance: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US"

`--rsa-private-key-id [-k] <RSA_PRIVATE_KEY_ID>` The existing private key id of an existing RSA keypair to use (optional - if no ID is provided, a RSA keypair will be created)

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)

`--issuer-private-key-id [-i] <ISSUER_PRIVATE_KEY_ID>` The issuer private key id - required when generating a new leaf certificate

`--leaf-certificate-extensions [-e] <LEAF_CERTIFICATE_EXTENSIONS>` Path to a file containing X.509 extensions, defined under a `[v3_ca]` section.
These extensions will be applied to the generated leaf certificate and must
comply with Google's S/MIME certificate requirements. For example:
```text
[ v3_ca ]
keyUsage=nonRepudiation,digitalSignature,dataEncipherment,keyEncipherment
extendedKeyUsage=emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
```
This parameter is ignored when using an existing leaf certificate.

`--leaf-certificate-id <LEAF_CERTIFICATE_ID>` The ID of an existing leaf certificate in KMS to use instead of generating a new one.
This certificate must be compatible with the private key being used.
Cannot be used together with --leaf-certificate-file.

`--leaf-certificate-pkcs12-file <LEAF_CERTIFICATE_PKCS12_FILE>` Path to a local leaf PKCS12 certificate file to use instead of generating a new one.
This PKCS12 certificate also holds the private key.
Cannot be used together with --leaf-certificate-id neither --leaf-certificate-extensions.

`--leaf-certificate-pkcs12-password <LEAF_CERTIFICATE_PKCS12_PASSWORD>` The password for the PKCS12 file containing the leaf certificate.

`--days [-d] <NUMBER_OF_DAYS>` The requested number of validity days The server may grant a different value

`--dry-run <DRY_RUN>` Dry run mode. If set, the action will not be executed

Possible values:  `"true", "false"` [default: `"false"`]




---

## 10.2 ckms google identities

Insert, get, list, patch and delete identities from Gmail API

### Usage
`ckms google identities <subcommand>`

### Subcommands

**`get`** [[10.2.1]](#1021-ckms-google-identities-get)  Retrieves a client-side encryption identity configuration.

**`list`** [[10.2.2]](#1022-ckms-google-identities-list)  Lists the client-side encrypted identities for an authenticated user.

**`insert`** [[10.2.3]](#1023-ckms-google-identities-insert)  Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

**`delete`** [[10.2.4]](#1024-ckms-google-identities-delete)  Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

**`patch`** [[10.2.5]](#1025-ckms-google-identities-patch)  Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

---

## 10.2.1 ckms google identities get

Retrieves a client-side encryption identity configuration.

### Usage
`ckms google identities get [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 10.2.2 ckms google identities list

Lists the client-side encrypted identities for an authenticated user.

### Usage
`ckms google identities list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 10.2.3 ckms google identities insert

Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

### Usage
`ckms google identities insert [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The keypair id, associated with a given cert/key. You can get the by listing the keypairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 10.2.4 ckms google identities delete

Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

### Usage
`ckms google identities delete [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 10.2.5 ckms google identities patch

Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

### Usage
`ckms google identities patch [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The key pair id, associated with a given cert/key. You can get the by listing the key pairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved





---

## 11 ckms locate

Locate cryptographic objects inside the KMS

### Usage
`ckms locate [options]`
### Arguments
`--tag [-t] <TAG>` User tags or system tags to locate the object.
To specify multiple tags, use the option multiple times.

`--algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` Cryptographic algorithm (case insensitive)

`--cryptographic-length [-l] <CRYPTOGRAPHIC_LENGTH>` Cryptographic length (e.g. key size) in bits

`--key-format-type [-f] <KEY_FORMAT_TYPE>` Key format type (case insensitive)

`--object-type [-o] <OBJECT_TYPE>` Object type (case insensitive)

`--public-key-id [-p] <PUBLIC_KEY_ID>` Locate an object which has a link to this public key id

`--private-key-id [-k] <PRIVATE_KEY_ID>` Locate an object which has a link to this private key id

`--certificate-id [-c] <CERTIFICATE_ID>` Locate an object which has a link to this certificate key id



---

## 12 ckms login

Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

### Usage
`ckms login`


---

## 13 ckms logout

Logout from the Identity Provider

### Usage
`ckms logout`


---

## 14 ckms hash

Hash arbitrary data.

### Usage
`ckms hash [options]`
### Arguments
`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to be hashed in hexadecimal format

`--correlation-value [-c] <CORRELATION_VALUE>` Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation)

`--init-indicator [-i] <INIT_INDICATOR>` Initial operation as Boolean

Possible values:  `"true", "false"`

`--final-indicator [-f] <FINAL_INDICATOR>` Final operation as Boolean

Possible values:  `"true", "false"`



---

## 15 ckms mac

MAC utilities: compute or verify a MAC value.

### Usage
`ckms mac <subcommand>`

### Subcommands

**`compute`** [[15.1]](#151-ckms-mac-compute)  Compute a MAC over data with a MAC key

**`verify`** [[15.2]](#152-ckms-mac-verify)  Verify a MAC over data with a MAC key

---

## 15.1 ckms mac compute

Compute a MAC over data with a MAC key

### Usage
`ckms mac compute [options]`
### Arguments
`--mac-key-id [-k] <MAC_KEY_ID>` Locate an object which has a link to this MAC key id

`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to be hashed in hexadecimal format. The data to be hashed in hexadecimal format

`--correlation-value [-c] <CORRELATION_VALUE>` Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation). The correlation value is represented as a hexadecimal string

`--init-indicator [-i] <INIT_INDICATOR>` Initial operation as Boolean

Possible values:  `"true", "false"`

`--final-indicator [-f] <FINAL_INDICATOR>` Final operation as Boolean

Possible values:  `"true", "false"`



---

## 15.2 ckms mac verify

Verify a MAC over data with a MAC key

### Usage
`ckms mac verify [options]`
### Arguments
`--mac-key-id [-k] <MAC_KEY_ID>` Locate an object which has a link to this MAC key id

`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to verify in hexadecimal format

`--mac [-m] <MAC_HEX>` The MAC to verify in hexadecimal format




---

## 16 ckms rng

RNG utilities: retrieve random bytes or seed RNG

### Usage
`ckms rng <subcommand>`

### Subcommands

**`retrieve`** [[16.1]](#161-ckms-rng-retrieve)  Retrieve cryptographically secure random bytes from the server RNG

**`seed`** [[16.2]](#162-ckms-rng-seed)  Seed the server RNG with provided hex-encoded bytes

---

## 16.1 ckms rng retrieve

Retrieve cryptographically secure random bytes from the server RNG

### Usage
`ckms rng retrieve [options]`
### Arguments
`--length [-l] <LENGTH>` Number of bytes to retrieve



---

## 16.2 ckms rng seed

Seed the server RNG with provided hex-encoded bytes

### Usage
`ckms rng seed [options]`
### Arguments
`--data [-d] <DATA>` Seed data as hex string




---

## 17 ckms discover-versions

Discover KMIP protocol versions supported by the server

### Usage
`ckms discover-versions`


---

## 18 ckms query

Query server capabilities and metadata (KMIP Query)

### Usage
`ckms query`


---

## 19 ckms rsa

Manage RSA keys. Encrypt and decrypt data using RSA keys

### Usage
`ckms rsa <subcommand>`

### Subcommands

**`keys`** [[19.1]](#191-ckms-rsa-keys)  Create, destroy, import, and export RSA key pairs

**`encrypt`** [[19.2]](#192-ckms-rsa-encrypt)  Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`decrypt`** [[19.3]](#193-ckms-rsa-decrypt)  Decrypt a file with the given private key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`sign`** [[19.4]](#194-ckms-rsa-sign)  Digital signature supported is RSASSA-PSS

**`sign-verify`** [[19.5]](#195-ckms-rsa-sign-verify)  Verify an RSASSA-PSS signature for a given data file

---

## 19.1 ckms rsa keys

Create, destroy, import, and export RSA key pairs

### Usage
`ckms rsa keys <subcommand>`

### Subcommands

**`create`** [[19.1.1]](#1911-ckms-rsa-keys-create)  Create a new RSA key pair

**`export`** [[19.1.2]](#1912-ckms-rsa-keys-export)  Export a key or secret data from the KMS

**`import`** [[19.1.3]](#1913-ckms-rsa-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[19.1.4]](#1914-ckms-rsa-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[19.1.5]](#1915-ckms-rsa-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[19.1.6]](#1916-ckms-rsa-keys-revoke)  Revoke a public or private key

**`destroy`** [[19.1.7]](#1917-ckms-rsa-keys-destroy)  Destroy a public or private key

---

## 19.1.1 ckms rsa keys create

Create a new RSA key pair

### Usage
`ckms rsa keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--size_in_bits [-s] <SIZE_IN_BITS>` The expected size in bits

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the private key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap the keypair with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 19.1.2 ckms rsa keys export

Export a key or secret data from the KMS

### Usage
`ckms rsa keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 19.1.3 ckms rsa keys import

Import a secret data or a key in the KMS.

### Usage
`ckms rsa keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 19.1.4 ckms rsa keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms rsa keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into an AES-256 symmetric key. For security reasons, a fresh salt is internally generated by `cosmian` and handled, and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The ID of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 19.1.5 ckms rsa keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms rsa keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 19.1.6 ckms rsa keys revoke

Revoke a public or private key

### Usage
`ckms rsa keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 19.1.7 ckms rsa keys destroy

Destroy a public or private key

### Usage
`ckms rsa keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 19.2 ckms rsa encrypt

Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`ckms rsa encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` The encryption algorithm

Possible values:  `"ckm-rsa-pkcs", "ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"` [default: `"ckm-rsa-pkcs-oaep"`]

`--hashing-algorithm [-s] <HASH_FN>` The hashing algorithm

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"sha256"`]

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 19.3 ckms rsa decrypt

Decrypt a file with the given private key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`ckms rsa decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` The encryption algorithm

Possible values:  `"ckm-rsa-pkcs", "ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"` [default: `"ckm-rsa-pkcs-oaep"`]

`--hashing-algorithm [-s] <HASH_FN>` The hashing algorithm (for OAEP and AES key wrap)

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"sha256"`]

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 19.4 ckms rsa sign

Digital signature supported is RSASSA-PSS

### Usage
`ckms rsa sign [options] <FILE>
`
### Arguments
` <FILE>` The file to sign

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The signature output file path

`--digested <DIGESTED>` Treat input as already-digested data (pre-hash)

Possible values:  `"true", "false"`



---

## 19.5 ckms rsa sign-verify

Verify an RSASSA-PSS signature for a given data file

### Usage
`ckms rsa sign-verify [options] <FILE>
 <SIGNATURE_FILE>
`
### Arguments
` <FILE>` The data that was signed

` <SIGNATURE_FILE>` The signature file

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` Optional output file path

`--digested <DIGESTED>` Treat data input as already-digested (pre-hash)

Possible values:  `"true", "false"`




---

## 20 ckms opaque-object

Create, import, export, revoke and destroy Opaque Objects

### Usage
`ckms opaque-object <subcommand>`

### Subcommands

**`create`** [[20.1]](#201-ckms-opaque-object-create)  Create (register) an `OpaqueObject` by importing raw bytes.

**`export`** [[20.2]](#202-ckms-opaque-object-export)  Export a key or secret data from the KMS

**`import`** [[20.3]](#203-ckms-opaque-object-import)  Import a secret data or a key in the KMS.

**`revoke`** [[20.4]](#204-ckms-opaque-object-revoke)  Revoke an `OpaqueObject`

**`destroy`** [[20.5]](#205-ckms-opaque-object-destroy)  Destroy an `OpaqueObject`

---

## 20.1 ckms opaque-object create

Create (register) an `OpaqueObject` by importing raw bytes.

### Usage
`ckms opaque-object create [options]`
### Arguments
`--file [-f] <FILE>` Optional file containing the opaque bytes to import

`--data [-d] <DATA>` Inline opaque data as a UTF-8 string. If provided, it's used instead of --file bytes

`--type <OPAQUE_TYPE>` Opaque data type (defaults to Vendor)

`--id <ID>` Optional object unique identifier to assign; otherwise server generates one

`--tag [-t] <TAG>` Tags to associate with the object. Repeat to add multiple tags



---

## 20.2 ckms opaque-object export

Export a key or secret data from the KMS

### Usage
`ckms opaque-object export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 20.3 ckms opaque-object import

Import a secret data or a key in the KMS.

### Usage
`ckms opaque-object import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 20.4 ckms opaque-object revoke

Revoke an `OpaqueObject`

### Usage
`ckms opaque-object revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <OBJECT_ID>` The opaque object unique identifier to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tags to locate the object if id is not provided. Repeat to specify multiple tags



---

## 20.5 ckms opaque-object destroy

Destroy an `OpaqueObject`

### Usage
`ckms opaque-object destroy [options]`
### Arguments
`--key-id [-k] <OBJECT_ID>` The opaque object unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tags to locate the object if id is not provided. Repeat to specify multiple tags

`--remove <REMOVE>` If the object should be removed from the database. If not specified, the object will be destroyed
but its metadata will still be available.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 21 ckms secret-data

Create, import, export and destroy secret data

### Usage
`ckms secret-data <subcommand>`

### Subcommands

**`create`** [[21.1]](#211-ckms-secret-data-create)  Create a new secret data

**`export`** [[21.2]](#212-ckms-secret-data-export)  Export a key or secret data from the KMS

**`import`** [[21.3]](#213-ckms-secret-data-import)  Import a secret data or a key in the KMS.

**`wrap`** [[21.4]](#214-ckms-secret-data-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[21.5]](#215-ckms-secret-data-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[21.6]](#216-ckms-secret-data-revoke)  Revoke a secret data

**`destroy`** [[21.7]](#217-ckms-secret-data-destroy)  Destroy a secret data

---

## 21.1 ckms secret-data create

Create a new secret data

### Usage
`ckms secret-data create [options] [SECRET_ID]
`
### Arguments
`--value [-v] <SECRET_VALUE>` Optional secret data string, UTF-8 encoded. If not provided, a random 32-byte seed will be generated

`--type <SECRET_TYPE>` The type of secret data. Defaults to a randomly generated Seed. To use a Password type, you must provide both this and a valid secret value

Possible values:  `"password", "seed"` [default: `"seed"`]

`--tag [-t] <TAG>` The tag to associate with the secret data. To specify multiple tags, use the option multiple times

` <SECRET_ID>` The unique id of the secret; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the secret will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this new secret data with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 21.2 ckms secret-data export

Export a key or secret data from the KMS

### Usage
`ckms secret-data export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 21.3 ckms secret-data import

Import a secret data or a key in the KMS.

### Usage
`ckms secret-data import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 21.4 ckms secret-data wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms secret-data wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into an AES-256 symmetric key. For security reasons, a fresh salt is internally generated by `cosmian` and handled, and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The ID of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 21.5 ckms secret-data unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms secret-data unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 21.6 ckms secret-data revoke

Revoke a secret data

### Usage
`ckms secret-data revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--secret-data-id [-s] <SECRET_ID>` The secret unique identifier of the secret to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the secret data when no secret data id is specified. To specify multiple tags, use the option multiple times



---

## 21.7 ckms secret-data destroy

Destroy a secret data

### Usage
`ckms secret-data destroy [options]`
### Arguments
`--key-id [-s] <SECRET_ID>` The secret unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the secret when no secret id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the secret should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 22 ckms server-version

Print the version of the server

### Usage
`ckms server-version`


---

## 23 ckms sym

Manage symmetric keys. Encrypt and decrypt data

### Usage
`ckms sym <subcommand>`

### Subcommands

**`keys`** [[23.1]](#231-ckms-sym-keys)  Create, destroy, import, and export symmetric keys

**`encrypt`** [[23.2]](#232-ckms-sym-encrypt)  Encrypt a file using a symmetric cipher

**`decrypt`** [[23.3]](#233-ckms-sym-decrypt)  Decrypt a file using a symmetric key.

---

## 23.1 ckms sym keys

Create, destroy, import, and export symmetric keys

### Usage
`ckms sym keys <subcommand>`

### Subcommands

**`create`** [[23.1.1]](#2311-ckms-sym-keys-create)  Create a new symmetric key

**`re-key`** [[23.1.2]](#2312-ckms-sym-keys-re-key)  Refresh an existing symmetric key

**`export`** [[23.1.3]](#2313-ckms-sym-keys-export)  Export a key or secret data from the KMS

**`import`** [[23.1.4]](#2314-ckms-sym-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[23.1.5]](#2315-ckms-sym-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[23.1.6]](#2316-ckms-sym-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[23.1.7]](#2317-ckms-sym-keys-revoke)  Revoke a symmetric key

**`destroy`** [[23.1.8]](#2318-ckms-sym-keys-destroy)  Destroy a symmetric key

---

## 23.1.1 ckms sym keys create

Create a new symmetric key

### Usage
`ckms sym keys create [options] [KEY_ID]
`
### Arguments
`--number-of-bits [-l] <NUMBER_OF_BITS>` The length of the generated random key or salt in bits

`--bytes-b64 [-k] <WRAP_KEY_B64>` The symmetric key bytes or salt as a base 64 string

`--algorithm [-a] <ALGORITHM>` The algorithm

Possible values:  `"chacha20", "aes", "sha3", "shake"` [default: `"aes"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this new key with.
If the wrapping key is:

- a symmetric key, AES-GCM will be used
- a RSA key, RSA-OAEP will be used
- a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 23.1.2 ckms sym keys re-key

Refresh an existing symmetric key

### Usage
`ckms sym keys re-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 23.1.3 ckms sym keys export

Export a key or secret data from the KMS

### Usage
`ckms sym keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key or secret data unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key or secret data id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <EXPORT_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys
      - secret data

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate (a.k.a. Key Encryption Key - KEK) to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
The possible wrapping algorithms are

 - using a symmetric KEK:
    - `nist-key-wrap` (default - a.k.a RFC 5649, `CKM_AES_KEY_WRAP_PAD`)
    - `aes-gcm`
 - using an RSA KEK:
    - `rsa-oaep` (default - CKM-RSA-OAEP)
    - `rsa-aes-key-wrap` (CKM-RSA-AES-KEY-WRP)
    - `rsa-pkcs-v15` (CKM-RSA v1.5)

Possible values:  `"aes-key-wrap-padding", "nist-key-wrap", "aes-gcm", "rsa-pkcs-v15-sha1", "rsa-pkcs-v15", "rsa-oaep-sha1", "rsa-oaep", "rsa-aes-key-wrap-sha1", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 23.1.4 ckms sym keys import

Import a secret data or a key in the KMS.

### Usage
`ckms sym keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The file holding the key or secret data to import

` <KEY_ID>` The unique ID of the key; a random UUID is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8-priv", "pkcs8-pub", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key ID, if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key ID, if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate ID, if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same ID

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` The cryptographic operations the key is allowed to perform

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key encryption key (KEK) used to wrap this imported key with.
If the wrapping key is:

- A symmetric key, AES-GCM will be used,
- An RSA key, RSA-OAEP with SHA-256 will be used,
- An EC key, ECIES will be used (salsa20poly1305 for X25519),



---

## 23.1.5 ckms sym keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms sym keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into an AES-256 symmetric key. For security reasons, a fresh salt is internally generated by `cosmian` and handled, and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The ID of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 23.1.6 ckms sym keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`ckms sym keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 23.1.7 ckms sym keys revoke

Revoke a symmetric key

### Usage
`ckms sym keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 23.1.8 ckms sym keys destroy

Destroy a symmetric key

### Usage
`ckms sym keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 23.2 ckms sym encrypt

Encrypt a file using a symmetric cipher

### Usage
`ckms sym encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The symmetric key unique identifier. If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, `aes-gcm` is used

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-cbc", "aes-xts", "aes-gcm-siv"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to encrypt the data encryption key.

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv", "rfc3394", "rfc5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--nonce [-n] <NONCE>` Optional nonce/IV (or tweak for XTS) as a hex string. If not provided, a random value is generated

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 23.3 ckms sym decrypt

Decrypt a file using a symmetric key.

### Usage
`ckms sym decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm.
If not specified, aes-gcm is used.

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-cbc", "aes-xts", "aes-gcm-siv"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to decrypt the data encryption key.

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv", "rfc3394", "rfc5649"`

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption as a hex string




---

## 24 ckms markdown

Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

### Usage
`ckms markdown [options] <MARKDOWN_FILE>
`
### Arguments
` <MARKDOWN_FILE>` The file to export the markdown to



---

## 25 ckms configure

Configure the KMS CLI (create ckms.toml)

### Usage
`ckms configure`





##  cosmian

Command Line Interface used to manage the Cosmian KMS server.

If any assistance is needed, please either visit the Cosmian technical documentation at https://docs.cosmian.com
or contact the Cosmian support team on Discord https://discord.com/invite/7kPMNtHpnz


### Usage
`cosmian <subcommand> [options]`
### Arguments
`--conf-path [-c] <CONF_PATH>` Configuration file location

`--url <URL>` The URL of the KMS

`--print-json <PRINT_JSON>` Output the KMS JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint

Possible values:  `"true", "false"`

`--accept-invalid-certs <ACCEPT_INVALID_CERTS>` Allow to connect using a self-signed cert or untrusted cert chain

Possible values:  `"true", "false"`

`--proxy-url <PROXY_URL>` The proxy URL:

  - e.g., `https://secure.example` for an HTTP proxy
  - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy

`--proxy-basic-auth-username <PROXY_BASIC_AUTH_USERNAME>` Set the Proxy-Authorization header username using Basic auth.

`--proxy-basic-auth-password <PROXY_BASIC_AUTH_PASSWORD>` Set the Proxy-Authorization header password using Basic auth.

`--proxy-custom-auth-header <PROXY_CUSTOM_AUTH_HEADER>` Set the Proxy-Authorization header to a specified value.

`--proxy-exclusion-list <PROXY_EXCLUSION_LIST>` The No Proxy exclusion list to this Proxy


### Subcommands

**`access-rights`** [[1]](#1-cosmian-access-rights)  Manage the users' access rights to the cryptographic objects

**`attributes`** [[2]](#2-cosmian-attributes)  Get/Set/Delete the KMIP object attributes

**`azure`** [[3]](#3-cosmian-azure)  Support for Azure specific interactions

**`bench`** [[4]](#4-cosmian-bench)  Run a set of benches to check the server performance

**`certificates`** [[5]](#5-cosmian-certificates)  Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

**`derive-key`** [[6]](#6-cosmian-derive-key)  Derive a new key from an existing key

**`ec`** [[7]](#7-cosmian-ec)  Manage elliptic curve keys. Encrypt and decrypt data using ECIES

**`google`** [[8]](#8-cosmian-google)  Manage google elements. Handle key pairs and identities from Gmail API

**`locate`** [[9]](#9-cosmian-locate)  Locate cryptographic objects inside the KMS

**`login`** [[10]](#10-cosmian-login)  Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

**`logout`** [[11]](#11-cosmian-logout)  Logout from the Identity Provider

**`hash`** [[12]](#12-cosmian-hash)  Hash arbitrary data.

**`mac`** [[13]](#13-cosmian-mac)  MAC utilities: compute or verify a MAC value.

**`rng`** [[14]](#14-cosmian-rng)  RNG utilities: retrieve random bytes or seed RNG

**`discover-versions`** [[15]](#15-cosmian-discover-versions)  Discover KMIP protocol versions supported by the server

**`query`** [[16]](#16-cosmian-query)  Query server capabilities and metadata (KMIP Query)

**`rsa`** [[17]](#17-cosmian-rsa)  Manage RSA keys. Encrypt and decrypt data using RSA keys

**`opaque-object`** [[18]](#18-cosmian-opaque-object)  Create, import, export, revoke and destroy Opaque Objects

**`secret-data`** [[19]](#19-cosmian-secret-data)  Create, import, export and destroy secret data

**`server-version`** [[20]](#20-cosmian-server-version)  Print the version of the server

**`sym`** [[21]](#21-cosmian-sym)  Manage symmetric keys. Encrypt and decrypt data

**`markdown`** [[22]](#22-cosmian-markdown)  Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

**`configure`** [[23]](#23-cosmian-configure)  Configure the KMS CLI (creates/updates cosmian.toml)

---

## 1 cosmian access-rights

Manage the users' access rights to the cryptographic objects

### Usage
`cosmian access-rights <subcommand>`

### Subcommands

**`grant`** [[1.1]](#11-cosmian-access-rights-grant)  Grant another user one or multiple access rights to an object

**`revoke`** [[1.2]](#12-cosmian-access-rights-revoke)  Revoke another user one or multiple access rights to an object

**`list`** [[1.3]](#13-cosmian-access-rights-list)  List the access rights granted on an object to other users

**`owned`** [[1.4]](#14-cosmian-access-rights-owned)  List the objects owned by the calling user

**`obtained`** [[1.5]](#15-cosmian-access-rights-obtained)  List the access rights obtained by the calling user

---

## 1.1 cosmian access-rights grant

Grant another user one or multiple access rights to an object

### Usage
`cosmian access-rights grant [options] <USER>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user identifier to allow

`--object-uid [-i] <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`, `get_attributes`)



---

## 1.2 cosmian access-rights revoke

Revoke another user one or multiple access rights to an object

### Usage
`cosmian access-rights revoke [options] <USER>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user to revoke access to

`--object-uid [-i] <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to revoke (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)



---

## 1.3 cosmian access-rights list

List the access rights granted on an object to other users

### Usage
`cosmian access-rights list [options] <OBJECT_UID>
`
### Arguments
` <OBJECT_UID>` The object unique identifier



---

## 1.4 cosmian access-rights owned

List the objects owned by the calling user

### Usage
`cosmian access-rights owned`


---

## 1.5 cosmian access-rights obtained

List the access rights obtained by the calling user

### Usage
`cosmian access-rights obtained`



---

## 2 cosmian attributes

Get/Set/Delete the KMIP object attributes

### Usage
`cosmian attributes <subcommand>`

### Subcommands

**`get`** [[2.1]](#21-cosmian-attributes-get)  Get the KMIP object attributes and tags.

**`set`** [[2.2]](#22-cosmian-attributes-set)  Set the KMIP object attributes.

**`delete`** [[2.3]](#23-cosmian-attributes-delete)  Delete the KMIP object attributes.

---

## 2.1 cosmian attributes get

Get the KMIP object attributes and tags.

### Usage
`cosmian attributes get [options]`
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

## 2.2 cosmian attributes set

Set the KMIP object attributes.

### Usage
`cosmian attributes set [options]`
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

`--vendor-identification [-v] <VENDOR_IDENTIFICATION>` The vendor identification

`--attribute-name [-n] <ATTRIBUTE_NAME>` The attribute name

`--attribute-value <ATTRIBUTE_VALUE>` The attribute value (in hex format)



---

## 2.3 cosmian attributes delete

Delete the KMIP object attributes.

### Usage
`cosmian attributes delete [options]`
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

`--vendor-identification [-v] <VENDOR_IDENTIFICATION>` The vendor identification

`--attribute-name [-n] <ATTRIBUTE_NAME>` The attribute name

`--attribute-value <ATTRIBUTE_VALUE>` The attribute value (in hex format)

`--attribute <ATTRIBUTE>` The attributes or tags to retrieve.
To specify multiple attributes, use the option multiple times.




---

## 3 cosmian azure

Support for Azure specific interactions

### Usage
`cosmian azure <subcommand>`

### Subcommands

**`byok`** [[3.1]](#31-cosmian-azure-byok)  Azure BYOK support. See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

---

## 3.1 cosmian azure byok

Azure BYOK support. See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

### Usage
`cosmian azure byok <subcommand>`

### Subcommands

**`import`** [[3.1.1]](#311-cosmian-azure-byok-import)  Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>

**`export`** [[3.1.2]](#312-cosmian-azure-byok-export)  Wrap a KMS key with an Azure Key Encryption Key (KEK),
previously imported using the `cosmian kms azure byok import` command.
Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

---

## 3.1.1 cosmian azure byok import

Import into the KMS an RSA Key Encryption Key (KEK) generated on Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification#generate-kek>

### Usage
`cosmian azure byok import [options] <KEK_FILE>
 <KID>
 [KEY_ID]
`
### Arguments
` <KEK_FILE>` The RSA Key Encryption Key (KEK) file exported from the Azure Key Vault in PKCS#8 PEM format

` <KID>` The Azure Key ID (kid). It should be something like:
<https://mypremiumkeyvault.vault.azure.net/keys/KEK-BYOK/664f5aa2797a4075b8e36ca4500636d8>

` <KEY_ID>` The unique ID of the key in this KMS; a random UUID is generated if not specified



---

## 3.1.2 cosmian azure byok export

Wrap a KMS key with an Azure Key Encryption Key (KEK),
previously imported using the `cosmian kms azure byok import` command.
Generate the `.byok` file that can be used to import the KMS key into Azure Key Vault.
See: <https://learn.microsoft.com/en-us/azure/key-vault/keys/byok-specification>

### Usage
`cosmian azure byok export [options] <WRAPPED_KEY_ID>
 <KEK_ID>
 [BYOK_FILE]
`
### Arguments
` <WRAPPED_KEY_ID>` The unique ID of the KMS private key that will be wrapped and then exported

` <KEK_ID>` The Azure KEK ID in this KMS

` <BYOK_FILE>` The file path to export the `.byok` file to. If not specified, the file will be called `<wrapped_key_id>.byok`





---

## 4 cosmian bench

Run a set of benches to check the server performance

### Usage
`cosmian bench [options]`
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

## 5 cosmian certificates

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

### Usage
`cosmian certificates <subcommand>`

### Subcommands

**`certify`** [[5.1]](#51-cosmian-certificates-certify)  Issue or renew a X509 certificate

**`decrypt`** [[5.2]](#52-cosmian-certificates-decrypt)  Decrypt a file using the private key of a certificate

**`encrypt`** [[5.3]](#53-cosmian-certificates-encrypt)  Encrypt a file using the certificate public key

**`export`** [[5.4]](#54-cosmian-certificates-export)  Export a certificate from the KMS

**`import`** [[5.5]](#55-cosmian-certificates-import)  Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

**`revoke`** [[5.6]](#56-cosmian-certificates-revoke)  Revoke a certificate

**`destroy`** [[5.7]](#57-cosmian-certificates-destroy)  Destroy a certificate

**`validate`** [[5.8]](#58-cosmian-certificates-validate)  Validate a certificate

---

## 5.1 cosmian certificates certify

Issue or renew a X509 certificate

### Usage
`cosmian certificates certify [options]`
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

Possible values:  `"nist-p224", "nist-p256", "nist-p384", "nist-p521", "rsa2048", "rsa3072", "rsa4096"` [default: `"rsa4096"`]

`--issuer-private-key-id [-k] <ISSUER_PRIVATE_KEY_ID>` The unique identifier of the private key of the issuer. A certificate must be linked to that private key if no issuer certificate id is provided

`--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID>` The unique identifier of the certificate of the issuer. A private key must be linked to that certificate if no issuer private key id is provided

`--days [-d] <NUMBER_OF_DAYS>` The requested number of validity days The server may grant a different value

`--certificate-extensions [-e] <CERTIFICATE_EXTENSIONS>` The path to a X509 extension's file, containing a `v3_ca` paragraph
with the x509 extensions to use. For instance:

`--tag [-t] <TAG>` The tag to associate to the certificate. To specify multiple tags, use the option multiple times



---

## 5.2 cosmian certificates decrypt

Decrypt a file using the private key of a certificate

### Usage
`cosmian certificates decrypt [options] <FILE>
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

Possible values:  `"ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"`



---

## 5.3 cosmian certificates encrypt

Encrypt a file using the certificate public key

### Usage
`cosmian certificates encrypt [options] <FILE>
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

Possible values:  `"ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"`



---

## 5.4 cosmian certificates export

Export a certificate from the KMS

### Usage
`cosmian certificates export [options] <CERTIFICATE_FILE>
`
### Arguments
` <CERTIFICATE_FILE>` The file to export the certificate to

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate/private key when no unique id is specified.
To specify multiple tags, use the option multiple times.

`--format [-f] <OUTPUT_FORMAT>` Export the certificate in the selected format

Possible values:  `"json-ttlv", "pem", "pkcs12", "pkcs7"` [default: `"json-ttlv"`]

`--pkcs12-password [-p] <PKCS12_PASSWORD>` Password to use to protect the PKCS#12 file

`--allow-revoked [-r] <ALLOW_REVOKED>` Allow exporting revoked and destroyed certificates or private key (for PKCS#12).
The user must be the owner of the certificate.
Destroyed objects have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]



---

## 5.5 cosmian certificates import

Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

### Usage
`cosmian certificates import [options] [CERTIFICATE_FILE]
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

## 5.6 cosmian certificates revoke

Revoke a certificate

### Usage
`cosmian certificates revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 5.7 cosmian certificates destroy

Destroy a certificate

### Usage
`cosmian certificates destroy [options]`
### Arguments
`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the certificate should be removed from the database
If not specified, the certificate will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]



---

## 5.8 cosmian certificates validate

Validate a certificate

### Usage
`cosmian certificates validate [options]`
### Arguments
`--certificate-id [-k] <CERTIFICATE_ID>` One or more Unique Identifiers of Certificate Objects

`--validity-time [-t] <VALIDITY_TIME>` A Date-Time object indicating when the certificate chain needs to be valid. If omitted, the current date and time SHALL be assumed




---

## 6 cosmian derive-key

Derive a new key from an existing key

### Usage
`cosmian derive-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The unique identifier of the base key to derive from Mutually exclusive with --password

`--password [-p] <PASSWORD>` UTF-8 password to use as base material for key derivation Will create a `SecretData` of type Password internally Mutually exclusive with --key-id

`--derivation-method [-m] <DERIVATION_METHOD>` The derivation method to use (PBKDF2 or HKDF)

`--salt [-s] <SALT>` Salt for key derivation (in hex format)

`--iteration-count [-i] <ITERATION_COUNT>` Number of iterations for PBKDF2 derivation

`--initialization-vector [-v] <INITIALIZATION_VECTOR>` Initialization vector for derivation (in hex format)

`--digest-algorithm [-d] <DIGEST_ALGORITHM>` Digest algorithm for derivation

Possible values:  `"sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"SHA256"`]

`--algorithm [-a] <ALGORITHM>` The algorithm

Possible values:  `"aes", "sha3", "shake"` [default: `"aes"`]

`--length [-l] <CRYPTOGRAPHIC_LENGTH>` Length of the derived key in bits

`--derived-key-id <DERIVED_KEY_ID>` Optional unique identifier for the derived key



---

## 7 cosmian ec

Manage elliptic curve keys. Encrypt and decrypt data using ECIES

### Usage
`cosmian ec <subcommand>`

### Subcommands

**`keys`** [[7.1]](#71-cosmian-ec-keys)  Create, destroy, import, and export elliptic curve key pairs

**`sign`** [[7.2]](#72-cosmian-ec-sign)  Sign a file using elliptic curve digital signature algorithms (ECDSA)

**`sign-verify`** [[7.3]](#73-cosmian-ec-sign-verify)  Verify an ECDSA signature for a given data file

---

## 7.1 cosmian ec keys

Create, destroy, import, and export elliptic curve key pairs

### Usage
`cosmian ec keys <subcommand>`

### Subcommands

**`create`** [[7.1.1]](#711-cosmian-ec-keys-create)  Create an elliptic curve key pair

**`export`** [[7.1.2]](#712-cosmian-ec-keys-export)  Export a key or secret data from the KMS

**`import`** [[7.1.3]](#713-cosmian-ec-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[7.1.4]](#714-cosmian-ec-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[7.1.5]](#715-cosmian-ec-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[7.1.6]](#716-cosmian-ec-keys-revoke)  Revoke a public or private key

**`destroy`** [[7.1.7]](#717-cosmian-ec-keys-destroy)  Destroy a public or private key

---

## 7.1.1 cosmian ec keys create

Create an elliptic curve key pair

### Usage
`cosmian ec keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p256", "nist-p384", "nist-p521"` [default: `"nist-p256"`]

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

## 7.1.2 cosmian ec keys export

Export a key or secret data from the KMS

### Usage
`cosmian ec keys export [options] <KEY_FILE>
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

## 7.1.3 cosmian ec keys import

Import a secret data or a key in the KMS.

### Usage
`cosmian ec keys import [options] <KEY_FILE>
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

## 7.1.4 cosmian ec keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian ec keys wrap [options] <KEY_FILE_IN>
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

## 7.1.5 cosmian ec keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian ec keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 7.1.6 cosmian ec keys revoke

Revoke a public or private key

### Usage
`cosmian ec keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 7.1.7 cosmian ec keys destroy

Destroy a public or private key

### Usage
`cosmian ec keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 7.2 cosmian ec sign

Sign a file using elliptic curve digital signature algorithms (ECDSA)

### Usage
`cosmian ec sign [options] <FILE>
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p256", "nist-p384", "nist-p521"` [default: `"nist-p256"`]

` <FILE>` The file to sign

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The signature output file path

`--digested <DIGESTED>` Treat input as already-digested data (pre-hash)

Possible values:  `"true", "false"`



---

## 7.3 cosmian ec sign-verify

Verify an ECDSA signature for a given data file

### Usage
`cosmian ec sign-verify [options] <FILE>
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

## 8 cosmian google

Manage google elements. Handle key pairs and identities from Gmail API

### Usage
`cosmian google <subcommand>`

### Subcommands

**`key-pairs`** [[8.1]](#81-cosmian-google-key-pairs)  Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

**`identities`** [[8.2]](#82-cosmian-google-identities)  Insert, get, list, patch and delete identities from Gmail API

---

## 8.1 cosmian google key-pairs

Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

### Usage
`cosmian google key-pairs <subcommand>`

### Subcommands

**`get`** [[8.1.1]](#811-cosmian-google-key-pairs-get)  Retrieves an existing client-side encryption key pair.

**`list`** [[8.1.2]](#812-cosmian-google-key-pairs-list)  Lists client-side encryption key pairs for a user.

**`enable`** [[8.1.3]](#813-cosmian-google-key-pairs-enable)  Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

**`disable`** [[8.1.4]](#814-cosmian-google-key-pairs-disable)  Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

**`obliterate`** [[8.1.5]](#815-cosmian-google-key-pairs-obliterate)  Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

**`create`** [[8.1.6]](#816-cosmian-google-key-pairs-create)  Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

---

## 8.1.1 cosmian google key-pairs get

Retrieves an existing client-side encryption key pair.

### Usage
`cosmian google key-pairs get [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to retrieve

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 8.1.2 cosmian google key-pairs list

Lists client-side encryption key pairs for a user.

### Usage
`cosmian google key-pairs list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 8.1.3 cosmian google key-pairs enable

Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

### Usage
`cosmian google key-pairs enable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to enable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 8.1.4 cosmian google key-pairs disable

Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

### Usage
`cosmian google key-pairs disable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to disable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 8.1.5 cosmian google key-pairs obliterate

Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

### Usage
`cosmian google key-pairs obliterate [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to obliterate

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 8.1.6 cosmian google key-pairs create

Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

### Usage
`cosmian google key-pairs create [options] <USER_ID>
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

## 8.2 cosmian google identities

Insert, get, list, patch and delete identities from Gmail API

### Usage
`cosmian google identities <subcommand>`

### Subcommands

**`get`** [[8.2.1]](#821-cosmian-google-identities-get)  Retrieves a client-side encryption identity configuration.

**`list`** [[8.2.2]](#822-cosmian-google-identities-list)  Lists the client-side encrypted identities for an authenticated user.

**`insert`** [[8.2.3]](#823-cosmian-google-identities-insert)  Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

**`delete`** [[8.2.4]](#824-cosmian-google-identities-delete)  Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

**`patch`** [[8.2.5]](#825-cosmian-google-identities-patch)  Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

---

## 8.2.1 cosmian google identities get

Retrieves a client-side encryption identity configuration.

### Usage
`cosmian google identities get [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 8.2.2 cosmian google identities list

Lists the client-side encrypted identities for an authenticated user.

### Usage
`cosmian google identities list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 8.2.3 cosmian google identities insert

Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

### Usage
`cosmian google identities insert [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The keypair id, associated with a given cert/key. You can get the by listing the keypairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 8.2.4 cosmian google identities delete

Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

### Usage
`cosmian google identities delete [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 8.2.5 cosmian google identities patch

Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

### Usage
`cosmian google identities patch [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The key pair id, associated with a given cert/key. You can get the by listing the key pairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved





---

## 9 cosmian locate

Locate cryptographic objects inside the KMS

### Usage
`cosmian locate [options]`
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

## 10 cosmian login

Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

### Usage
`cosmian login`


---

## 11 cosmian logout

Logout from the Identity Provider

### Usage
`cosmian logout`


---

## 12 cosmian hash

Hash arbitrary data.

### Usage
`cosmian hash [options]`
### Arguments
`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to be hashed in hexadecimal format

`--correlation-value [-c] <CORRELATION_VALUE>` Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation)

`--init-indicator [-i] <INIT_INDICATOR>` Initial operation as Boolean

Possible values:  `"true", "false"`

`--final-indicator [-f] <FINAL_INDICATOR>` Final operation as Boolean

Possible values:  `"true", "false"`



---

## 13 cosmian mac

MAC utilities: compute or verify a MAC value.

### Usage
`cosmian mac <subcommand>`

### Subcommands

**`compute`** [[13.1]](#131-cosmian-mac-compute)  Compute a MAC over data with a MAC key

**`verify`** [[13.2]](#132-cosmian-mac-verify)  Verify a MAC over data with a MAC key

---

## 13.1 cosmian mac compute

Compute a MAC over data with a MAC key

### Usage
`cosmian mac compute [options]`
### Arguments
`--mac-key-id [-k] <MAC_KEY_ID>` Locate an object which has a link to this MAC key id

`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to be hashed in hexadecimal format. The data to be hashed in hexadecimal format

`--correlation-value [-c] <CORRELATION_VALUE>` Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation). The correlation value is represented as a hexadecimal string

`--init-indicator [-i] <INIT_INDICATOR>` Initial operation as Boolean

Possible values:  `"true", "false"`

`--final-indicator [-f] <FINAL_INDICATOR>` Final operation as Boolean

Possible values:  `"true", "false"`



---

## 13.2 cosmian mac verify

Verify a MAC over data with a MAC key

### Usage
`cosmian mac verify [options]`
### Arguments
`--mac-key-id [-k] <MAC_KEY_ID>` Locate an object which has a link to this MAC key id

`--algorithm [-a] <ALGORITHM>` Hashing algorithm (case insensitive)

Possible values:  `"sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"`

`--data [-d] <DATA>` The data to verify in hexadecimal format

`--mac [-m] <MAC_HEX>` The MAC to verify in hexadecimal format




---

## 14 cosmian rng

RNG utilities: retrieve random bytes or seed RNG

### Usage
`cosmian rng <subcommand>`

### Subcommands

**`retrieve`** [[14.1]](#141-cosmian-rng-retrieve)  Retrieve cryptographically secure random bytes from the server RNG

**`seed`** [[14.2]](#142-cosmian-rng-seed)  Seed the server RNG with provided hex-encoded bytes

---

## 14.1 cosmian rng retrieve

Retrieve cryptographically secure random bytes from the server RNG

### Usage
`cosmian rng retrieve [options]`
### Arguments
`--length [-l] <LENGTH>` Number of bytes to retrieve



---

## 14.2 cosmian rng seed

Seed the server RNG with provided hex-encoded bytes

### Usage
`cosmian rng seed [options]`
### Arguments
`--data [-d] <DATA>` Seed data as hex string




---

## 15 cosmian discover-versions

Discover KMIP protocol versions supported by the server

### Usage
`cosmian discover-versions`


---

## 16 cosmian query

Query server capabilities and metadata (KMIP Query)

### Usage
`cosmian query`


---

## 17 cosmian rsa

Manage RSA keys. Encrypt and decrypt data using RSA keys

### Usage
`cosmian rsa <subcommand>`

### Subcommands

**`keys`** [[17.1]](#171-cosmian-rsa-keys)  Create, destroy, import, and export RSA key pairs

**`encrypt`** [[17.2]](#172-cosmian-rsa-encrypt)  Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`decrypt`** [[17.3]](#173-cosmian-rsa-decrypt)  Decrypt a file with the given private key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`sign`** [[17.4]](#174-cosmian-rsa-sign)  Digital signature supported is RSASSA-PSS

**`sign-verify`** [[17.5]](#175-cosmian-rsa-sign-verify)  Verify an RSASSA-PSS signature for a given data file

---

## 17.1 cosmian rsa keys

Create, destroy, import, and export RSA key pairs

### Usage
`cosmian rsa keys <subcommand>`

### Subcommands

**`create`** [[17.1.1]](#1711-cosmian-rsa-keys-create)  Create a new RSA key pair

**`export`** [[17.1.2]](#1712-cosmian-rsa-keys-export)  Export a key or secret data from the KMS

**`import`** [[17.1.3]](#1713-cosmian-rsa-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[17.1.4]](#1714-cosmian-rsa-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[17.1.5]](#1715-cosmian-rsa-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[17.1.6]](#1716-cosmian-rsa-keys-revoke)  Revoke a public or private key

**`destroy`** [[17.1.7]](#1717-cosmian-rsa-keys-destroy)  Destroy a public or private key

---

## 17.1.1 cosmian rsa keys create

Create a new RSA key pair

### Usage
`cosmian rsa keys create [options] [PRIVATE_KEY_ID]
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

## 17.1.2 cosmian rsa keys export

Export a key or secret data from the KMS

### Usage
`cosmian rsa keys export [options] <KEY_FILE>
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

## 17.1.3 cosmian rsa keys import

Import a secret data or a key in the KMS.

### Usage
`cosmian rsa keys import [options] <KEY_FILE>
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

## 17.1.4 cosmian rsa keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian rsa keys wrap [options] <KEY_FILE_IN>
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

## 17.1.5 cosmian rsa keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian rsa keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 17.1.6 cosmian rsa keys revoke

Revoke a public or private key

### Usage
`cosmian rsa keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 17.1.7 cosmian rsa keys destroy

Destroy a public or private key

### Usage
`cosmian rsa keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 17.2 cosmian rsa encrypt

Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`cosmian rsa encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` The encryption algorithm

Possible values:  `"ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"` [default: `"ckm-rsa-pkcs-oaep"`]

`--hashing-algorithm [-s] <HASH_FN>` The hashing algorithm

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"sha256"`]

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 17.3 cosmian rsa decrypt

Decrypt a file with the given private key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`cosmian rsa decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--encryption-algorithm [-e] <ENCRYPTION_ALGORITHM>` The encryption algorithm

Possible values:  `"ckm-rsa-pkcs-oaep", "ckm-rsa-aes-key-wrap"` [default: `"ckm-rsa-pkcs-oaep"`]

`--hashing-algorithm [-s] <HASH_FN>` The hashing algorithm (for OAEP and AES key wrap)

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"sha256"`]

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path



---

## 17.4 cosmian rsa sign

Digital signature supported is RSASSA-PSS

### Usage
`cosmian rsa sign [options] <FILE>
`
### Arguments
` <FILE>` The file to sign

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The signature output file path

`--digested <DIGESTED>` Treat input as already-digested data (pre-hash)

Possible values:  `"true", "false"`



---

## 17.5 cosmian rsa sign-verify

Verify an RSASSA-PSS signature for a given data file

### Usage
`cosmian rsa sign-verify [options] <FILE>
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

## 18 cosmian opaque-object

Create, import, export, revoke and destroy Opaque Objects

### Usage
`cosmian opaque-object <subcommand>`

### Subcommands

**`create`** [[18.1]](#181-cosmian-opaque-object-create)  Create (register) an `OpaqueObject` by importing raw bytes.

**`export`** [[18.2]](#182-cosmian-opaque-object-export)  Export a key or secret data from the KMS

**`import`** [[18.3]](#183-cosmian-opaque-object-import)  Import a secret data or a key in the KMS.

**`revoke`** [[18.4]](#184-cosmian-opaque-object-revoke)  Revoke an `OpaqueObject`

**`destroy`** [[18.5]](#185-cosmian-opaque-object-destroy)  Destroy an `OpaqueObject`

---

## 18.1 cosmian opaque-object create

Create (register) an `OpaqueObject` by importing raw bytes.

### Usage
`cosmian opaque-object create [options]`
### Arguments
`--file [-f] <FILE>` Optional file containing the opaque bytes to import

`--data [-d] <DATA>` Inline opaque data as a UTF-8 string. If provided, it's used instead of --file bytes

`--type <OPAQUE_TYPE>` Opaque data type (defaults to Vendor)

`--id <ID>` Optional object unique identifier to assign; otherwise server generates one

`--tag [-t] <TAG>` Tags to associate with the object. Repeat to add multiple tags



---

## 18.2 cosmian opaque-object export

Export a key or secret data from the KMS

### Usage
`cosmian opaque-object export [options] <KEY_FILE>
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

## 18.3 cosmian opaque-object import

Import a secret data or a key in the KMS.

### Usage
`cosmian opaque-object import [options] <KEY_FILE>
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

## 18.4 cosmian opaque-object revoke

Revoke an `OpaqueObject`

### Usage
`cosmian opaque-object revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <OBJECT_ID>` The opaque object unique identifier to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tags to locate the object if id is not provided. Repeat to specify multiple tags



---

## 18.5 cosmian opaque-object destroy

Destroy an `OpaqueObject`

### Usage
`cosmian opaque-object destroy [options]`
### Arguments
`--key-id [-k] <OBJECT_ID>` The opaque object unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tags to locate the object if id is not provided. Repeat to specify multiple tags

`--remove <REMOVE>` If the object should be removed from the database. If not specified, the object will be destroyed
but its metadata will still be available.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 19 cosmian secret-data

Create, import, export and destroy secret data

### Usage
`cosmian secret-data <subcommand>`

### Subcommands

**`create`** [[19.1]](#191-cosmian-secret-data-create)  Create a new secret data

**`export`** [[19.2]](#192-cosmian-secret-data-export)  Export a key or secret data from the KMS

**`import`** [[19.3]](#193-cosmian-secret-data-import)  Import a secret data or a key in the KMS.

**`wrap`** [[19.4]](#194-cosmian-secret-data-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[19.5]](#195-cosmian-secret-data-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[19.6]](#196-cosmian-secret-data-revoke)  Revoke a secret data

**`destroy`** [[19.7]](#197-cosmian-secret-data-destroy)  Destroy a secret data

---

## 19.1 cosmian secret-data create

Create a new secret data

### Usage
`cosmian secret-data create [options] [SECRET_ID]
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

## 19.2 cosmian secret-data export

Export a key or secret data from the KMS

### Usage
`cosmian secret-data export [options] <KEY_FILE>
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

## 19.3 cosmian secret-data import

Import a secret data or a key in the KMS.

### Usage
`cosmian secret-data import [options] <KEY_FILE>
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

## 19.4 cosmian secret-data wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian secret-data wrap [options] <KEY_FILE_IN>
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

## 19.5 cosmian secret-data unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian secret-data unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 19.6 cosmian secret-data revoke

Revoke a secret data

### Usage
`cosmian secret-data revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--secret-data-id [-s] <SECRET_ID>` The secret unique identifier of the secret to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the secret data when no secret data id is specified. To specify multiple tags, use the option multiple times



---

## 19.7 cosmian secret-data destroy

Destroy a secret data

### Usage
`cosmian secret-data destroy [options]`
### Arguments
`--key-id [-s] <SECRET_ID>` The secret unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the secret when no secret id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the secret should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 20 cosmian server-version

Print the version of the server

### Usage
`cosmian server-version`


---

## 21 cosmian sym

Manage symmetric keys. Encrypt and decrypt data

### Usage
`cosmian sym <subcommand>`

### Subcommands

**`keys`** [[21.1]](#211-cosmian-sym-keys)  Create, destroy, import, and export symmetric keys

**`encrypt`** [[21.2]](#212-cosmian-sym-encrypt)  Encrypt a file using a symmetric cipher

**`decrypt`** [[21.3]](#213-cosmian-sym-decrypt)  Decrypt a file using a symmetric key.

---

## 21.1 cosmian sym keys

Create, destroy, import, and export symmetric keys

### Usage
`cosmian sym keys <subcommand>`

### Subcommands

**`create`** [[21.1.1]](#2111-cosmian-sym-keys-create)  Create a new symmetric key

**`re-key`** [[21.1.2]](#2112-cosmian-sym-keys-re-key)  Refresh an existing symmetric key

**`export`** [[21.1.3]](#2113-cosmian-sym-keys-export)  Export a key or secret data from the KMS

**`import`** [[21.1.4]](#2114-cosmian-sym-keys-import)  Import a secret data or a key in the KMS.

**`wrap`** [[21.1.5]](#2115-cosmian-sym-keys-wrap)  Locally wrap a secret data or key in KMIP JSON TTLV format.

**`unwrap`** [[21.1.6]](#2116-cosmian-sym-keys-unwrap)  Locally unwrap a secret data or key in KMIP JSON TTLV format.

**`revoke`** [[21.1.7]](#2117-cosmian-sym-keys-revoke)  Revoke a symmetric key

**`destroy`** [[21.1.8]](#2118-cosmian-sym-keys-destroy)  Destroy a symmetric key

---

## 21.1.1 cosmian sym keys create

Create a new symmetric key

### Usage
`cosmian sym keys create [options] [KEY_ID]
`
### Arguments
`--number-of-bits [-l] <NUMBER_OF_BITS>` The length of the generated random key or salt in bits

`--bytes-b64 [-k] <WRAP_KEY_B64>` The symmetric key bytes or salt as a base 64 string

`--algorithm [-a] <ALGORITHM>` The algorithm

Possible values:  `"aes", "sha3", "shake"` [default: `"aes"`]

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

## 21.1.2 cosmian sym keys re-key

Refresh an existing symmetric key

### Usage
`cosmian sym keys re-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 21.1.3 cosmian sym keys export

Export a key or secret data from the KMS

### Usage
`cosmian sym keys export [options] <KEY_FILE>
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

## 21.1.4 cosmian sym keys import

Import a secret data or a key in the KMS.

### Usage
`cosmian sym keys import [options] <KEY_FILE>
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

## 21.1.5 cosmian sym keys wrap

Locally wrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian sym keys wrap [options] <KEY_FILE_IN>
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

## 21.1.6 cosmian sym keys unwrap

Locally unwrap a secret data or key in KMIP JSON TTLV format.

### Usage
`cosmian sym keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of an unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` An unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 21.1.7 cosmian sym keys revoke

Revoke a symmetric key

### Usage
`cosmian sym keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 21.1.8 cosmian sym keys destroy

Destroy a symmetric key

### Usage
`cosmian sym keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--remove <REMOVE>` If the key should be removed from the database
If not specified, the key will be destroyed
but its metadata will still be available in the database.
Please note that the KMIP specification does not support the removal of objects.

Possible values:  `"true", "false"` [default: `"false"`]




---

## 21.2 cosmian sym encrypt

Encrypt a file using a symmetric cipher

### Usage
`cosmian sym encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The symmetric key unique identifier. If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, `aes-gcm` is used

Possible values:  `"aes-gcm", "aes-cbc", "aes-xts"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to encrypt the data encryption key.

Possible values:  `"aes-gcm", "aes-xts", "rfc3394", "rfc5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--nonce [-n] <NONCE>` Optional nonce/IV (or tweak for XTS) as a hex string. If not provided, a random value is generated

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 21.3 cosmian sym decrypt

Decrypt a file using a symmetric key.

### Usage
`cosmian sym decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm.
If not specified, aes-gcm is used.

Possible values:  `"aes-gcm", "aes-cbc", "aes-xts"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to decrypt the data encryption key.

Possible values:  `"aes-gcm", "aes-xts", "rfc3394", "rfc5649"`

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption as a hex string




---

## 22 cosmian markdown

Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

### Usage
`cosmian markdown [options] <MARKDOWN_FILE>
`
### Arguments
` <MARKDOWN_FILE>` The file to export the markdown to



---

## 23 cosmian configure

Configure the KMS CLI (creates/updates cosmian.toml)

### Usage
`cosmian configure`




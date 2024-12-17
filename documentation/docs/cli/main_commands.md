
##  cosmian

CLI used to manage the Cosmian KMS.

### Usage
`cosmian <subcommand> [options]`
### Arguments
`--conf-path [-c] <CONF_PATH>` Configuration file location

`--kms-url <KMS_URL>` The URL of the KMS

`--kms-accept-invalid-certs <KMS_ACCEPT_INVALID_CERTS>` Allow to connect using a self-signed cert or untrusted cert chain

Possible values:  `"true", "false"`

`--kms-print-json <KMS_PRINT_JSON>` Output the KMS JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint

Possible values:  `"true", "false"`

`--findex-url <FINDEX_URL>` The URL of the Findex server

`--findex-accept-invalid-certs <FINDEX_ACCEPT_INVALID_CERTS>` Allow to connect using a self-signed cert or untrusted cert chain

Possible values:  `"true", "false"`


### Subcommands

**`kms`** [[1]](#1-cosmian-kms)  Handle KMS actions

**`findex-server`** [[2]](#2-cosmian-findex-server)  Handle Findex server actions

**`markdown`** [[3]](#3-cosmian-markdown)  Action to auto-generate doc in Markdown format Run `cargo run --bin cosmian -- markdown documentation/docs/cli/main_commands.md`

---

## 1 cosmian kms

Handle KMS actions

### Usage
`cosmian kms <subcommand>`

### Subcommands

**`access-rights`** [[1.1]](#11-cosmian-kms-access-rights)  Manage the users' access rights to the cryptographic objects

**`attributes`** [[1.2]](#12-cosmian-kms-attributes)  Get/Set/Delete the KMIP object attributes

**`bench`** [[1.3]](#13-cosmian-kms-bench)  Run a set of benches to check the server performance

**`certificates`** [[1.4]](#14-cosmian-kms-certificates)  Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

**`ec`** [[1.5]](#15-cosmian-kms-ec)  Manage elliptic curve keys. Encrypt and decrypt data using ECIES

**`google`** [[1.6]](#16-cosmian-kms-google)  Manage google elements. Handle key pairs and identities from Gmail API

**`locate`** [[1.7]](#17-cosmian-kms-locate)  Locate cryptographic objects inside the KMS

**`login`** [[1.8]](#18-cosmian-kms-login)  Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

**`logout`** [[1.9]](#19-cosmian-kms-logout)  Logout from the Identity Provider.

**`new-database`** [[1.10]](#110-cosmian-kms-new-database)  Initialize a new user encrypted database and return the secret (`SQLCipher` only).

**`rsa`** [[1.11]](#111-cosmian-kms-rsa)  Manage RSA keys. Encrypt and decrypt data using RSA keys

**`server-version`** [[1.12]](#112-cosmian-kms-server-version)  Print the version of the server

**`sym`** [[1.13]](#113-cosmian-kms-sym)  Manage symmetric keys. Encrypt and decrypt data

---

## 1.1 cosmian kms access-rights

Manage the users' access rights to the cryptographic objects

### Usage
`cosmian kms access-rights <subcommand>`

### Subcommands

**`grant`** [[1.1.1]](#111-cosmian-kms-access-rights-grant)  Grant another user one or multiple access rights to an object

**`revoke`** [[1.1.2]](#112-cosmian-kms-access-rights-revoke)  Revoke another user one or multiple access rights to an object

**`list`** [[1.1.3]](#113-cosmian-kms-access-rights-list)  List the access rights granted on an object to other users

**`owned`** [[1.1.4]](#114-cosmian-kms-access-rights-owned)  List the objects owned by the calling user

**`obtained`** [[1.1.5]](#115-cosmian-kms-access-rights-obtained)  List the access rights obtained by the calling user

---

## 1.1.1 cosmian kms access-rights grant

Grant another user one or multiple access rights to an object

### Usage
`cosmian kms access-rights grant [options] <USER>
 <OBJECT_UID>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user identifier to allow

` <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)



---

## 1.1.2 cosmian kms access-rights revoke

Revoke another user one or multiple access rights to an object

### Usage
`cosmian kms access-rights revoke [options] <USER>
 <OBJECT_UID>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user to revoke access to

` <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to revoke (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)



---

## 1.1.3 cosmian kms access-rights list

List the access rights granted on an object to other users

### Usage
`cosmian kms access-rights list [options] <OBJECT_UID>
`
### Arguments
` <OBJECT_UID>` The object unique identifier



---

## 1.1.4 cosmian kms access-rights owned

List the objects owned by the calling user

### Usage
`cosmian kms access-rights owned`


---

## 1.1.5 cosmian kms access-rights obtained

List the access rights obtained by the calling user

### Usage
`cosmian kms access-rights obtained`



---

## 1.2 cosmian kms attributes

Get/Set/Delete the KMIP object attributes

### Usage
`cosmian kms attributes <subcommand>`

### Subcommands

**`get`** [[1.2.1]](#121-cosmian-kms-attributes-get)  Get the KMIP object attributes and tags.

**`set`** [[1.2.2]](#122-cosmian-kms-attributes-set)  Set the KMIP object attributes.

**`delete`** [[1.2.3]](#123-cosmian-kms-attributes-delete)  Delete the KMIP object attributes.

---

## 1.2.1 cosmian kms attributes get

Get the KMIP object attributes and tags.

### Usage
`cosmian kms attributes get [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--attribute [-a] <ATTRIBUTE>` The attributes or `KMIP-tags` to retrieve.
To specify multiple attributes, use the option multiple times.
If not specified, all possible attributes are returned.

`--link-type [-l] <LINK_TYPE>` Filter on retrieved links. Only if KMIP tag `LinkType` is used in `attribute` parameter.
To specify multiple attributes, use the option multiple times.
If not specified, all possible link types are returned.

Possible values:  `"certificate", "public-key", "private-key", "derivation-base-object", "derived-key", "replacement-object", "replaced-object", "parent", "child", "previous", "next", "pkcs12-certificate", "pkcs12-password", "wrapping-key"`

`--output-file [-o] <OUTPUT_FILE>` An optional file where to export the attributes.
The attributes will be in JSON TTLV format.



---

## 1.2.2 cosmian kms attributes set

Set the KMIP object attributes.

### Usage
`cosmian kms attributes set [options]`
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

## 1.2.3 cosmian kms attributes delete

Delete the KMIP object attributes.

### Usage
`cosmian kms attributes delete [options]`
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

## 1.3 cosmian kms bench

Run a set of benches to check the server performance

### Usage
`cosmian kms bench [options]`
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

## 1.4 cosmian kms certificates

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

### Usage
`cosmian kms certificates <subcommand>`

### Subcommands

**`certify`** [[1.4.1]](#141-cosmian-kms-certificates-certify)  Issue or renew a X509 certificate

**`decrypt`** [[1.4.2]](#142-cosmian-kms-certificates-decrypt)  Decrypt a file using the private key of a certificate

**`encrypt`** [[1.4.3]](#143-cosmian-kms-certificates-encrypt)  Encrypt a file using the certificate public key

**`export`** [[1.4.4]](#144-cosmian-kms-certificates-export)  Export a certificate from the KMS

**`import`** [[1.4.5]](#145-cosmian-kms-certificates-import)  Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

**`revoke`** [[1.4.6]](#146-cosmian-kms-certificates-revoke)  Revoke a certificate

**`destroy`** [[1.4.7]](#147-cosmian-kms-certificates-destroy)  Destroy a certificate

**`validate`** [[1.4.8]](#148-cosmian-kms-certificates-validate)  Validate a certificate

---

## 1.4.1 cosmian kms certificates certify

Issue or renew a X509 certificate

### Usage
`cosmian kms certificates certify [options]`
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

## 1.4.2 cosmian kms certificates decrypt

Decrypt a file using the private key of a certificate

### Usage
`cosmian kms certificates decrypt [options] <FILE>
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

## 1.4.3 cosmian kms certificates encrypt

Encrypt a file using the certificate public key

### Usage
`cosmian kms certificates encrypt [options] <FILE>
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

## 1.4.4 cosmian kms certificates export

Export a certificate from the KMS

### Usage
`cosmian kms certificates export [options] <CERTIFICATE_FILE>
`
### Arguments
` <CERTIFICATE_FILE>` The file to export the certificate to

`--certificate-id [-c] <UNIQUE_ID>` The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
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

## 1.4.5 cosmian kms certificates import

Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

### Usage
`cosmian kms certificates import [options] [CERTIFICATE_FILE]
 [CERTIFICATE_ID]
`
### Arguments
` <CERTIFICATE_FILE>` The input file in PEM, KMIP-JSON-TTLV or PKCS#12 format

` <CERTIFICATE_ID>` The unique id of the leaf certificate; a unique id
based on the key material is generated if not specified.
When importing a PKCS12, the unique id will be that of the private key.

`--format [-f] <INPUT_FORMAT>` Import the certificate in the selected format

Possible values:  `"json-ttlv", "pem", "der", "chain", "ccadb", "pkcs12"` [default: `"json-ttlv"`]

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

## 1.4.6 cosmian kms certificates revoke

Revoke a certificate

### Usage
`cosmian kms certificates revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 1.4.7 cosmian kms certificates destroy

Destroy a certificate

### Usage
`cosmian kms certificates destroy [options]`
### Arguments
`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 1.4.8 cosmian kms certificates validate

Validate a certificate

### Usage
`cosmian kms certificates validate [options]`
### Arguments
`--certificate [-v] <CERTIFICATE>` One or more Certificates filepath

`--unique-identifier [-k] <UNIQUE_IDENTIFIER>` One or more Unique Identifiers of Certificate Objects

`--validity-time [-t] <VALIDITY_TIME>` A Date-Time object indicating when the certificate chain needs to be valid. If omitted, the current date and time SHALL be assumed




---

## 1.5 cosmian kms ec

Manage elliptic curve keys. Encrypt and decrypt data using ECIES

### Usage
`cosmian kms ec <subcommand>`

### Subcommands

**`keys`** [[1.5.1]](#151-cosmian-kms-ec-keys)  Create, destroy, import, and export elliptic curve key pairs

---

## 1.5.1 cosmian kms ec keys

Create, destroy, import, and export elliptic curve key pairs

### Usage
`cosmian kms ec keys <subcommand>`

### Subcommands

**`create`** [[1.5.1.1]](#1511-cosmian-kms-ec-keys-create)  Create an elliptic curve key pair

**`export`** [[1.5.1.2]](#1512-cosmian-kms-ec-keys-export)  Export a key from the KMS

**`import`** [[1.5.1.3]](#1513-cosmian-kms-ec-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[1.5.1.4]](#1514-cosmian-kms-ec-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[1.5.1.5]](#1515-cosmian-kms-ec-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[1.5.1.6]](#1516-cosmian-kms-ec-keys-revoke)  Revoke a public or private key

**`destroy`** [[1.5.1.7]](#1517-cosmian-kms-ec-keys-destroy)  Destroy a public or private key

---

## 1.5.1.1 cosmian kms ec keys create

Create an elliptic curve key pair

### Usage
`cosmian kms ec keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p224", "nist-p256", "nist-p384", "nist-p521"` [default: `"nist-p256"`]

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]



---

## 1.5.1.2 cosmian kms ec keys export

Export a key from the KMS

### Usage
`cosmian kms ec keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <KEY_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `spki-pem` and `spki-der` only apply to RSA and EC public keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
By default, the algorithm used is

- `NISTKeyWrap` for symmetric keys (a.k.a. RFC 5649)
- `RsaPkcsOaep` for RSA keys

Possible values:  `"nist-key-wrap", "aes-gcm", "rsa-pkcs-v15", "rsa-oaep", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 1.5.1.3 cosmian kms ec keys import

Import a private or public key in the KMS.

### Usage
`cosmian kms ec keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` For what operations should the key be used

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Optional authenticated encryption additional data to use for AES256GCM authenticated encryption unwrapping



---

## 1.5.1.4 cosmian kms ec keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms ec keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 1.5.1.5 cosmian kms ec keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms ec keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 1.5.1.6 cosmian kms ec keys revoke

Revoke a public or private key

### Usage
`cosmian kms ec keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 1.5.1.7 cosmian kms ec keys destroy

Destroy a public or private key

### Usage
`cosmian kms ec keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times





---

## 1.6 cosmian kms google

Manage google elements. Handle key pairs and identities from Gmail API

### Usage
`cosmian kms google <subcommand>`

### Subcommands

**`key-pairs`** [[1.6.1]](#161-cosmian-kms-google-key-pairs)  Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

**`identities`** [[1.6.2]](#162-cosmian-kms-google-identities)  Insert, get, list, patch and delete identities from Gmail API

---

## 1.6.1 cosmian kms google key-pairs

Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

### Usage
`cosmian kms google key-pairs <subcommand>`

### Subcommands

**`get`** [[1.6.1.1]](#1611-cosmian-kms-google-key-pairs-get)  Retrieves an existing client-side encryption key pair.

**`list`** [[1.6.1.2]](#1612-cosmian-kms-google-key-pairs-list)  Lists client-side encryption key pairs for a user.

**`enable`** [[1.6.1.3]](#1613-cosmian-kms-google-key-pairs-enable)  Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

**`disable`** [[1.6.1.4]](#1614-cosmian-kms-google-key-pairs-disable)  Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

**`obliterate`** [[1.6.1.5]](#1615-cosmian-kms-google-key-pairs-obliterate)  Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

**`create`** [[1.6.1.6]](#1616-cosmian-kms-google-key-pairs-create)  Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

---

## 1.6.1.1 cosmian kms google key-pairs get

Retrieves an existing client-side encryption key pair.

### Usage
`cosmian kms google key-pairs get [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to retrieve

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 1.6.1.2 cosmian kms google key-pairs list

Lists client-side encryption key pairs for a user.

### Usage
`cosmian kms google key-pairs list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 1.6.1.3 cosmian kms google key-pairs enable

Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

### Usage
`cosmian kms google key-pairs enable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to enable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 1.6.1.4 cosmian kms google key-pairs disable

Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

### Usage
`cosmian kms google key-pairs disable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to disable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 1.6.1.5 cosmian kms google key-pairs obliterate

Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

### Usage
`cosmian kms google key-pairs obliterate [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to obliterate

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 1.6.1.6 cosmian kms google key-pairs create

Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

### Usage
`cosmian kms google key-pairs create [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address

`--cse-key-id [-w] <CSE_KEY_ID>` CSE key ID to wrap exported user private key

`--issuer-private-key-id [-i] <ISSUER_PRIVATE_KEY_ID>` The issuer private key id

`--subject-name [-s] <SUBJECT_NAME>` When certifying a public key, or generating a keypair,
the subject name to use.

`--rsa-private-key-id [-k] <RSA_PRIVATE_KEY_ID>` The existing private key id of an existing RSA keypair to use (optional - if no ID is provided, a RSA keypair will be created)

`--sensitive <SENSITIVE>` Sensitive: if set, the key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]

`--dry-run <DRY_RUN>` Dry run mode. If set, the action will not be executed

Possible values:  `"true", "false"` [default: `"false"`]




---

## 1.6.2 cosmian kms google identities

Insert, get, list, patch and delete identities from Gmail API

### Usage
`cosmian kms google identities <subcommand>`

### Subcommands

**`get`** [[1.6.2.1]](#1621-cosmian-kms-google-identities-get)  Retrieves a client-side encryption identity configuration.

**`list`** [[1.6.2.2]](#1622-cosmian-kms-google-identities-list)  Lists the client-side encrypted identities for an authenticated user.

**`insert`** [[1.6.2.3]](#1623-cosmian-kms-google-identities-insert)  Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

**`delete`** [[1.6.2.4]](#1624-cosmian-kms-google-identities-delete)  Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

**`patch`** [[1.6.2.5]](#1625-cosmian-kms-google-identities-patch)  Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

---

## 1.6.2.1 cosmian kms google identities get

Retrieves a client-side encryption identity configuration.

### Usage
`cosmian kms google identities get [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 1.6.2.2 cosmian kms google identities list

Lists the client-side encrypted identities for an authenticated user.

### Usage
`cosmian kms google identities list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 1.6.2.3 cosmian kms google identities insert

Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

### Usage
`cosmian kms google identities insert [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The keypair id, associated with a given cert/key. You can get the by listing the keypairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 1.6.2.4 cosmian kms google identities delete

Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

### Usage
`cosmian kms google identities delete [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 1.6.2.5 cosmian kms google identities patch

Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

### Usage
`cosmian kms google identities patch [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The key pair id, associated with a given cert/key. You can get the by listing the key pairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved





---

## 1.7 cosmian kms locate

Locate cryptographic objects inside the KMS

### Usage
`cosmian kms locate [options]`
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

## 1.8 cosmian kms login

Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

### Usage
`cosmian kms login`


---

## 1.9 cosmian kms logout

Logout from the Identity Provider.

### Usage
`cosmian kms logout`


---

## 1.10 cosmian kms new-database

Initialize a new user encrypted database and return the secret (`SQLCipher` only).

### Usage
`cosmian kms new-database`


---

## 1.11 cosmian kms rsa

Manage RSA keys. Encrypt and decrypt data using RSA keys

### Usage
`cosmian kms rsa <subcommand>`

### Subcommands

**`keys`** [[1.11.1]](#1111-cosmian-kms-rsa-keys)  Create, destroy, import, and export RSA key pairs

**`encrypt`** [[1.11.2]](#1112-cosmian-kms-rsa-encrypt)  Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`decrypt`** [[1.11.3]](#1113-cosmian-kms-rsa-decrypt)  Decrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

---

## 1.11.1 cosmian kms rsa keys

Create, destroy, import, and export RSA key pairs

### Usage
`cosmian kms rsa keys <subcommand>`

### Subcommands

**`create`** [[1.11.1.1]](#11111-cosmian-kms-rsa-keys-create)  Create a new RSA key pair

**`export`** [[1.11.1.2]](#11112-cosmian-kms-rsa-keys-export)  Export a key from the KMS

**`import`** [[1.11.1.3]](#11113-cosmian-kms-rsa-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[1.11.1.4]](#11114-cosmian-kms-rsa-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[1.11.1.5]](#11115-cosmian-kms-rsa-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[1.11.1.6]](#11116-cosmian-kms-rsa-keys-revoke)  Revoke a public or private key

**`destroy`** [[1.11.1.7]](#11117-cosmian-kms-rsa-keys-destroy)  Destroy a public or private key

---

## 1.11.1.1 cosmian kms rsa keys create

Create a new RSA key pair

### Usage
`cosmian kms rsa keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--size_in_bits [-s] <SIZE_IN_BITS>` The expected size in bits

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified

`--sensitive <SENSITIVE>` Sensitive: if set, the private key will not be exportable

Possible values:  `"true", "false"` [default: `"false"`]



---

## 1.11.1.2 cosmian kms rsa keys export

Export a key from the KMS

### Usage
`cosmian kms rsa keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <KEY_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `spki-pem` and `spki-der` only apply to RSA and EC public keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
By default, the algorithm used is

- `NISTKeyWrap` for symmetric keys (a.k.a. RFC 5649)
- `RsaPkcsOaep` for RSA keys

Possible values:  `"nist-key-wrap", "aes-gcm", "rsa-pkcs-v15", "rsa-oaep", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 1.11.1.3 cosmian kms rsa keys import

Import a private or public key in the KMS.

### Usage
`cosmian kms rsa keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` For what operations should the key be used

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Optional authenticated encryption additional data to use for AES256GCM authenticated encryption unwrapping



---

## 1.11.1.4 cosmian kms rsa keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms rsa keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 1.11.1.5 cosmian kms rsa keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms rsa keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 1.11.1.6 cosmian kms rsa keys revoke

Revoke a public or private key

### Usage
`cosmian kms rsa keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 1.11.1.7 cosmian kms rsa keys destroy

Destroy a public or private key

### Usage
`cosmian kms rsa keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 1.11.2 cosmian kms rsa encrypt

Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`cosmian kms rsa encrypt [options] <FILE>
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

## 1.11.3 cosmian kms rsa decrypt

Decrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

### Usage
`cosmian kms rsa decrypt [options] <FILE>
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

## 1.12 cosmian kms server-version

Print the version of the server

### Usage
`cosmian kms server-version`


---

## 1.13 cosmian kms sym

Manage symmetric keys. Encrypt and decrypt data

### Usage
`cosmian kms sym <subcommand>`

### Subcommands

**`keys`** [[1.13.1]](#1131-cosmian-kms-sym-keys)  Create, destroy, import, and export symmetric keys

**`encrypt`** [[1.13.2]](#1132-cosmian-kms-sym-encrypt)  Encrypt a file using a symmetric cipher

**`decrypt`** [[1.13.3]](#1133-cosmian-kms-sym-decrypt)  Decrypt a file using a symmetric key.

---

## 1.13.1 cosmian kms sym keys

Create, destroy, import, and export symmetric keys

### Usage
`cosmian kms sym keys <subcommand>`

### Subcommands

**`create`** [[1.13.1.1]](#11311-cosmian-kms-sym-keys-create)  Create a new symmetric key

**`re-key`** [[1.13.1.2]](#11312-cosmian-kms-sym-keys-re-key)  Refresh an existing symmetric key

**`export`** [[1.13.1.3]](#11313-cosmian-kms-sym-keys-export)  Export a key from the KMS

**`import`** [[1.13.1.4]](#11314-cosmian-kms-sym-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[1.13.1.5]](#11315-cosmian-kms-sym-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[1.13.1.6]](#11316-cosmian-kms-sym-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[1.13.1.7]](#11317-cosmian-kms-sym-keys-revoke)  Revoke a symmetric key

**`destroy`** [[1.13.1.8]](#11318-cosmian-kms-sym-keys-destroy)  Destroy a symmetric key

---

## 1.13.1.1 cosmian kms sym keys create

Create a new symmetric key

### Usage
`cosmian kms sym keys create [options] [KEY_ID]
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

`--wrapping-key-id [-w] <WRAPPING_KEY_ID>` The key to wrap this new key with.
If the wrapping key is:

-  a symmetric key, AES-GCM will be used
-  a RSA key, RSA-OAEP will be used
-  a EC key, ECIES will be used (salsa20poly1305 for X25519)



---

## 1.13.1.2 cosmian kms sym keys re-key

Refresh an existing symmetric key

### Usage
`cosmian kms sym keys re-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 1.13.1.3 cosmian kms sym keys export

Export a key from the KMS

### Usage
`cosmian kms sym keys export [options] <KEY_FILE>
`
### Arguments
` <KEY_FILE>` The file to export the key to

`--key-id [-k] <KEY_ID>` The key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--key-format [-f] <KEY_FORMAT>` The format of the key

 - `json-ttlv` [default]. It should be the format to use to later re-import the key
 - `sec1-pem` and `sec1-der`only apply to NIST EC private keys (Not Curve25519 or X448)
 - `pkcs1-pem` and `pkcs1-der` only apply to RSA private and public keys
 - `pkcs8-pem` and `pkcs8-der` only apply to RSA and EC private keys
 - `spki-pem` and `spki-der` only apply to RSA and EC public keys
 - `raw` returns the raw bytes of
      - symmetric keys
      - Covercrypt keys
      - wrapped keys

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "base64", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

Possible values:  `"true", "false"` [default: `"false"`]

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.

Possible values:  `"true", "false"` [default: `"false"`]

`--wrapping-algorithm [-m] <WRAPPING_ALGORITHM>` Wrapping algorithm to use when exporting the key
By default, the algorithm used is

- `NISTKeyWrap` for symmetric keys (a.k.a. RFC 5649)
- `RsaPkcsOaep` for RSA keys

Possible values:  `"nist-key-wrap", "aes-gcm", "rsa-pkcs-v15", "rsa-oaep", "rsa-aes-key-wrap"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data Only available for AES GCM wrapping



---

## 1.13.1.4 cosmian kms sym keys import

Import a private or public key in the KMS.

### Usage
`cosmian kms sym keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding KMS public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding KMS private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

Possible values:  `"true", "false"` [default: `"false"`]

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

Possible values:  `"true", "false"` [default: `"false"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times

`--key-usage <KEY_USAGE>` For what operations should the key be used

Possible values:  `"sign", "verify", "encrypt", "decrypt", "wrap-key", "unwrap-key", "mac-generate", "mac-verify", "derive-key", "key-agreement", "certificate-sign", "crl-sign", "authenticate", "unrestricted"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Optional authenticated encryption additional data to use for AES256GCM authenticated encryption unwrapping



---

## 1.13.1.5 cosmian kms sym keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms sym keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified, the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 1.13.1.6 cosmian kms sym keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`cosmian kms sym keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 1.13.1.7 cosmian kms sym keys revoke

Revoke a symmetric key

### Usage
`cosmian kms sym keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 1.13.1.8 cosmian kms sym keys destroy

Destroy a symmetric key

### Usage
`cosmian kms sym keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 1.13.2 cosmian kms sym encrypt

Encrypt a file using a symmetric cipher

### Usage
`cosmian kms sym encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The symmetric key unique identifier. If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"AesGcm", "AesXts"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to encrypt the data encryption key.

Possible values:  `"AesGcm", "AesXts", "RFC5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--nonce [-n] <NONCE>` Optional nonce/IV (or tweak for XTS) as a hex string. If not provided, a random value is generated

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 1.13.3 cosmian kms sym decrypt

Decrypt a file using a symmetric key.

### Usage
`cosmian kms sym decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"AesGcm", "AesXts"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to decrypt the data encryption key.

Possible values:  `"AesGcm", "AesXts", "RFC5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption as a hex string





---

## 2 cosmian findex-server

Handle Findex server actions

### Usage
`cosmian findex-server <subcommand>`

### Subcommands

**`encrypt-and-index`** [[2.1]](#21-cosmian-findex-server-encrypt-and-index)  Encrypt entries and index the corresponding database UUIDs with the Findex.

**`search-and-decrypt`** [[2.2]](#22-cosmian-findex-server-search-and-decrypt)  Search keywords and decrypt the content of corresponding UUIDs.

**`delete-dataset`** [[2.3]](#23-cosmian-findex-server-delete-dataset)  Delete encrypted entries. (Indexes are not deleted)

**`datasets`** [[2.4]](#24-cosmian-findex-server-datasets)  Manage encrypted datasets

**`delete`** [[2.5]](#25-cosmian-findex-server-delete)  Delete indexed keywords

**`index`** [[2.6]](#26-cosmian-findex-server-index)  Index new keywords

**`login`** [[2.7]](#27-cosmian-findex-server-login)  Login to the Identity Provider of the Findex server using the `OAuth2`
authorization code flow.

**`logout`** [[2.8]](#28-cosmian-findex-server-logout)  Logout from the Identity Provider.

**`permissions`** [[2.9]](#29-cosmian-findex-server-permissions)  Manage the users permissions to the indexes

**`search`** [[2.10]](#210-cosmian-findex-server-search)  Findex: Search keywords.

**`server-version`** [[2.11]](#211-cosmian-findex-server-server-version)  Print the version of the server

---

## 2.1 cosmian findex-server encrypt-and-index

Encrypt entries and index the corresponding database UUIDs with the Findex.

### Usage
`cosmian findex-server encrypt-and-index [options]`
### Arguments
`--key [-k] <KEY>` The user findex key used (to add, search, delete and compact). The key is a 16 bytes hex string

`--label [-l] <LABEL>` The Findex label

`--index-id [-i] <INDEX_ID>` The index ID

`--csv-path <CSV_PATH>` The path to the CSV file path containing the data to index

`--kek-id <KEY_ENCRYPTION_KEY_ID>` The key encryption key (KEK) unique identifier. If provided, all encryption is done client side. The KEK is first exported locally and is used in the KEM to encapsulates the ephemeral Data Encryption Key (DEK). This KEK has been created in KMS and provides the Key Encapsulation Mechanism (KEM) parameters such as algorithm and mode. KEM supported are: - RFC5649 - AES-GCM - RSA PKCS#1 v1.5 - RSA-OAEP - RSA-AES hybrid key wrapping - Salsa Sealed Box - ECIES

`--dek-id <DATA_ENCRYPTION_KEY_ID>` The data encryption key (DEK) unique identifier. The key has been created in KMS. DEM supported are: - RFC5649 - AES-GCM

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"AesGcm", "AesXts"` [default: `"AesGcm"`]

`--nonce [-n] <NONCE>` Optional nonce/IV (or tweak for XTS) as a hex string. If not provided, a random value is generated

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 2.2 cosmian findex-server search-and-decrypt

Search keywords and decrypt the content of corresponding UUIDs.

### Usage
`cosmian findex-server search-and-decrypt [options]`
### Arguments
`--key [-k] <KEY>` The user findex key used (to add, search, delete and compact). The key is a 16 bytes hex string

`--label [-l] <LABEL>` The Findex label

`--index-id [-i] <INDEX_ID>` The index ID

`--keyword <KEYWORD>` The word to search. Can be repeated

`--kek-id <KEY_ENCRYPTION_KEY_ID>` The Key Encryption key (KEM) unique identifier. If not specified, tags should be specified

`--dek-id <DATA_ENCRYPTION_KEY_ID>` The data encryption key (DEK) unique identifier. The key has been created in KMS. DEM supported are: - RFC5649 - AES-GCM

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"AesGcm", "AesXts"` [default: `"AesGcm"`]

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 2.3 cosmian findex-server delete-dataset

Delete encrypted entries. (Indexes are not deleted)

### Usage
`cosmian findex-server delete-dataset [options]`
### Arguments
`--index-id [-i] <INDEX_ID>` Index id

`--uuid [-u] <UUID>` List of UUIDS to delete



---

## 2.4 cosmian findex-server datasets

Manage encrypted datasets

### Usage
`cosmian findex-server datasets <subcommand>`

### Subcommands

**`add`** [[2.4.1]](#241-cosmian-findex-server-datasets-add)  Add datasets entries

**`delete`** [[2.4.2]](#242-cosmian-findex-server-datasets-delete)  Delete datasets entries using corresponding entries UUID

**`get`** [[2.4.3]](#243-cosmian-findex-server-datasets-get)  Get datasets entries using corresponding entries UUID. Returns the entries

---

## 2.4.1 cosmian findex-server datasets add

Add datasets entries

### Usage
`cosmian findex-server datasets add [options]`
### Arguments
`--index-id <INDEX_ID>` The index ID

` [-D] <ENTRIES>` The entries to add under the format `KEY=VALUE` where: - `KEY` is a UUID - `VALUE` is a base64 encoded string



---

## 2.4.2 cosmian findex-server datasets delete

Delete datasets entries using corresponding entries UUID

### Usage
`cosmian findex-server datasets delete [options]`
### Arguments
`--index-id <INDEX_ID>` The index ID

`--uuids <UUIDS>` The entries UUIDs to delete



---

## 2.4.3 cosmian findex-server datasets get

Get datasets entries using corresponding entries UUID. Returns the entries

### Usage
`cosmian findex-server datasets get [options]`
### Arguments
`--index-id <INDEX_ID>` The index id

`--uuids <UUIDS>` The entries uuids




---

## 2.5 cosmian findex-server delete

Delete indexed keywords

### Usage
`cosmian findex-server delete [options]`
### Arguments
`--key [-k] <KEY>` The user findex key used (to add, search, delete and compact). The key is a 16 bytes hex string

`--label [-l] <LABEL>` The Findex label

`--index-id [-i] <INDEX_ID>` The index ID

`--csv <CSV>` The path to the CSV file containing the data to index



---

## 2.6 cosmian findex-server index

Index new keywords

### Usage
`cosmian findex-server index [options]`
### Arguments
`--key [-k] <KEY>` The user findex key used (to add, search, delete and compact). The key is a 16 bytes hex string

`--label [-l] <LABEL>` The Findex label

`--index-id [-i] <INDEX_ID>` The index ID

`--csv <CSV>` The path to the CSV file containing the data to index



---

## 2.7 cosmian findex-server login

Login to the Identity Provider of the Findex server using the `OAuth2`
authorization code flow.

### Usage
`cosmian findex-server login`


---

## 2.8 cosmian findex-server logout

Logout from the Identity Provider.

### Usage
`cosmian findex-server logout`


---

## 2.9 cosmian findex-server permissions

Manage the users permissions to the indexes

### Usage
`cosmian findex-server permissions <subcommand>`

### Subcommands

**`create`** [[2.9.1]](#291-cosmian-findex-server-permissions-create)  Create a new index. It results on an `admin` permission on a new index

**`list`** [[2.9.2]](#292-cosmian-findex-server-permissions-list)  List user's permission. Returns a list of indexes with their permissions

**`grant`** [[2.9.3]](#293-cosmian-findex-server-permissions-grant)  Grant permission on a index

**`revoke`** [[2.9.4]](#294-cosmian-findex-server-permissions-revoke)  Revoke user permission

---

## 2.9.1 cosmian findex-server permissions create

Create a new index. It results on an `admin` permission on a new index

### Usage
`cosmian findex-server permissions create`


---

## 2.9.2 cosmian findex-server permissions list

List user's permission. Returns a list of indexes with their permissions

### Usage
`cosmian findex-server permissions list [options]`
### Arguments
`--user <USER>` The user identifier to allow



---

## 2.9.3 cosmian findex-server permissions grant

Grant permission on a index

### Usage
`cosmian findex-server permissions grant [options]`
### Arguments
`--user <USER>` The user identifier to allow

`--index-id <INDEX_ID>` The index ID

`--permission <PERMISSION>`


---

## 2.9.4 cosmian findex-server permissions revoke

Revoke user permission

### Usage
`cosmian findex-server permissions revoke [options]`
### Arguments
`--user <USER>` The user identifier to revoke

`--index-id <INDEX_ID>` The index id




---

## 2.10 cosmian findex-server search

Findex: Search keywords.

### Usage
`cosmian findex-server search [options]`
### Arguments
`--key [-k] <KEY>` The user findex key used (to add, search, delete and compact). The key is a 16 bytes hex string

`--label [-l] <LABEL>` The Findex label

`--index-id [-i] <INDEX_ID>` The index ID

`--keyword <KEYWORD>` The word to search. Can be repeated



---

## 2.11 cosmian findex-server server-version

Print the version of the server

### Usage
`cosmian findex-server server-version`



---

## 3 cosmian markdown

Action to auto-generate doc in Markdown format Run `cargo run --bin cosmian -- markdown documentation/docs/cli/main_commands.md`

### Usage
`cosmian markdown [options] <MARKDOWN_FILE>
`
### Arguments
` <MARKDOWN_FILE>` The file to export the markdown to





*-- This file is auto-generated using the `ckms markdown` command. --*

##  ckms

CLI used to manage the Cosmian KMS.

### Usage
`ckms <subcommand> [options]`
### Arguments
`--conf [-c] <CONF>` Configuration file location

`--url <URL>` The URL of the KMS

`--accept-invalid-certs <ACCEPT_INVALID_CERTS>` Allow to connect using a self-signed cert or untrusted cert chain

Possible values:  `"true", "false"`

`--json <JSON>` Output the JSON KMIP request and response. This is useful to understand JSON POST requests and responses required to programmatically call the KMS on the `/kmip/2_1` endpoint

Possible values:  `"true", "false"` [default: `"false"`]


### Subcommands

**`access-rights`** [[1]](#1-ckms-access-rights)  Manage the users' access rights to the cryptographic objects

**`cc`** [[2]](#2-ckms-cc)  Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data

**`certificates`** [[3]](#3-ckms-certificates)  Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

**`ec`** [[4]](#4-ckms-ec)  Manage elliptic curve keys. Encrypt and decrypt data using ECIES

**`attributes`** [[5]](#5-ckms-attributes)  Get/Set/Delete the KMIP object attributes

**`locate`** [[6]](#6-ckms-locate)  Locate cryptographic objects inside the KMS

**`new-database`** [[7]](#7-ckms-new-database)  Initialize a new user encrypted database and return the secret (`SQLCipher` only).

**`rsa`** [[8]](#8-ckms-rsa)  Manage RSA keys. Encrypt and decrypt data using RSA keys

**`server-version`** [[9]](#9-ckms-server-version)  Print the version of the server

**`sym`** [[10]](#10-ckms-sym)  Manage symmetric keys. Encrypt and decrypt data

**`login`** [[11]](#11-ckms-login)  Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

**`logout`** [[12]](#12-ckms-logout)  Logout from the Identity Provider.

**`markdown`** [[13]](#13-ckms-markdown)  Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

**`google`** [[14]](#14-ckms-google)  Manage google elements. Handle key pairs and identities from Gmail API

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
 <OBJECT_UID>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user identifier to allow

` <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATIONS>` The operations to grant (`create`, `get`, `encrypt`, `decrypt`, `import`, `revoke`, `locate`, `rekey`, `destroy`)



---

## 1.2 ckms access-rights revoke

Revoke another user one or multiple access rights to an object

### Usage
`ckms access-rights revoke [options] <USER>
 <OBJECT_UID>
 <OPERATIONS>...
`
### Arguments
` <USER>` The user to revoke access to

` <OBJECT_UID>` The object unique identifier stored in the KMS

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

## 2 ckms cc

Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data

### Usage
`ckms cc <subcommand>`

### Subcommands

**`keys`** [[2.1]](#21-ckms-cc-keys)  Create, destroy, import, export, and rekey `Covercrypt` master and user keys

**`policy`** [[2.2]](#22-ckms-cc-policy)  Extract, view, or edit policies of existing keys, and create a binary policy from specifications

**`encrypt`** [[2.3]](#23-ckms-cc-encrypt)  Encrypt a file using Covercrypt

**`decrypt`** [[2.4]](#24-ckms-cc-decrypt)  Decrypt a file using Covercrypt

---

## 2.1 ckms cc keys

Create, destroy, import, export, and rekey `Covercrypt` master and user keys

### Usage
`ckms cc keys <subcommand>`

### Subcommands

**`create-master-key-pair`** [[2.1.1]](#211-ckms-cc-keys-create-master-key-pair)  Create a new master key pair for a given policy and return the key IDs.

**`create-user-key`** [[2.1.2]](#212-ckms-cc-keys-create-user-key)  Create a new user decryption key given an access policy expressed as a boolean expression.

**`export`** [[2.1.3]](#213-ckms-cc-keys-export)  Export a key from the KMS

**`import`** [[2.1.4]](#214-ckms-cc-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[2.1.5]](#215-ckms-cc-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[2.1.6]](#216-ckms-cc-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[2.1.7]](#217-ckms-cc-keys-revoke)  Revoke a Covercrypt master or user decryption key

**`destroy`** [[2.1.8]](#218-ckms-cc-keys-destroy)  Destroy a Covercrypt master or user decryption key

**`rekey`** [[2.1.9]](#219-ckms-cc-keys-rekey)  Rekey the master and user keys for a given access policy.

**`prune`** [[2.1.10]](#2110-ckms-cc-keys-prune)  Prune the master and user keys for a given access policy.

---

## 2.1.1 ckms cc keys create-master-key-pair

Create a new master key pair for a given policy and return the key IDs.

### Usage
`ckms cc keys create-master-key-pair [options]`
### Arguments
`--policy-specifications [-s] <POLICY_SPECIFICATIONS_FILE>` The JSON policy specifications file to use to generate the master keys. See the inline doc of the `create-master-key-pair` command for details

`--policy-binary [-b] <POLICY_BINARY_FILE>` When not using policy specifications, a policy binary file can be used instead. See the `policy` command, to create this binary file from policy specifications or to extract it from existing keys

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times



---

## 2.1.2 ckms cc keys create-user-key

Create a new user decryption key given an access policy expressed as a boolean expression.

### Usage
`ckms cc keys create-user-key [options] <MASTER_PRIVATE_KEY_ID>
 <ACCESS_POLICY>
`
### Arguments
` <MASTER_PRIVATE_KEY_ID>` The master private key unique identifier

` <ACCESS_POLICY>` The access policy as a boolean expression combining policy attributes

`--tag [-t] <TAG>` The tag to associate with the user decryption key. To specify multiple tags, use the option multiple times



---

## 2.1.3 ckms cc keys export

Export a key from the KMS

### Usage
`ckms cc keys export [options] <KEY_FILE>
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

`--block-cipher-mode [-m] <BLOCK_CIPHER_MODE>` Block cipher mode

Possible values:  `"CBC", "ECB", "PCBC", "CFB", "OFB", "CTR", "CMAC", "CCM", "GCM", "CBCMAC", "XTS", "X9102AESKW", "X9102TDKW", "X9102AKW1", "X9102AKW2", "AEAD", "NISTKeyWrap", "GCMSIV"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data



---

## 2.1.4 ckms cc keys import

Import a private or public key in the KMS.

### Usage
`ckms cc keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

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

## 2.1.5 ckms cc keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`ckms cc keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 2.1.6 ckms cc keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`ckms cc keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 2.1.7 ckms cc keys revoke

Revoke a Covercrypt master or user decryption key

### Usage
`ckms cc keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.1.8 ckms cc keys destroy

Destroy a Covercrypt master or user decryption key

### Usage
`ckms cc keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.1.9 ckms cc keys rekey

Rekey the master and user keys for a given access policy.

### Usage
`ckms cc keys rekey [options] <ACCESS_POLICY>
`
### Arguments
` <ACCESS_POLICY>` The access policy to rekey. Example: `department::marketing && level::confidential`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.1.10 ckms cc keys prune

Prune the master and user keys for a given access policy.

### Usage
`ckms cc keys prune [options] <ACCESS_POLICY>
`
### Arguments
` <ACCESS_POLICY>` The access policy to prune. Example: `department::marketing && level::confidential`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 2.2 ckms cc policy

Extract, view, or edit policies of existing keys, and create a binary policy from specifications

### Usage
`ckms cc policy <subcommand>`

### Subcommands

**`view`** [[2.2.1]](#221-ckms-cc-policy-view)  View the policy of an existing public or private master key.

**`specs`** [[2.2.2]](#222-ckms-cc-policy-specs)  Extract the policy specifications from a public or private master key to a policy specifications file

**`binary`** [[2.2.3]](#223-ckms-cc-policy-binary)  Extract the policy from a public or private master key to a policy binary file

**`create`** [[2.2.4]](#224-ckms-cc-policy-create)  Create a policy binary file from policy specifications

**`add-attribute`** [[2.2.5]](#225-ckms-cc-policy-add-attribute)  Add an attribute to the policy of an existing private master key.

**`remove-attribute`** [[2.2.6]](#226-ckms-cc-policy-remove-attribute)  Remove an attribute from the policy of an existing private master key.
Permanently removes the ability to use this attribute in both encryptions and decryptions.

**`disable-attribute`** [[2.2.7]](#227-ckms-cc-policy-disable-attribute)  Disable an attribute from the policy of an existing private master key.
Prevents the encryption of new messages for this attribute while keeping the ability to decrypt existing ciphertexts.

**`rename-attribute`** [[2.2.8]](#228-ckms-cc-policy-rename-attribute)  Rename an attribute in the policy of an existing private master key.

---

## 2.2.1 ckms cc policy view

View the policy of an existing public or private master key.

### Usage
`ckms cc policy view [options]`
### Arguments
`--key-id [-i] <KEY_ID>` The public or private master key ID if the key is stored in the KMS

`--key-file [-f] <KEY_FILE>` If `key-id` is not provided, the file containing the public or private master key in TTLV format

`--detailed [-d] <DETAILED>` Show all the policy details rather than just the specifications

Possible values:  `"true", "false"` [default: `"false"`]



---

## 2.2.2 ckms cc policy specs

Extract the policy specifications from a public or private master key to a policy specifications file

### Usage
`ckms cc policy specs [options]`
### Arguments
`--key-id [-i] <KEY_ID>` The public or private master key ID if the key is stored in the KMS

`--key-file [-f] <KEY_FILE>` If `key-id` is not provided, the file containing the public or private master key in JSON TTLV format

`--specifications [-s] <POLICY_SPECS_FILE>` The output policy specifications file



---

## 2.2.3 ckms cc policy binary

Extract the policy from a public or private master key to a policy binary file

### Usage
`ckms cc policy binary [options]`
### Arguments
`--key-id [-i] <KEY_ID>` The public or private master key ID if the key is stored in the KMS

`--key-file [-f] <KEY_FILE>` If `key-id` is not provided, the file containing the public or private master key in TTLV format

`--policy [-p] <POLICY_BINARY_FILE>` The output binary policy file



---

## 2.2.4 ckms cc policy create

Create a policy binary file from policy specifications

### Usage
`ckms cc policy create [options]`
### Arguments
`--specifications [-s] <POLICY_SPECIFICATIONS_FILE>` The policy specifications filename. The policy is expressed as a JSON object describing the Policy axes. See the documentation for details

`--policy [-p] <POLICY_BINARY_FILE>` The output binary policy file generated from the specifications file



---

## 2.2.5 ckms cc policy add-attribute

Add an attribute to the policy of an existing private master key.

### Usage
`ckms cc policy add-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to create. Example: `department::rd`

`--hybridized <HYBRIDIZED>` Set encryption hint for the new attribute to use hybridized keys

Possible values:  `"true", "false"` [default: `"false"`]

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.2.6 ckms cc policy remove-attribute

Remove an attribute from the policy of an existing private master key.
Permanently removes the ability to use this attribute in both encryptions and decryptions.

### Usage
`ckms cc policy remove-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to remove. Example: `department::marketing`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.2.7 ckms cc policy disable-attribute

Disable an attribute from the policy of an existing private master key.
Prevents the encryption of new messages for this attribute while keeping the ability to decrypt existing ciphertexts.

### Usage
`ckms cc policy disable-attribute [options] <ATTRIBUTE>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to disable. Example: `department::marketing`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.2.8 ckms cc policy rename-attribute

Rename an attribute in the policy of an existing private master key.

### Usage
`ckms cc policy rename-attribute [options] <ATTRIBUTE>
 <NEW_NAME>
`
### Arguments
` <ATTRIBUTE>` The name of the attribute to rename. Example: `department::mkg`

` <NEW_NAME>` The new name for the attribute. Example: `marketing`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 2.3 ckms cc encrypt

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

## 2.4 ckms cc decrypt

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

## 3 ckms certificates

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

### Usage
`ckms certificates <subcommand>`

### Subcommands

**`certify`** [[3.1]](#31-ckms-certificates-certify)  Issue or renew a X509 certificate

**`decrypt`** [[3.2]](#32-ckms-certificates-decrypt)  Decrypt a file using the private key of a certificate

**`encrypt`** [[3.3]](#33-ckms-certificates-encrypt)  Encrypt a file using the certificate public key

**`export`** [[3.4]](#34-ckms-certificates-export)  Export a certificate from the KMS

**`import`** [[3.5]](#35-ckms-certificates-import)  Import one of the following:

- a certificate: formatted as a X509 PEM (pem), X509 DER (der) or JSON TTLV (json-ttlv)
- a certificate chain as a PEM-stack (chain)
- a PKCS12 file containing a certificate, a private key and possibly a chain (pkcs12)
- the Mozilla Common CA Database (CCADB - fetched by the CLI before import) (ccadb)

**`revoke`** [[3.6]](#36-ckms-certificates-revoke)  Revoke a certificate

**`destroy`** [[3.7]](#37-ckms-certificates-destroy)  Destroy a certificate

**`validate`** [[3.8]](#38-ckms-certificates-validate)  Validate a certificate

---

## 3.1 ckms certificates certify

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

Possible values:  `"nist-p192", "nist-p224", "nist-p256", "nist-p384", "nist-p521", "x25519", "ed25519", "x448", "ed448", "rsa1024", "rsa2048", "rsa3072", "rsa4096"` [default: `"rsa4096"`]

`--issuer-private-key-id [-k] <ISSUER_PRIVATE_KEY_ID>` The unique identifier of the private key of the issuer. A certificate must be linked to that private key if no issuer certificate id is provided

`--issuer-certificate-id [-i] <ISSUER_CERTIFICATE_ID>` The unique identifier of the certificate of the issuer. A private key must be linked to that certificate if no issuer private key id is provided

`--days [-d] <NUMBER_OF_DAYS>` The requested number of validity days The server may grant a different value

`--certificate-extensions [-e] <CERTIFICATE_EXTENSIONS>` The path to a X509 extension's file, containing a `v3_ca` paragraph
with the x509 extensions to use. For instance:

`--tag [-t] <TAG>` The tag to associate to the certificate. To specify multiple tags, use the option multiple times



---

## 3.2 ckms certificates decrypt

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



---

## 3.3 ckms certificates encrypt

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



---

## 3.4 ckms certificates export

Export a certificate from the KMS

### Usage
`ckms certificates export [options] <CERTIFICATE_FILE>
`
### Arguments
` <CERTIFICATE_FILE>` The file to export the certificate to

`--certificate-id [-c] <UNIQUE_ID>` The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
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

## 3.5 ckms certificates import

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

## 3.6 ckms certificates revoke

Revoke a certificate

### Usage
`ckms certificates revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 3.7 ckms certificates destroy

Destroy a certificate

### Usage
`ckms certificates destroy [options]`
### Arguments
`--certificate-id [-c] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 3.8 ckms certificates validate

Validate a certificate

### Usage
`ckms certificates validate [options]`
### Arguments
`--certificate [-v] <CERTIFICATE>` One or more Certificates filepath

`--unique-identifier [-k] <UNIQUE_IDENTIFIER>` One or more Unique Identifiers of Certificate Objects

`--validity-time [-t] <VALIDITY_TIME>` A Date-Time object indicating when the certificate chain needs to be valid. If omitted, the current date and time SHALL be assumed




---

## 4 ckms ec

Manage elliptic curve keys. Encrypt and decrypt data using ECIES

### Usage
`ckms ec <subcommand>`

### Subcommands

**`keys`** [[4.1]](#41-ckms-ec-keys)  Create, destroy, import, and export elliptic curve key pairs

**`encrypt`** [[4.2]](#42-ckms-ec-encrypt)  Encrypt a file with the given public key using ECIES

**`decrypt`** [[4.3]](#43-ckms-ec-decrypt)  Decrypts a file with the given private key using ECIES

---

## 4.1 ckms ec keys

Create, destroy, import, and export elliptic curve key pairs

### Usage
`ckms ec keys <subcommand>`

### Subcommands

**`create`** [[4.1.1]](#411-ckms-ec-keys-create)  Create an elliptic curve key pair

**`export`** [[4.1.2]](#412-ckms-ec-keys-export)  Export a key from the KMS

**`import`** [[4.1.3]](#413-ckms-ec-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[4.1.4]](#414-ckms-ec-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[4.1.5]](#415-ckms-ec-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[4.1.6]](#416-ckms-ec-keys-revoke)  Revoke a public or private key

**`destroy`** [[4.1.7]](#417-ckms-ec-keys-destroy)  Destroy a public or private key

---

## 4.1.1 ckms ec keys create

Create an elliptic curve key pair

### Usage
`ckms ec keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--curve [-c] <CURVE>` The elliptic curve

Possible values:  `"nist-p192", "nist-p224", "nist-p256", "nist-p384", "nist-p521", "x25519", "ed25519", "x448", "ed448"` [default: `"nist-p256"`]

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified



---

## 4.1.2 ckms ec keys export

Export a key from the KMS

### Usage
`ckms ec keys export [options] <KEY_FILE>
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

`--block-cipher-mode [-m] <BLOCK_CIPHER_MODE>` Block cipher mode

Possible values:  `"CBC", "ECB", "PCBC", "CFB", "OFB", "CTR", "CMAC", "CCM", "GCM", "CBCMAC", "XTS", "X9102AESKW", "X9102TDKW", "X9102AKW1", "X9102AKW2", "AEAD", "NISTKeyWrap", "GCMSIV"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data



---

## 4.1.3 ckms ec keys import

Import a private or public key in the KMS.

### Usage
`ckms ec keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

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

## 4.1.4 ckms ec keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`ckms ec keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 4.1.5 ckms ec keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`ckms ec keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 4.1.6 ckms ec keys revoke

Revoke a public or private key

### Usage
`ckms ec keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 4.1.7 ckms ec keys destroy

Destroy a public or private key

### Usage
`ckms ec keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 4.2 ckms ec encrypt

Encrypt a file with the given public key using ECIES

### Usage
`ckms ec encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data. This data needs to be provided back for decryption



---

## 4.3 ckms ec decrypt

Decrypts a file with the given private key using ECIES

### Usage
`ckms ec decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption




---

## 5 ckms attributes

Get/Set/Delete the KMIP object attributes

### Usage
`ckms attributes <subcommand>`

### Subcommands

**`get`** [[5.1]](#51-ckms-attributes-get)  Get the KMIP object attributes and tags.

**`set`** [[5.2]](#52-ckms-attributes-set)  Set the KMIP object attributes.

**`delete`** [[5.3]](#53-ckms-attributes-delete)  Delete the KMIP object attributes.

---

## 5.1 ckms attributes get

Get the KMIP object attributes and tags.

### Usage
`ckms attributes get [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--attribute [-a] <ATTRIBUTE>` The attributes or `KMIP-tags` to retrieve.
To specify multiple attributes, use the option multiple times.
If not specified, all possible attributes are returned.

Possible values:  `"ActivationDate", "ApplicationData", "ApplicationNamespace", "ApplicationSpecific_Information", "ArchiveDate", "AsynchronousCorrelation_Value", "AsynchronousIndicator", "Attribute", "AttributeName", "AttributeValue", "Authentication", "BatchCount", "BatchErrorContinuationOption", "BatchItem", "BatchOrderOption", "BlockCipherMode", "CancellationResult", "Certificate", "CertificateRequest", "CertificateRequestType", "CertificateType", "CertificateValue", "CompromiseDate", "CompromiseOccurrenceDate", "ContactInformation", "Credential", "CredentialType", "CredentialValue", "CriticalityIndicator", "CRTCoefficient", "CryptographicAlgorithm", "CryptographicDomainParameters", "CryptographicLength", "CryptographicParameters", "CryptographicUsageMask", "D", "DeactivationDate", "DerivationData", "DerivationMethod", "DerivationParameters", "DestroyDate", "Digest", "DigestValue", "EncryptionKeyInformation", "G", "HashingAlgorithm", "InitialDate", "InitializationVector", "IterationCount", "IVCounterNonce", "J", "Key", "KeyBlock", "KeyCompressionType", "KeyFormatType", "KeyMaterial", "KeyPartIdentifier", "KeyValue", "KeyWrappingData", "KeyWrappingSpecification", "LastChangeDate", "LeaseTime", "Link", "LinkType", "LinkedObjectIdentifier", "MACSignature", "MACSignatureKey_Information", "MaximumItems", "MaximumResponseSize", "MessageExtension", "Modulus", "Name", "NameType", "NameValue", "ObjectGroup", "ObjectType", "Offset", "OpaqueDataType", "OpaqueDataValue", "OpaqueObject", "Operation", "P", "PaddingMethod", "PrimeExponentP", "PrimeExponentQ", "PrimeFieldSize", "PrivateExponent", "PrivateKey", "PrivateKeyUniqueIdentifier", "ProcessStartDate", "ProtectStopDate", "ProtocolVersion", "ProtocolVersionMajor", "ProtocolVersionMinor", "PublicExponent", "PublicKey", "PublicKeyUniqueIdentifier", "PutFunction", "Q", "QString", "Qlength", "QueryFunction", "RecommendedCurve", "ReplacedUniqueIdentifier", "RequestHeader", "RequestMessage", "RequestPayload", "ResponseHeader", "ResponseMessage", "ResponsePayload", "ResultMessage", "ResultReason", "ResultStatus", "RevocationMessage", "RevocationReason", "RevocationReasonCode", "KeyRoleType", "Salt", "SecretData", "SecretDataType", "ServerInformation", "SplitKey", "SplitKeyMethod", "SplitKeyParts", "SplitKeyThreshold", "State", "StorageStatusMask", "SymmetricKey", "TimeStamp", "UniqueBatchItemID", "UniqueIdentifier", "UsageLimits", "UsageLimitsCount", "UsageLimitsTotal", "UsageLimitsUnit", "Username", "ValidityDate", "ValidityIndicator", "VendorExtension", "VendorIdentification", "WrappingMethod", "X", "Y", "Password", "DeviceIdentifier", "EncodingOption", "ExtensionInformation", "ExtensionName", "ExtensionTag", "ExtensionType", "Fresh", "MachineIdentifier", "MediaIdentifier", "NetworkIdentifier", "ObjectGroupMember", "CertificateLength", "DigitalSignatureAlgorithm", "CertificateSerialNumber", "DeviceSerialNumber", "IssuerAlternativeName", "IssuerDistinguishedName", "SubjectAlternativeName", "SubjectDistinguishedName", "X509CertificateIdentifier", "X509CertificateIssuer", "X509CertificateSubject", "KeyValueLocation", "KeyValueLocationValue", "KeyValueLocationType", "KeyValuePresent", "OriginalCreationDate", "PGPKey", "PGPKeyVersion", "AlternativeName", "AlternativeNameValue", "AlternativeNameType", "Data", "SignatureData", "DataLength", "RandomIV", "MACData", "AttestationType", "Nonce", "NonceID", "NonceValue", "AttestationMeasurement", "AttestationAssertion", "IVLength", "TagLength", "FixedFieldLength", "CounterLength", "InitialCounterValue", "InvocationFieldLength", "AttestationCapableIndicator", "OffsetItems", "LocatedItems", "CorrelationValue", "InitIndicator", "FinalIndicator", "RNGParameters", "RNGAlgorithm", "DRBGAlgorithm", "FIPS186Variation", "PredictionResistance", "RandomNumberGenerator", "ValidationInformation", "ValidationAuthorityType", "ValidationAuthorityCountry", "ValidationAuthorityURI", "ValidationVersionMajor", "ValidationVersionMinor", "ValidationType", "ValidationLevel", "ValidationCertificateIdentifier", "ValidationCertificateURI", "ValidationVendorURI", "ValidationProfile", "ProfileInformation", "ProfileName", "ServerURI", "ServerPort", "StreamingCapability", "AsynchronousCapability", "AttestationCapability", "UnwrapMode", "DestroyAction", "ShreddingAlgorithm", "RNGMode", "ClientRegistrationMethod", "CapabilityInformation", "KeyWrapType", "BatchUndoCapability", "BatchContinueCapability", "PKCS12FriendlyName", "Description", "Comment", "AuthenticatedEncryptionAdditionalData", "AuthenticatedEncryptionTag", "SaltLength", "MaskGenerator", "MaskGeneratorHashingAlgorithm", "PSource", "TrailerField", "ClientCorrelationValue", "ServerCorrelationValue", "DigestedData", "CertificateSubjectCN", "CertificateSubjectO", "CertificateSubjectOU", "CertificateSubjectEmail", "CertificateSubjectC", "CertificateSubjectST", "CertificateSubjectL", "CertificateSubjectUID", "CertificateSubjectSerialNumber", "CertificateSubjectTitle", "CertificateSubjectDC", "CertificateSubjectDNQualifier", "CertificateIssuerCN", "CertificateIssuerO", "CertificateIssuerOU", "CertificateIssuerEmail", "CertificateIssuerC", "CertificateIssuerST", "CertificateIssuerL", "CertificateIssuerUID", "CertificateIssuerSerialNumber", "CertificateIssuerTitle", "CertificateIssuerDC", "CertificateIssuerDNQualifier", "Sensitive", "AlwaysSensitive", "Extractable", "NeverExtractable", "ReplaceExisting", "Attributes", "CommonAttributes", "PrivateKeyAttributes", "PublicKeyAttributes", "ExtensionEnumeration", "ExtensionAttribute", "ExtensionParentStructureTag", "ExtensionDescription", "ServerName", "ServerSerialNumber", "ServerVersion", "ServerLoad", "ProductName", "BuildLevel", "BuildDate", "ClusterInfo", "AlternateFailoverEndpoints", "ShortUniqueIdentifier", "Reserved", "Tag", "CertificateRequestUniqueIdentifier", "NISTKeyType", "AttributeReference", "CurrentAttribute", "NewAttribute", "CertificateRequestValue", "LogMessage", "ProfileVersion", "ProfileVersionMajor", "ProfileVersionMinor", "ProtectionLevel", "ProtectionPeriod", "QuantumSafe", "QuantumSafeCapability", "Ticket", "TicketType", "TicketValue", "RequestCount", "Rights", "Objects", "Operations", "Right", "EndpointRole", "DefaultsInformation", "ObjectDefaults", "Ephemeral", "ServerHashedPassword", "OneTimePassword", "HashedPassword", "AdjustmentType", "PKCS11Interface", "PKCS11Function", "PKCS11InputParameters", "PKCS11OutputParameters", "PKCS11ReturnCode", "ProtectionStorageMask", "ProtectionStorageMasks", "InteropFunction", "InteropIdentifier", "AdjustmentValue", "CommonProtectionStorageMasks", "PrivateProtectionStorageMasks", "PublicProtectionStorageMasks"`

`--link-type [-l] <LINK_TYPE>` Filter on retrieved links. Only if KMIP tag `LinkType` is used in `attribute` parameter.
To specify multiple attributes, use the option multiple times.
If not specified, all possible link types are returned.

Possible values:  `"CertificateLink", "PublicKeyLink", "PrivateKeyLink", "DerivationBaseObjectLink", "DerivedKeyLink", "ReplacementObjectLink", "ReplacedObjectLink", "ParentLink", "ChildLink", "PreviousLink", "NextLink", "PKCS12CertificateLink", "PKCS12PasswordLink", "WrappingKeyLink"`

`--output-file [-o] <OUTPUT_FILE>` An optional file where to export the attributes.
The attributes will be in JSON TTLV format.



---

## 5.2 ckms attributes set

Set the KMIP object attributes.

### Usage
`ckms attributes set [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--activation-date [-d] <ACTIVATION_DATE>` Set the activation date of the key. Epoch time (or Unix time) in milliseconds

`--cryptographic-algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` The cryptographic algorithm used by the key

Possible values:  `"DES", "THREE_DES", "AES", "RSA", "DSA", "ECDSA", "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACMD5", "DH", "ECDH", "ECMQV", "Blowfish", "Camellia", "CAST5", "IDEA", "MARS", "RC2", "RC4", "RC5", "SKIPJACK", "Twofish", "EC", "OneTimePad", "ChaCha20", "Poly1305", "ChaCha20Poly1305", "SHA3224", "SHA3256", "SHA3384", "SHA3512", "HMACSHA3224", "HMACSHA3256", "HMACSHA3384", "HMACSHA3512", "SHAKE128", "SHAKE256", "ARIA", "SEED", "SM2", "SM3", "SM4", "GOSTR34102012", "GOSTR34112012", "GOSTR34132015", "GOST2814789", "XMSS", "SPHINCS_256", "Page166Of230McEliece", "McEliece6960119", "McEliece8192128", "Ed25519", "Ed448", "CoverCrypt", "CoverCryptBulk"`

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

## 5.3 ckms attributes delete

Delete the KMIP object attributes.

### Usage
`ckms attributes delete [options]`
### Arguments
`--id [-i] <ID>` The unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--activation-date [-d] <ACTIVATION_DATE>` Set the activation date of the key. Epoch time (or Unix time) in milliseconds

`--cryptographic-algorithm [-a] <CRYPTOGRAPHIC_ALGORITHM>` The cryptographic algorithm used by the key

Possible values:  `"DES", "THREE_DES", "AES", "RSA", "DSA", "ECDSA", "HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACMD5", "DH", "ECDH", "ECMQV", "Blowfish", "Camellia", "CAST5", "IDEA", "MARS", "RC2", "RC4", "RC5", "SKIPJACK", "Twofish", "EC", "OneTimePad", "ChaCha20", "Poly1305", "ChaCha20Poly1305", "SHA3224", "SHA3256", "SHA3384", "SHA3512", "HMACSHA3224", "HMACSHA3256", "HMACSHA3384", "HMACSHA3512", "SHAKE128", "SHAKE256", "ARIA", "SEED", "SM2", "SM3", "SM4", "GOSTR34102012", "GOSTR34112012", "GOSTR34132015", "GOST2814789", "XMSS", "SPHINCS_256", "Page166Of230McEliece", "McEliece6960119", "McEliece8192128", "Ed25519", "Ed448", "CoverCrypt", "CoverCryptBulk"`

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

Possible values:  `"ActivationDate", "ApplicationData", "ApplicationNamespace", "ApplicationSpecific_Information", "ArchiveDate", "AsynchronousCorrelation_Value", "AsynchronousIndicator", "Attribute", "AttributeName", "AttributeValue", "Authentication", "BatchCount", "BatchErrorContinuationOption", "BatchItem", "BatchOrderOption", "BlockCipherMode", "CancellationResult", "Certificate", "CertificateRequest", "CertificateRequestType", "CertificateType", "CertificateValue", "CompromiseDate", "CompromiseOccurrenceDate", "ContactInformation", "Credential", "CredentialType", "CredentialValue", "CriticalityIndicator", "CRTCoefficient", "CryptographicAlgorithm", "CryptographicDomainParameters", "CryptographicLength", "CryptographicParameters", "CryptographicUsageMask", "D", "DeactivationDate", "DerivationData", "DerivationMethod", "DerivationParameters", "DestroyDate", "Digest", "DigestValue", "EncryptionKeyInformation", "G", "HashingAlgorithm", "InitialDate", "InitializationVector", "IterationCount", "IVCounterNonce", "J", "Key", "KeyBlock", "KeyCompressionType", "KeyFormatType", "KeyMaterial", "KeyPartIdentifier", "KeyValue", "KeyWrappingData", "KeyWrappingSpecification", "LastChangeDate", "LeaseTime", "Link", "LinkType", "LinkedObjectIdentifier", "MACSignature", "MACSignatureKey_Information", "MaximumItems", "MaximumResponseSize", "MessageExtension", "Modulus", "Name", "NameType", "NameValue", "ObjectGroup", "ObjectType", "Offset", "OpaqueDataType", "OpaqueDataValue", "OpaqueObject", "Operation", "P", "PaddingMethod", "PrimeExponentP", "PrimeExponentQ", "PrimeFieldSize", "PrivateExponent", "PrivateKey", "PrivateKeyUniqueIdentifier", "ProcessStartDate", "ProtectStopDate", "ProtocolVersion", "ProtocolVersionMajor", "ProtocolVersionMinor", "PublicExponent", "PublicKey", "PublicKeyUniqueIdentifier", "PutFunction", "Q", "QString", "Qlength", "QueryFunction", "RecommendedCurve", "ReplacedUniqueIdentifier", "RequestHeader", "RequestMessage", "RequestPayload", "ResponseHeader", "ResponseMessage", "ResponsePayload", "ResultMessage", "ResultReason", "ResultStatus", "RevocationMessage", "RevocationReason", "RevocationReasonCode", "KeyRoleType", "Salt", "SecretData", "SecretDataType", "ServerInformation", "SplitKey", "SplitKeyMethod", "SplitKeyParts", "SplitKeyThreshold", "State", "StorageStatusMask", "SymmetricKey", "TimeStamp", "UniqueBatchItemID", "UniqueIdentifier", "UsageLimits", "UsageLimitsCount", "UsageLimitsTotal", "UsageLimitsUnit", "Username", "ValidityDate", "ValidityIndicator", "VendorExtension", "VendorIdentification", "WrappingMethod", "X", "Y", "Password", "DeviceIdentifier", "EncodingOption", "ExtensionInformation", "ExtensionName", "ExtensionTag", "ExtensionType", "Fresh", "MachineIdentifier", "MediaIdentifier", "NetworkIdentifier", "ObjectGroupMember", "CertificateLength", "DigitalSignatureAlgorithm", "CertificateSerialNumber", "DeviceSerialNumber", "IssuerAlternativeName", "IssuerDistinguishedName", "SubjectAlternativeName", "SubjectDistinguishedName", "X509CertificateIdentifier", "X509CertificateIssuer", "X509CertificateSubject", "KeyValueLocation", "KeyValueLocationValue", "KeyValueLocationType", "KeyValuePresent", "OriginalCreationDate", "PGPKey", "PGPKeyVersion", "AlternativeName", "AlternativeNameValue", "AlternativeNameType", "Data", "SignatureData", "DataLength", "RandomIV", "MACData", "AttestationType", "Nonce", "NonceID", "NonceValue", "AttestationMeasurement", "AttestationAssertion", "IVLength", "TagLength", "FixedFieldLength", "CounterLength", "InitialCounterValue", "InvocationFieldLength", "AttestationCapableIndicator", "OffsetItems", "LocatedItems", "CorrelationValue", "InitIndicator", "FinalIndicator", "RNGParameters", "RNGAlgorithm", "DRBGAlgorithm", "FIPS186Variation", "PredictionResistance", "RandomNumberGenerator", "ValidationInformation", "ValidationAuthorityType", "ValidationAuthorityCountry", "ValidationAuthorityURI", "ValidationVersionMajor", "ValidationVersionMinor", "ValidationType", "ValidationLevel", "ValidationCertificateIdentifier", "ValidationCertificateURI", "ValidationVendorURI", "ValidationProfile", "ProfileInformation", "ProfileName", "ServerURI", "ServerPort", "StreamingCapability", "AsynchronousCapability", "AttestationCapability", "UnwrapMode", "DestroyAction", "ShreddingAlgorithm", "RNGMode", "ClientRegistrationMethod", "CapabilityInformation", "KeyWrapType", "BatchUndoCapability", "BatchContinueCapability", "PKCS12FriendlyName", "Description", "Comment", "AuthenticatedEncryptionAdditionalData", "AuthenticatedEncryptionTag", "SaltLength", "MaskGenerator", "MaskGeneratorHashingAlgorithm", "PSource", "TrailerField", "ClientCorrelationValue", "ServerCorrelationValue", "DigestedData", "CertificateSubjectCN", "CertificateSubjectO", "CertificateSubjectOU", "CertificateSubjectEmail", "CertificateSubjectC", "CertificateSubjectST", "CertificateSubjectL", "CertificateSubjectUID", "CertificateSubjectSerialNumber", "CertificateSubjectTitle", "CertificateSubjectDC", "CertificateSubjectDNQualifier", "CertificateIssuerCN", "CertificateIssuerO", "CertificateIssuerOU", "CertificateIssuerEmail", "CertificateIssuerC", "CertificateIssuerST", "CertificateIssuerL", "CertificateIssuerUID", "CertificateIssuerSerialNumber", "CertificateIssuerTitle", "CertificateIssuerDC", "CertificateIssuerDNQualifier", "Sensitive", "AlwaysSensitive", "Extractable", "NeverExtractable", "ReplaceExisting", "Attributes", "CommonAttributes", "PrivateKeyAttributes", "PublicKeyAttributes", "ExtensionEnumeration", "ExtensionAttribute", "ExtensionParentStructureTag", "ExtensionDescription", "ServerName", "ServerSerialNumber", "ServerVersion", "ServerLoad", "ProductName", "BuildLevel", "BuildDate", "ClusterInfo", "AlternateFailoverEndpoints", "ShortUniqueIdentifier", "Reserved", "Tag", "CertificateRequestUniqueIdentifier", "NISTKeyType", "AttributeReference", "CurrentAttribute", "NewAttribute", "CertificateRequestValue", "LogMessage", "ProfileVersion", "ProfileVersionMajor", "ProfileVersionMinor", "ProtectionLevel", "ProtectionPeriod", "QuantumSafe", "QuantumSafeCapability", "Ticket", "TicketType", "TicketValue", "RequestCount", "Rights", "Objects", "Operations", "Right", "EndpointRole", "DefaultsInformation", "ObjectDefaults", "Ephemeral", "ServerHashedPassword", "OneTimePassword", "HashedPassword", "AdjustmentType", "PKCS11Interface", "PKCS11Function", "PKCS11InputParameters", "PKCS11OutputParameters", "PKCS11ReturnCode", "ProtectionStorageMask", "ProtectionStorageMasks", "InteropFunction", "InteropIdentifier", "AdjustmentValue", "CommonProtectionStorageMasks", "PrivateProtectionStorageMasks", "PublicProtectionStorageMasks"`




---

## 6 ckms locate

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

## 7 ckms new-database

Initialize a new user encrypted database and return the secret (`SQLCipher` only).

### Usage
`ckms new-database`


---

## 8 ckms rsa

Manage RSA keys. Encrypt and decrypt data using RSA keys

### Usage
`ckms rsa <subcommand>`

### Subcommands

**`keys`** [[8.1]](#81-ckms-rsa-keys)  Create, destroy, import, and export RSA key pairs

**`encrypt`** [[8.2]](#82-ckms-rsa-encrypt)  Encrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

**`decrypt`** [[8.3]](#83-ckms-rsa-decrypt)  Decrypt a file with the given public key using either

 - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
 - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
 - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40

---

## 8.1 ckms rsa keys

Create, destroy, import, and export RSA key pairs

### Usage
`ckms rsa keys <subcommand>`

### Subcommands

**`create`** [[8.1.1]](#811-ckms-rsa-keys-create)  Create a new RSA key pair

**`export`** [[8.1.2]](#812-ckms-rsa-keys-export)  Export a key from the KMS

**`import`** [[8.1.3]](#813-ckms-rsa-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[8.1.4]](#814-ckms-rsa-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[8.1.5]](#815-ckms-rsa-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[8.1.6]](#816-ckms-rsa-keys-revoke)  Revoke a public or private key

**`destroy`** [[8.1.7]](#817-ckms-rsa-keys-destroy)  Destroy a public or private key

---

## 8.1.1 ckms rsa keys create

Create a new RSA key pair

### Usage
`ckms rsa keys create [options] [PRIVATE_KEY_ID]
`
### Arguments
`--size_in_bits [-s] <SIZE_IN_BITS>` The expected size in bits

`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times

` <PRIVATE_KEY_ID>` The unique id of the private key; a random uuid is generated if not specified



---

## 8.1.2 ckms rsa keys export

Export a key from the KMS

### Usage
`ckms rsa keys export [options] <KEY_FILE>
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

`--block-cipher-mode [-m] <BLOCK_CIPHER_MODE>` Block cipher mode

Possible values:  `"CBC", "ECB", "PCBC", "CFB", "OFB", "CTR", "CMAC", "CCM", "GCM", "CBCMAC", "XTS", "X9102AESKW", "X9102TDKW", "X9102AKW1", "X9102AKW2", "AEAD", "NISTKeyWrap", "GCMSIV"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data



---

## 8.1.3 ckms rsa keys import

Import a private or public key in the KMS.

### Usage
`ckms rsa keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

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

## 8.1.4 ckms rsa keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`ckms rsa keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 8.1.5 ckms rsa keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`ckms rsa keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 8.1.6 ckms rsa keys revoke

Revoke a public or private key

### Usage
`ckms rsa keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 8.1.7 ckms rsa keys destroy

Destroy a public or private key

### Usage
`ckms rsa keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier of the key to destroy If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 8.2 ckms rsa encrypt

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

## 8.3 ckms rsa decrypt

Decrypt a file with the given public key using either

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

`--hashing-algorithm [-s] <HASH_FN>` The hashing algorithm

Possible values:  `"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512"` [default: `"sha256"`]

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path




---

## 9 ckms server-version

Print the version of the server

### Usage
`ckms server-version`


---

## 10 ckms sym

Manage symmetric keys. Encrypt and decrypt data

### Usage
`ckms sym <subcommand>`

### Subcommands

**`keys`** [[10.1]](#101-ckms-sym-keys)  Create, destroy, import, and export symmetric keys

**`encrypt`** [[10.2]](#102-ckms-sym-encrypt)  Encrypt a file using a symmetric cipher

**`decrypt`** [[10.3]](#103-ckms-sym-decrypt)  Decrypt a file using a symmetric key.

---

## 10.1 ckms sym keys

Create, destroy, import, and export symmetric keys

### Usage
`ckms sym keys <subcommand>`

### Subcommands

**`create`** [[10.1.1]](#1011-ckms-sym-keys-create)  Create a new symmetric key

**`re-key`** [[10.1.2]](#1012-ckms-sym-keys-re-key)  Refresh an existing symmetric key

**`export`** [[10.1.3]](#1013-ckms-sym-keys-export)  Export a key from the KMS

**`import`** [[10.1.4]](#1014-ckms-sym-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[10.1.5]](#1015-ckms-sym-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[10.1.6]](#1016-ckms-sym-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[10.1.7]](#1017-ckms-sym-keys-revoke)  Revoke a symmetric key

**`destroy`** [[10.1.8]](#1018-ckms-sym-keys-destroy)  Destroy a symmetric key

---

## 10.1.1 ckms sym keys create

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



---

## 10.1.2 ckms sym keys re-key

Refresh an existing symmetric key

### Usage
`ckms sym keys re-key [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 10.1.3 ckms sym keys export

Export a key from the KMS

### Usage
`ckms sym keys export [options] <KEY_FILE>
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

`--block-cipher-mode [-m] <BLOCK_CIPHER_MODE>` Block cipher mode

Possible values:  `"CBC", "ECB", "PCBC", "CFB", "OFB", "CTR", "CMAC", "CCM", "GCM", "CBCMAC", "XTS", "X9102AESKW", "X9102TDKW", "X9102AKW1", "X9102AKW2", "AEAD", "NISTKeyWrap", "GCMSIV"`

`--authenticated-additional-data [-d] <AUTHENTICATED_ADDITIONAL_DATA>` Authenticated encryption additional data



---

## 10.1.4 ckms sym keys import

Import a private or public key in the KMS.

### Usage
`ckms sym keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a random uuid is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

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

## 10.1.5 ckms sym keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`ckms sym keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key. This password will be derived into a AES-256 symmetric key. For security reasons, a fresh salt is internally handled and generated by `ckms` and this final AES symmetric key will be displayed only once

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 10.1.6 ckms sym keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`ckms sym keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 10.1.7 ckms sym keys revoke

Revoke a symmetric key

### Usage
`ckms sym keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 10.1.8 ckms sym keys destroy

Destroy a symmetric key

### Usage
`ckms sym keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 10.2 ckms sym encrypt

Encrypt a file using a symmetric cipher

### Usage
`ckms sym encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The symmetric key unique identifier. If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to encrypt the data encryption key.

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv", "rfc5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--nonce [-n] <NONCE>` Optional nonce/IV (or tweak for XTS) as a hex string. If not provided, a random value is generated

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional additional authentication data as a hex string. This data needs to be provided back for decryption. This data is ignored with XTS



---

## 10.3 ckms sym decrypt

Decrypt a file using a symmetric key.

### Usage
`ckms sym decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--data-encryption-algorithm [-d] <DATA_ENCRYPTION_ALGORITHM>` The data encryption algorithm. If not specified, aes-gcm is used

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv"` [default: `"aes-gcm"`]

`--key-encryption-algorithm [-e] <KEY_ENCRYPTION_ALGORITHM>` The optional key encryption algorithm used to decrypt the data encryption key.

Possible values:  `"chacha20-poly1305", "aes-gcm", "aes-xts", "aes-gcm-siv", "rfc5649"`

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption as a hex string




---

## 11 ckms login

Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

### Usage
`ckms login`


---

## 12 ckms logout

Logout from the Identity Provider.

### Usage
`ckms logout`


---

## 13 ckms markdown

Action to auto-generate doc in Markdown format Run `cargo run --bin ckms -- markdown documentation/docs/cli/main_commands.md`

### Usage
`ckms markdown [options] <MARKDOWN_FILE>
`
### Arguments
` <MARKDOWN_FILE>` The file to export the markdown to



---

## 14 ckms google

Manage google elements. Handle key pairs and identities from Gmail API

### Usage
`ckms google <subcommand>`

### Subcommands

**`key-pairs`** [[14.1]](#141-ckms-google-key-pairs)  Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

**`identities`** [[14.2]](#142-ckms-google-identities)  Insert, get, list, patch and delete identities from Gmail API

---

## 14.1 ckms google key-pairs

Insert, get, list, enable, disabled and obliterate key pairs to Gmail API

### Usage
`ckms google key-pairs <subcommand>`

### Subcommands

**`get`** [[14.1.1]](#1411-ckms-google-key-pairs-get)  Retrieves an existing client-side encryption key pair.

**`list`** [[14.1.2]](#1412-ckms-google-key-pairs-list)  Lists client-side encryption key pairs for a user.

**`enable`** [[14.1.3]](#1413-ckms-google-key-pairs-enable)  Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

**`disable`** [[14.1.4]](#1414-ckms-google-key-pairs-disable)  Turns off a client-side encryption key pair. The authenticated user can no longer use the key
pair to decrypt incoming CSE message texts or sign outgoing CSE mail. To regain access, use the
key pairs.enable to turn on the key pair. After 30 days, you can permanently delete the key pair
by using the key pairs.obliterate method.

**`obliterate`** [[14.1.5]](#1415-ckms-google-key-pairs-obliterate)  Deletes a client-side encryption key pair permanently and immediately. You can only permanently
delete key pairs that have been turned off for more than 30 days. To turn off a key pair, use
the key pairs disable method. Gmail can't restore or decrypt any messages that were encrypted by
an obliterated key. Authenticated users and Google Workspace administrators lose access to
reading the encrypted messages.

**`create`** [[14.1.6]](#1416-ckms-google-key-pairs-create)  Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

---

## 14.1.1 ckms google key-pairs get

Retrieves an existing client-side encryption key pair.

### Usage
`ckms google key-pairs get [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to retrieve

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 14.1.2 ckms google key-pairs list

Lists client-side encryption key pairs for a user.

### Usage
`ckms google key-pairs list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 14.1.3 ckms google key-pairs enable

Turns on a client-side encryption key pair that was turned off. The key pair becomes active
again for any associated client-side encryption identities.

### Usage
`ckms google key-pairs enable [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The identifier of the key pair to enable

`--user-id [-u] <USER_ID>` The requester's primary email address



---

## 14.1.4 ckms google key-pairs disable

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

## 14.1.5 ckms google key-pairs obliterate

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

## 14.1.6 ckms google key-pairs create

Creates and uploads a client-side encryption S/MIME public key certificate chain and private key
metadata for a user.

### Usage
`ckms google key-pairs create [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address

`--cse-key-id [-w] <CSE_KEY_ID>` CSE key ID to wrap exported user private key

`--issuer-private-key-id [-i] <ISSUER_PRIVATE_KEY_ID>` The issuer private key id

`--subject-name [-s] <SUBJECT_NAME>` When certifying a public key, or generating a keypair,
the subject name to use.

`--rsa-private-key-id [-k] <RSA_PRIVATE_KEY_ID>` The existing private key id of an existing RSA keypair to use (optional - if no ID is provided, a RSA keypair will be created)

`--dry-run <DRY_RUN>` Dry run mode. If set, the action will not be executed

Possible values:  `"true", "false"` [default: `"false"`]




---

## 14.2 ckms google identities

Insert, get, list, patch and delete identities from Gmail API

### Usage
`ckms google identities <subcommand>`

### Subcommands

**`get`** [[14.2.1]](#1421-ckms-google-identities-get)  Retrieves a client-side encryption identity configuration.

**`list`** [[14.2.2]](#1422-ckms-google-identities-list)  Lists the client-side encrypted identities for an authenticated user.

**`insert`** [[14.2.3]](#1423-ckms-google-identities-insert)  Creates and configures a client-side encryption identity that's authorized to send mail from the
user account. Google publishes the S/MIME certificate to a shared domain-wide directory so that
people within a Google Workspace organization can encrypt and send mail to the identity.

**`delete`** [[14.2.4]](#1424-ckms-google-identities-delete)  Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

**`patch`** [[14.2.5]](#1425-ckms-google-identities-patch)  Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

---

## 14.2.1 ckms google identities get

Retrieves a client-side encryption identity configuration.

### Usage
`ckms google identities get [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 14.2.2 ckms google identities list

Lists the client-side encrypted identities for an authenticated user.

### Usage
`ckms google identities list [options] <USER_ID>
`
### Arguments
` <USER_ID>` The requester's primary email address



---

## 14.2.3 ckms google identities insert

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

## 14.2.4 ckms google identities delete

Deletes a client-side encryption identity. The authenticated user can no longer use the identity
to send encrypted messages. You cannot restore the identity after you delete it. Instead, use
the identities.create method to create another identity with the same configuration.

### Usage
`ckms google identities delete [options] <USER_ID>
`
### Arguments
` <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved



---

## 14.2.5 ckms google identities patch

Associates a different key pair with an existing client-side encryption identity. The updated
key pair must validate against Google's S/MIME certificate profiles.

### Usage
`ckms google identities patch [options] <KEY_PAIRS_ID>
`
### Arguments
` <KEY_PAIRS_ID>` The key pair id, associated with a given cert/key. You can get the by listing the key pairs associated with the user-id

`--user-id [-u] <USER_ID>` The primary email address associated with the client-side encryption identity configuration that's retrieved







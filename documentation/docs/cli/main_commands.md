*-- This file is auto-generated using the `ckms markdown` command. --*

##  ckms

CLI used to manage the Cosmian KMS.

### Usage
`ckms <subcommand>`

### Subcommands

**`access-rights`** [[1]](#1-ckms-access-rights)  Manage the users' access rights to the cryptographic objects

**`cc`** [[2]](#2-ckms-cc)  Manage Covercrypt keys and policies. Rotate attributes. Encrypt and decrypt data

**`certificates`** [[3]](#3-ckms-certificates)  Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

**`ec`** [[4]](#4-ckms-ec)  Manage elliptic curve keys. Encrypt and decrypt data using ECIES

**`get-attributes`** [[5]](#5-ckms-get-attributes)  Get the KMIP object attributes and tags.

**`locate`** [[6]](#6-ckms-locate)  Locate cryptographic objects inside the KMS

**`new-database`** [[7]](#7-ckms-new-database)  Initialize a new user encrypted database and return the secret (`SQLCipher` only).

**`server-version`** [[8]](#8-ckms-server-version)  Print the version of the server

**`sym`** [[9]](#9-ckms-sym)  Manage symmetric keys. Encrypt and decrypt data

**`login`** [[10]](#10-ckms-login)  Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

**`logout`** [[11]](#11-ckms-logout)  Logout from the Identity Provider.

**`markdown`** [[12]](#12-ckms-markdown)  Generate the CLI documentation as markdown

---

## 1 ckms access-rights

Manage the users' access rights to the cryptographic objects

### Usage
`ckms access-rights <subcommand>`

### Subcommands

**`grant`** [[1.1]](#11-ckms-access-rights-grant)  Grant another user an access right to an object

**`revoke`** [[1.2]](#12-ckms-access-rights-revoke)  Revoke another user access right to an object

**`list`** [[1.3]](#13-ckms-access-rights-list)  List the access rights granted on an object to other users

**`owned`** [[1.4]](#14-ckms-access-rights-owned)  List the objects owned by the calling user

**`obtained`** [[1.5]](#15-ckms-access-rights-obtained)  List the access rights obtained by the calling user

---

## 1.1 ckms access-rights grant

Grant another user an access right to an object

### Usage
`ckms access-rights grant [options] <USER>
 <OBJECT_UID>
 <OPERATION>
`
### Arguments
` <USER>` The user identifier to allow

` <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATION>` The KMIP operation to allow



---

## 1.2 ckms access-rights revoke

Revoke another user access right to an object

### Usage
`ckms access-rights revoke [options] <USER>
 <OBJECT_UID>
 <OPERATION>
`
### Arguments
` <USER>` The user to revoke access to

` <OBJECT_UID>` The object unique identifier stored in the KMS

` <OPERATION>` The operation to revoke (create, get, encrypt, decrypt, import, revoke, locate, rekey, destroy)



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

**`keys`** [[2.1]](#21-ckms-cc-keys)  Create, destroy, import, export `Covercrypt` master and user keys

**`policy`** [[2.2]](#22-ckms-cc-policy)  Extract or view policies of existing keys, and create a binary policy from specifications

**`rotate`** [[2.3]](#23-ckms-cc-rotate)  Rotate attributes and rekey the master and user keys.

**`encrypt`** [[2.4]](#24-ckms-cc-encrypt)  Encrypt a file using Covercrypt

**`decrypt`** [[2.5]](#25-ckms-cc-decrypt)  Decrypt a file using Covercrypt

---

## 2.1 ckms cc keys

Create, destroy, import, export `Covercrypt` master and user keys

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

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.



---

## 2.1.4 ckms cc keys import

Import a private or public key in the KMS.

### Usage
`ckms cc keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a unique id based on the key material is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times



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

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key

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

`--unwrap-password [-p] <UNWRAP_PASSWORD>` A password to unwrap the imported key

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

## 2.2 ckms cc policy

Extract or view policies of existing keys, and create a binary policy from specifications

### Usage
`ckms cc policy <subcommand>`

### Subcommands

**`view`** [[2.2.1]](#221-ckms-cc-policy-view)  View the policy of an existing public or private master key.

**`specs`** [[2.2.2]](#222-ckms-cc-policy-specs)  Extract the policy specifications from a public or private master key to a policy specifications file

**`binary`** [[2.2.3]](#223-ckms-cc-policy-binary)  Extract the policy from a public or private master key to a policy binary file

**`create`** [[2.2.4]](#224-ckms-cc-policy-create)  Create a policy binary file from policy specifications

---

## 2.2.1 ckms cc policy view

View the policy of an existing public or private master key.

### Usage
`ckms cc policy view [options]`
### Arguments
`--key-id [-i] <KEY_ID>` The public or private master key ID if the key is stored in the KMS

`--key-file [-f] <KEY_FILE>` If `key-id` is not provided, the file containing the public or private master key in TTLV format

`--detailed [-d] <DETAILED>` Show all the policy details rather than just the specifications



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

## 2.3 ckms cc rotate

Rotate attributes and rekey the master and user keys.

### Usage
`ckms cc rotate [options] <ATTRIBUTES>...
`
### Arguments
` <ATTRIBUTES>` The policy attributes to rotate. Example: `department::marketing level::confidential`

`--key-id [-k] <SECRET_KEY_ID>` The private master key unique identifier stored in the KMS If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 2.4 ckms cc encrypt

Encrypt a file using Covercrypt

### Usage
`ckms cc encrypt [options] <FILE>...
 <ENCRYPTION_POLICY>
`
### Arguments
` <FILE>` The files to encrypt

` <ENCRYPTION_POLICY>` The encryption policy to encrypt the file with Example: "department::marketing && level::confidential"`

`--key-id [-k] <KEY_ID>` The public key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data. This data needs to be provided back for decryption



---

## 2.5 ckms cc decrypt

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

**`certify`** [[3.1]](#31-ckms-certificates-certify)  Certify a Certificate Signing Request or a Public key to create a X509 certificate.

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

---

## 3.1 ckms certificates certify

Certify a Certificate Signing Request or a Public key to create a X509 certificate.

### Usage
`ckms certificates certify [options]`
### Arguments
`--certificate-id [-i] <CERTIFICATE_ID>` The certificate unique identifier. A random one will be generated if not provided

`--certificate-signing-request [-r] <CERTIFICATE_SIGNING_REQUEST>` The path to a certificate signing request

`--certificate-signing-request-format [-f] <CERTIFICATE_SIGNING_REQUEST_FORMAT>` The format of the certificate signing request

Possible values:  `"pem", "der"` [default: `"pem"`]

`--public-key-id-to-certify [-p] <PUBLIC_KEY_ID_TO_CERTIFY>` If not using a CSR, the id of the public key to certify

`--subject-name [-s] <SUBJECT_NAME>` When certifying a public key, the subject name to use

`--issuer-private-key-id [-k] <ISSUER_PRIVATE_KEY_ID>` The unique identifier of the private key of the issuer. A certificate must be linked to that private key if no issuer certificate id is provided

`--issuer-certificate-id [-c] <ISSUER_CERTIFICATE_ID>` The unique identifier of the certificate of the issuer. A private key must be linked to that certificate if no issuer private key id is provided

`--days [-d] <NUMBER_OF_DAYS>` The requested number of validity days The server may grant a different value

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

`--certificate-id [-k] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

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

`--certificate-id [-k] <UNIQUE_ID>` The certificate unique identifier stored in the KMS; for PKCS#12, provide the private key id
If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate/private key when no unique id is specified.
To specify multiple tags, use the option multiple times.

`--format [-f] <OUTPUT_FORMAT>` Export the certificate in the selected format

Possible values:  `"json-ttlv", "pem", "pkcs12"` [default: `"json-ttlv"`]

`--pkcs12-password [-p] <PKCS12_PASSWORD>` Password to use to protect the PKCS#12 file

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed certificates or private key (for PKCS#12).
The user must be the owner of the certificate.
Destroyed objects have their key material removed.



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

`--tag [-t] <TAG>` The tag to associate with the certificate. To specify multiple tags, use the option multiple times



---

## 3.6 ckms certificates revoke

Revoke a certificate

### Usage
`ckms certificates revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--certificate-id [-k] <CERTIFICATE_ID>` The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times



---

## 3.7 ckms certificates destroy

Destroy a certificate

### Usage
`ckms certificates destroy [options]`
### Arguments
`--certificate-id [-k] <CERTIFICATE_ID>` The certificate unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times




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

**`create`** [[4.1.1]](#411-ckms-ec-keys-create)  Create a new X25519 key pair

**`export`** [[4.1.2]](#412-ckms-ec-keys-export)  Export a key from the KMS

**`import`** [[4.1.3]](#413-ckms-ec-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[4.1.4]](#414-ckms-ec-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[4.1.5]](#415-ckms-ec-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[4.1.6]](#416-ckms-ec-keys-revoke)  Revoke a public or private key

**`destroy`** [[4.1.7]](#417-ckms-ec-keys-destroy)  Destroy a public or private key

---

## 4.1.1 ckms ec keys create

Create a new X25519 key pair

### Usage
`ckms ec keys create [options]`
### Arguments
`--tag [-t] <TAG>` The tag to associate with the master key pair. To specify multiple tags, use the option multiple times



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

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.



---

## 4.1.3 ckms ec keys import

Import a private or public key in the KMS.

### Usage
`ckms ec keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a unique id based on the key material is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times



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

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key

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

`--unwrap-password [-p] <UNWRAP_PASSWORD>` A password to unwrap the imported key

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

## 5 ckms get-attributes

Get the KMIP object attributes and tags.

### Usage
`ckms get-attributes [options]`
### Arguments
`--id [-i] <ID>` The key unique identifier of the cryptographic object. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--attribute [-a] <ATTRIBUTE>` The attributes or tags to retrieve.
To specify multiple attributes, use the option multiple times.

Possible values:  `"activation-date", "cryptographic-algorithm", "cryptographic-length", "cryptographic-parameters", "cryptographic-domain-parameters", "cryptographic-usage-mask", "key-format-type", "linked-private-key-id", "linked-public-key-id", "linked-issuer-certificate-id", "linked-certificate-id", "tags"`

`--output-file [-o] <OUTPUT_FILE>` An optional file where to export the attributes.
The attributes will be in JSON TTLV format.



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

`--public-key-id [-p] <PUBLIC_KEY_ID>` Locate an object which has a link to this public key id

`--private-key-id [-k] <PRIVATE_KEY_ID>` Locate an object which has a link to this private key id

`--certificate-id [-c] <CERTIFICATE_ID>` Locate an object which has a link to this certificate key id

`--certificate-cn <CERTIFICATE_CN>` Locate a certificate which has this Common Name

`--certificate-spki <CERTIFICATE_SPKI>` Locate a certificate which has this Subject Public Key Info. For example: AF:B0:19:F4:09:3E:2F:F4:52:07:54:7F:17:62:9D:74:76:E3:A4:F6 The value will be stripped from the colons and converted to lower case



---

## 7 ckms new-database

Initialize a new user encrypted database and return the secret (`SQLCipher` only).

### Usage
`ckms new-database`


---

## 8 ckms server-version

Print the version of the server

### Usage
`ckms server-version`


---

## 9 ckms sym

Manage symmetric keys. Encrypt and decrypt data

### Usage
`ckms sym <subcommand>`

### Subcommands

**`keys`** [[9.1]](#91-ckms-sym-keys)  Create, destroy, import, and export symmetric keys

**`encrypt`** [[9.2]](#92-ckms-sym-encrypt)  Encrypt a file using AES GCM

**`decrypt`** [[9.3]](#93-ckms-sym-decrypt)  Decrypts a file using AES GCM

---

## 9.1 ckms sym keys

Create, destroy, import, and export symmetric keys

### Usage
`ckms sym keys <subcommand>`

### Subcommands

**`create`** [[9.1.1]](#911-ckms-sym-keys-create)  Create a new symmetric key

**`export`** [[9.1.2]](#912-ckms-sym-keys-export)  Export a key from the KMS

**`import`** [[9.1.3]](#913-ckms-sym-keys-import)  Import a private or public key in the KMS.

**`wrap`** [[9.1.4]](#914-ckms-sym-keys-wrap)  Locally wrap a key in KMIP JSON TTLV format.

**`unwrap`** [[9.1.5]](#915-ckms-sym-keys-unwrap)  Locally unwrap a key in KMIP JSON TTLV format.

**`revoke`** [[9.1.6]](#916-ckms-sym-keys-revoke)  Revoke a symmetric key

**`destroy`** [[9.1.7]](#917-ckms-sym-keys-destroy)  Destroy a symmetric key

---

## 9.1.1 ckms sym keys create

Create a new symmetric key

### Usage
`ckms sym keys create [options]`
### Arguments
`--number-of-bits [-l] <NUMBER_OF_BITS>` The length of the generated random key or salt in bits

`--bytes-b64 [-k] <WRAP_KEY_B64>` The symmetric key bytes or salt as a base 64 string

`--algorithm [-a] <ALGORITHM>` The algorithm

Possible values:  `"aes", "chacha20", "sha3", "shake"` [default: `"aes"`]

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 9.1.2 ckms sym keys export

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

Possible values:  `"json-ttlv", "sec1-pem", "sec1-der", "pkcs1-pem", "pkcs1-der", "pkcs8-pem", "pkcs8-der", "spki-pem", "spki-der", "raw"` [default: `"json-ttlv"`]

`--unwrap [-u] <UNWRAP>` Unwrap the key if it is wrapped before export

`--wrap-key-id [-w] <WRAP_KEY_ID>` The id of the key/certificate to use to wrap this key before export

`--allow-revoked [-i] <ALLOW_REVOKED>` Allow exporting revoked and destroyed keys.
The user must be the owner of the key.
Destroyed keys have their key material removed.



---

## 9.1.3 ckms sym keys import

Import a private or public key in the KMS.

### Usage
`ckms sym keys import [options] <KEY_FILE>
 [KEY_ID]
`
### Arguments
` <KEY_FILE>` The KMIP JSON TTLV key file

` <KEY_ID>` The unique id of the key; a unique id based on the key material is generated if not specified

`--key-format [-f] <KEY_FORMAT>` The format of the key

Possible values:  `"json-ttlv", "pem", "sec1", "pkcs1-priv", "pkcs1-pub", "pkcs8", "spki", "aes", "chacha20"` [default: `"json-ttlv"`]

`--public-key-id [-p] <PUBLIC_KEY_ID>` For a private key: the corresponding public key id if any

`--private-key-id [-k] <PRIVATE_KEY_ID>` For a public key: the corresponding private key id if any

`--certificate-id [-c] <CERTIFICATE_ID>` For a public or private key: the corresponding certificate id if any

`--unwrap [-u] <UNWRAP>` In the case of a JSON TTLV key, unwrap the key if it is wrapped before storing it

`--replace [-r] <REPLACE_EXISTING>` Replace an existing key under the same id

`--tag [-t] <TAG>` The tag to associate with the key. To specify multiple tags, use the option multiple times



---

## 9.1.4 ckms sym keys wrap

Locally wrap a key in KMIP JSON TTLV format.

### Usage
`ckms sym keys wrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to wrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--wrap-password [-p] <WRAP_PASSWORD>` A password to wrap the imported key

`--wrap-key-b64 [-k] <WRAP_KEY_B64>` A symmetric key as a base 64 string to wrap the imported key

`--wrap-key-id [-i] <WRAP_KEY_ID>` The id of a wrapping key in the KMS that will be exported and used to wrap the key

`--wrap-key-file [-f] <WRAP_KEY_FILE>` A wrapping key in a KMIP JSON TTLV file used to wrap the key



---

## 9.1.5 ckms sym keys unwrap

Locally unwrap a key in KMIP JSON TTLV format.

### Usage
`ckms sym keys unwrap [options] <KEY_FILE_IN>
 [KEY_FILE_OUT]
`
### Arguments
` <KEY_FILE_IN>` The KMIP JSON TTLV input key file to unwrap

` <KEY_FILE_OUT>` The KMIP JSON output file. When not specified the input file is overwritten

`--unwrap-password [-p] <UNWRAP_PASSWORD>` A password to unwrap the imported key

`--unwrap-key-b64 [-k] <UNWRAP_KEY_B64>` A symmetric key as a base 64 string to unwrap the imported key

`--unwrap-key-id [-i] <UNWRAP_KEY_ID>` The id of a unwrapping key in the KMS that will be exported and used to unwrap the key

`--unwrap-key-file [-f] <UNWRAP_KEY_FILE>` A unwrapping key in a KMIP JSON TTLV file used to unwrap the key



---

## 9.1.6 ckms sym keys revoke

Revoke a symmetric key

### Usage
`ckms sym keys revoke [options] <REVOCATION_REASON>
`
### Arguments
` <REVOCATION_REASON>` The reason for the revocation as a string

`--key-id [-k] <KEY_ID>` The key unique identifier of the key to revoke. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times



---

## 9.1.7 ckms sym keys destroy

Destroy a symmetric key

### Usage
`ckms sym keys destroy [options]`
### Arguments
`--key-id [-k] <KEY_ID>` The key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times




---

## 9.2 ckms sym encrypt

Encrypt a file using AES GCM

### Usage
`ckms sym encrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to encrypt

`--key-id [-k] <KEY_ID>` The symmetric key unique identifier. If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data. This data needs to be provided back for decryption



---

## 9.3 ckms sym decrypt

Decrypts a file using AES GCM

### Usage
`ckms sym decrypt [options] <FILE>
`
### Arguments
` <FILE>` The file to decrypt

`--key-id [-k] <KEY_ID>` The private key unique identifier If not specified, tags should be specified

`--tag [-t] <TAG>` Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

`--output-file [-o] <OUTPUT_FILE>` The encrypted output file path

`--authentication-data [-a] <AUTHENTICATION_DATA>` Optional authentication data that was supplied during encryption




---

## 10 ckms login

Login to the Identity Provider of the KMS server using the `OAuth2` authorization code flow.

### Usage
`ckms login`


---

## 11 ckms logout

Logout from the Identity Provider.

### Usage
`ckms logout`


---

## 12 ckms markdown

Generate the CLI documentation as markdown

### Usage
`ckms markdown [options] <MARKDOWN_FILE>
`
### Arguments
` <MARKDOWN_FILE>` The file to export the markdown to





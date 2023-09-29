# Certificates

Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data

```sh
ckms certificates <COMMAND>
```

## Create

Create a new X509 certificate. If absent, the Certificate Authority certificates will be also created.

If no option is specified, a fresh signed certificate will be created in the same time of the underlying keypair.

Tags can be later used to retrieve the key. Tags are optional.

**Arguments:**

```sh
ckms certificates create [SUBCOMMAND]
```

**Usage:**

```sh
ckms certificates create [OPTIONS] --ca_subject_common_names <CA_SUBJECT_COMMON_NAMES> --subject_common_name <SUBJECT_COMMON_NAME>
```

**Options:**

```sh
  -k, --certificate-id <CERTIFICATE_ID>
          The certificate unique identifier

  -c, --ca_subject_common_names <CA_SUBJECT_COMMON_NAMES>
          The full Certificate Authority chain Subject Common Names separated by slashes (for example: CA/SubCA). If chain certificates does not exist, the KMS server will create them

  -s, --subject_common_name <SUBJECT_COMMON_NAME>
          The subject CN of the desired certificate

  -t, --tag <TAG>
          The tag to associate to the certificate. To specify multiple tags, use the option multiple times

  -h, --help
          Print help (see a summary with '-h')
```

## Decrypt

Decrypt a file using the private key of a certificate.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.

**Usage:**

```sh
ckms certificates decrypt [OPTIONS] <FILE>
```

**Arguments:**

```sh
  <FILE>
          The file to decrypt
```

**Options:**

```sh
  -k, --key-id <PRIVATE_KEY_ID>
          The private key unique identifier related to certificate If not specified, tags should be specified

  -t, --tag <TAG>
          Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

  -o, --output-file <OUTPUT_FILE>
          The encrypted output file path

  -a, --authentication-data <AUTHENTICATION_DATA>
          Optional authentication data that was supplied during encryption

  -h, --help
          Print help (see a summary with '-h')
```

## Encrypt

Encrypt a file using the certificate public key.

Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.

**Usage:**

```sh
ckms certificates encrypt [OPTIONS] <FILE>
```

**Arguments:**

```sh
<FILE>
The file to encrypt
```

**Options:**

```sh
-k, --certificate-id <CERTIFICATE_ID>
The certificate unique identifier. If not specified, tags should be specified

-t, --tag <TAG>
Tag to use to retrieve the key when no key id is specified. To specify multiple tags, use the option multiple times

-o, --output-file <OUTPUT_FILE>
The encrypted output file path

-a, --authentication-data <AUTHENTICATION_DATA>
Optional authentication data. This data needs to be provided back for decryption

-h, --help
Print help (see a summary with '-h')
```

## Export

Export a certificate from the KMS

The certificate is exported either:

- in PEM format
- in PKCS12 format including private key and certificate file
- in TTLV JSON KMIP format

When using tags to retrieve the certificate, rather than the certificate id,
an error is returned if multiple certificates matching the tags are found.

**Usage:**

```sh
ckms certificates export [OPTIONS] --format <OUTPUT_FORMAT> <CERTIFICATE_FILE>
```

**Arguments:**

```sh
  <CERTIFICATE_FILE>
          The file to export the certificate to
```

**Options:**

```sh
  -k, --certificate-id <CERTIFICATE_ID>
          The certificate unique identifier stored in the KMS. If not specified, tags should be specified

  -t, --tag <TAG>
          Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

  -f, --format <OUTPUT_FORMAT>
          Export the certificate in the selected format

          [possible values: ttlv, pem, pkcs12]

  -p, --pkcs12_password <PKCS12_PASSWORD>
          Export the certificate in PKCS12 format and protect the private key using this password

  -i, --allow-revoked
          Allow exporting revoked and destroyed certificates. The user must be the owner of the certificate. Destroyed certificates have their certificate material removed

  -h, --help
          Print help (see a summary with '-h')
```

## Import

Import into the KMS database the following elements:
- a certificate (as PEM or TTLV format)
- a private key (as PEM or TTLV format)
- a certificate chain as a PEM-stack
- the Mozilla Common CA Database (CCADB). Automate the Mozilla database fetch.

**Usage:**

```sh
ckms certificates import [OPTIONS] --format <INPUT_FORMAT> [CERTIFICATE_FILE] [CERTIFICATE_ID]
```

**Arguments:**

```sh
  <CERTIFICATE_FILE>
          The KMIP JSON TTLV certificate file

  [CERTIFICATE_ID]
          The unique id of the certificate; a random UUID v4 is generated if not specified
```

**Options:**

```sh
  -f, --format <INPUT_FORMAT>  Import the certificate in the selected format [possible values: ttlv, pem, chain, ccadb]
  -u, --unwrap                 Unwrap the object if it is wrapped before storing it
  -r, --replace                Replace an existing certificate under the same id
  -t, --tag <TAG>              The tag to associate with the certificate. To specify multiple tags, use the option multiple times
  -h, --help                   Print help (see more with '--help')
```

## Revoke

When a certificate is revoked, it can only be exported by the owner of the certificate, using the --allow-revoked flag on the export function.

**Usage:**

```sh
ckms certificates revoke [OPTIONS] <REVOCATION_REASON>
```

**Arguments:**

```sh
  <REVOCATION_REASON>
          The reason for the revocation as a string
```

**Options:**

```sh
  -k, --certificate-id <CERTIFICATE_ID>
          The certificate unique identifier of the certificate to revoke. If not specified, tags should be specified

  -t, --tag <TAG>
          Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

  -h, --help
          Print help (see a summary with '-h')
```

## Destroy

Destroy a certificate.

The certificate must have been revoked first.

When a certificate is destroyed, it can only be exported by the owner of the certificate

**Usage:**

```sh
ckms certificates destroy [OPTIONS]
```

**Options:**

```sh
-k, --certificate-id <CERTIFICATE_ID>
The certificate unique identifier. If not specified, tags should be specified

-t, --tag <TAG>
Tag to use to retrieve the certificate when no certificate id is specified. To specify multiple tags, use the option multiple times

-h, --help
Print help (see a summary with '-h')
```

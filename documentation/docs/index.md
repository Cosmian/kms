# Cosmian KMS

The Cosmian KMS is a high-performance, [**open-source**](https://github.com/Cosmian/kms), server application
written in [**Rust**](https://www.rust-lang.org/) that provides a [**KMIP 2.1**](#kmip-21-api)
REST API.

The Cosmian KMS is both a Key Management System and a Public Key Infrastructure.
As a KMS, it is designed to manage the lifecycle of keys and provide scalable cryptographic
services such as on-the-fly key generation, encryption, and decryption operations.

The KMS supports all the standard NIST cryptographic algorithms as well as advanced post-quantum
cryptography algorithms such as [Covercrypt](https://github.com/Cosmian/cover_crypt).

As a PKI it can manage root and intermediate certificates, sign and verify certificates, use
their public keys to encrypt and decrypt data.
Certificates can be exported under various formats including PKCS#12 modern and legacy flavor,
to be used in various applications, such as in S/MIME encrypted emails.

!!! info "Quick start"

    To quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data
    inside the container, simply run the following command:

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.19.3
    ```

    Pre-built binaries, for both the server and CLI (called `ckms`) are available for multiple
    operating systems on [Cosmian packages](https://package.cosmian.com/kms/4.19.3/).

    Using [`ckms`](./cli/cli.md), you can easily manage the server:

    1) Create a 256-bit symmetric key

    ```sh
    ckms sym keys create --number-of-bits 256 --algorithm aes --tag my-file-key
    ...
    The symmetric key was successfully generated.
          Unique identifier: 87e9e2a8-4538-4701-aa8c-e3af94e44a9e
    ```

    2) Encrypt the `image.png` file with AES GCM using the key

    ```sh
    ckms sym encrypt --tag my-file-key --output-file image.enc image.png
    ...
    The encrypted file is available at "image.enc"
    ```

    3) Decrypt the `image.enc` file using the key
    ```sh
    ckms sym decrypt --tag my-file-key --output-file image2.png image.enc
    ...
    The decrypted file is available at "image2.png"
    ```

## Table of contents

- [Cosmian KMS](#cosmian-kms)
  - [Table of contents](#table-of-contents)
  - [Public Source Code](#public-source-code)
  - [KMIP 2.1 API](#kmip-21-api)
  - [Supports Google Workspace Client Side Encryption](#supports-google-workspace-client-side-encryption)
  - [Supports Microsoft Double Key Encryption](#supports-microsoft-double-key-encryption)
  - [FIPS 140-3 certifications](#fips-140-3-certifications)
  - [Veracrypt and LUKS disk encryption support](#veracrypt-and-luks-disk-encryption-support)
  - [State-of-the-art authentication](#state-of-the-art-authentication)
  - [High-availability and databases](#high-availability-and-databases)
  - [Designed to securely run in the Public Cloud or other Zero-Trust environments](#designed-to-securely-run-in-the-public-cloud-or-other-zero-trust-environments)
  - [Support for object tagging](#support-for-object-tagging)
  - [Command line interface client](#command-line-interface-client)
  - [Easy to deploy: Docker image and pre-built binaries](#easy-to-deploy-docker-image-and-pre-built-binaries)
  - [Integrated with OpenTelemetry](#integrated-with-opentelemetry)
  - [Integrated with Cloudproof libraries](#integrated-with-cloudproof-libraries)
  - [Comprehensive inline help](#comprehensive-inline-help)
  - [TOML configuration file](#toml-configuration-file)

## Public Source Code

The server's source code is fully available on [GitHub](https://github.com/Cosmian/kms) under a
Business Source License so that it can be audited and improved by anyone.

## KMIP 2.1 API

The Cosmian KMS server exposes a **KMIP 2.1** REST API on the `/kmip_2_1` endpoint that follows
the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415)
of
the
OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

Check the [KMIP 2.1](./kmip_2_1/index.md) page for details.

## Supports Google Workspace Client Side Encryption

The KMS server can be used as a Key Management System for the Google Workspace Client Side
Encryption feature.
Please check the [Google Workspace Client Side Encryption](./google_cse/google_cse.md) page for
details.

## Supports Microsoft Double Key Encryption

The KMS server can be used as a Key Management System for the Microsoft Double Key Encryption
feature.
Please check the [Microsoft Double Key Encryption](./ms_dke/ms_dke.md) page for details.

## FIPS 140-3 certifications

When run in FIPS mode, the Cosmian KMS uses only cryptographic primitives that are compliant with
the standards of the National Institute of Standards and Technology (NIST) and uses
implementations of an NIST FIPS 140–3 compliant cryptographic module.
See [FIPS mode](./fips.md)

## Veracrypt and LUKS disk encryption support

The KMS server can provide keys on the fly to mount LUKS and Veracrypt encrypted volumes using
its PKCS#11 module. With LUKS, the decryption key never leaves the KMS server.
Check the [Veracrypt](./pkcs11/veracrypt.md) and [LUKS](./pkcs11/luks.md) pages for details.

## State-of-the-art authentication

State-of-the-art authentication facilitates integration with existing IT infrastructure and allows
single sign-on
scenarios.

Server access is secured using native TLS combined with [Open ID-compliant](https://openid.net/) JWT
access tokens or
TLS client certificates.

Check the enabling [TLS documentation](./tls.md) as well as
the [authentication documentation](./authentication.md) for
details.

## High-availability and databases

The Cosmian KMS may be deployed either in [single-server mode](./single_server_mode.md) or
for [high availability](./high_availability_mode.md)
using simple horizontal scaling of the servers.

For additional security, the server supports concurrent user encrypted databases in single-server
mode
and an application-level encrypted database on top of Redis in a high-availability scenario.

## Designed to securely run in the Public Cloud or other Zero-Trust environments

When running on top of Cosmian VMs with a fully application-level encrypted
Redis database, the Cosmian KMS can securely run in zero-trust environments, such as the public
cloud.
See our cloud-ready confidential KMS on the
[Azure, GCP, and AWS marketplaces](https://cosmian.com/marketplaces/)

Read our dedicated page for [running the KMS in a zero-trust environment](./zero_trust.md).

## Support for object tagging

The KMS server supports user tagging of objects to facilitate their management.
Specify as many user tags as needed when creating and importing objects.

In addition, the KMS server will automatically add a system tag based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate

Use the tags to export objects, locate them, or request data encryption and decryption.

## Command line interface client

The KMS has an easy-to-use command line interface client built for many operating systems.

The **`ckms`** CLI can manage the server, and the keys and perform operations such as encryption or
decryption.

Check the [ckms documentation](./cli/cli.md) for details.

## Easy to deploy: Docker image and pre-built binaries

The KMS server is available as a Docker image on
the [Cosmian public Docker repository](https://github.com/Cosmian/kms/pkgs/container/kms).

Raw binaries for multiple operating systems are also available on
the [Cosmian public packages repository](https://package.cosmian.com/kms/4.19.3/)

## Integrated with OpenTelemetry

The KMS server can be configured to send telemetry traces to
an [OpenTelemetry](https://opentelemetry.io/) collector.

## Integrated with Cloudproof libraries

To build the next generation of privacy-by-design applications with end-to-end encryption,
the KMS server is integrated with the
[**Cloudproof**](https://docs.cosmian.com/cloudproof_encryption/how_it_works/)
libraries to deliver keys and secrets to the client-side cryptographic stacks or perform
delegated encryption and decryption.

The libraries are available in many languages, including JavaScript, Java, Dart, and Python.
Check
their [documentation](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/)
for details.

## Comprehensive inline help

Just like the [`ckms` Command Line Interface](./cli/cli.md), the KMS server has a built-in help
system that can be accessed using the `--help` command line option.

```sh
docker run --rm ghcr.io/cosmian/kms:4.19.3 --help
```

The options are enabled on the docker command line or using the environment variables listed in the
options help.

```text
Cosmian Key Management Service

Usage: cosmian_kms_server [OPTIONS]

Options:
      --database-type <DATABASE_TYPE>
          The database type of the KMS server
          - postgresql: PostgreSQL. The database url must be provided
          - mysql: MySql or MariaDB. The database url must be provided
          - sqlite: SQLite. The data will be stored at the sqlite_path directory
          - sqlite-enc: SQLite encrypted at rest. the data will be stored at the sqlite_path directory.
            A key must be supplied on every call
          - redis-findex: a Redis database with encrypted data and encrypted indexes thanks to Findex.
            The Redis url must be provided, as well as the redis-master-password and the redis-findex-label

          [env: KMS_DATABASE_TYPE=]
          [possible values: postgresql, mysql, sqlite, sqlite-enc, redis-findex]

      --database-url <DATABASE_URL>
          The url of the database for postgresql, mysql or redis-findex

          [env: KMS_DATABASE_URL=]

      --sqlite-path <SQLITE_PATH>
          The directory path of the sqlite or sqlite-enc

          [env: KMS_SQLITE_PATH=]
          [default: ./sqlite-data]

      --redis-master-password <REDIS_MASTER_PASSWORD>
          redis-findex: a master password used to encrypt the Redis data and indexes

          [env: KMS_REDIS_MASTER_PASSWORD=]

      --redis-findex-label <REDIS_FINDEX_LABEL>
          redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key

          [env: KMS_REDIS_FINDEX_LABEL=]

      --clear-database
          Clear the database on start.
          WARNING: This will delete ALL the data in the database

          [env: KMS_CLEAR_DATABASE=]

      --port <PORT>
          The KMS server port

          [env: KMS_PORT=]
          [default: 9998]

      --hostname <HOSTNAME>
          The KMS server hostname

          [env: KMS_HOSTNAME=]
          [default: 0.0.0.0]

      --https-p12-file <HTTPS_P12_FILE>
          The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode

          [env: KMS_HTTPS_P12_FILE=]

      --https-p12-password <HTTPS_P12_PASSWORD>
          The password to open the PKCS#12 Certificates and Key file

          [env: KMS_HTTPS_P12_PASSWORD=]

      --authority-cert-file <AUTHORITY_CERT_FILE>
          The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication. If provided, this will require clients to present a certificate signed by this authority for authentication. The server must run in TLS mode for this to be used

          [env: KMS_AUTHORITY_CERT_FILE=]

      --jwt-issuer-uri <JWT_ISSUER_URI>...
          The issuer URI of the JWT token

          To handle multiple identity managers, add different parameters under each argument (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in the same order :

          --jwt_issuer_uri <JWT_ISSUER_URI_1> <JWT_ISSUER_URI_2> --jwks_uri <JWKS_URI_1> <JWKS_URI_2> --jwt_audience <JWT_AUDIENCE_1> <JWT_AUDIENCE_2>

          For Auth0, this is the delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`

          For Google, this would be `https://accounts.google.com`

          [env: KMS_JWT_ISSUER_URI=]

      --jwks-uri <JWKS_URI>...
          The JWKS (Json Web Key Set) URI of the JWT token

          To handle multiple identity managers, add different parameters under each argument (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in the same order

          For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`

          For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`

          Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set

          [env: KMS_JWKS_URI=]

      --jwt-audience <JWT_AUDIENCE>...
          The audience of the JWT token

          Optional: the server will validate the JWT `aud` claim against this value if set

          [env: KMS_JST_AUDIENCE=]

      --root-data-path <ROOT_DATA_PATH>
          The root folder where the KMS will store its data A relative path is taken relative to the user HOME directory

          [env: KMS_ROOT_DATA_PATH=]
          [default: ./cosmian-kms]

      --tmp-path <TMP_PATH>
          The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution)

          [env: KMS_TMP_PATH=]
          [default: /tmp]

      --default-username <DEFAULT_USERNAME>
          The default username to use when no authentication method is provided

          [env: KMS_DEFAULT_USERNAME=]
          [default: admin]

      --force-default-username
          When an authentication method is provided, perform the authentication but always use the default username instead of the one provided by the authentication method

          [env: KMS_FORCE_DEFAULT_USERNAME=]

      --google-cse-kacls-url <GOOGLE_CSE_KACLS_URL>
          This setting enables the Google Workspace Client Side Encryption feature of this KMS server.

          It should contain the external URL of this server as configured in Google Workspace client side encryption settings For instance, if this server is running on domain `cse.my_domain.com`, the URL should be something like <https://cse.my_domain.com/google_cse>

          [env: KMS_GOOGLE_CSE_KACLS_URL=]

      --ms-dke-service-url <MS_DKE_SERVICE_URL>
          This setting enables the Microsoft Double Key Encryption service feature of this server.

          It should contain the external URL of this server as configured in Azure App Registrations
          as the DKE Service (https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store)

          The URL should be something like <https://cse.my_domain.com/ms_dke>

          [env: KMS_MS_DKE_SERVICE_URL=]

      --otlp <OTLP>
          The OTLP collector URL
          (for instance, http://localhost:4317)

          [env: KMS_OTLP_URL=]

      --quiet
          Do not log to stdout

          [env: KMS_LOG_QUIET=]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

```

## TOML configuration file

If a file is found at `/etc/cosmian_kms/server.toml`, the KMS server will use it to configure
itself.
The location of the file can be changed using the `COSMIAN_KMS_CONF` environment variable.

The file should be a TOML file with the following structure:

```toml
default_username = "[default username]"
force_default_username = false
google_cse_kacls_url = "[google cse kacls url]"
ms_dke_service_url = "[ms dke service url]"

[db]
database_type = "[redis-findex, postgresql,...]"
database_url = "[redis urls]"
sqlite_path = "[sqlite path]"
redis_master_password = "[redis master password]"
redis_findex_label = "[redis findex label]"
clear_database = false

[http]
port = 443
hostname = "[hostname]"
https_p12_file = "[https p12 file]"
https_p12_password = "[https p12 password]"
authority_cert_file = "[authority cert file]"

[auth]
jwt_issuer_uri = ["[jwt issuer uri]"]
jwks_uri = ["[jwks uri]"]
jwt_audience = ["[jwt audience]"]

[workspace]
root_data_path = "[root data path]"
tmp_path = "[tmp path]"

[telemetry]
otlp = "[url of the OTLP collector]"
quiet = false
```

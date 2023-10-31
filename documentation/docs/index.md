The Cosmian Key Management System (KMS) is a high-performance, [**open-source**](#open-source), server application written in [**Rust**](https://www.rust-lang.org/) that provides a [**KMIP**](#kmip-21-api) REST API to store and manage keys used in many standard (AES, ECIES,...) cryptographic stacks as well as Cosmian cryptographic stacks ([**Covercrypt**](https://github.com/Cosmian/cover_crypt), [**Findex**](https://github.com/Cosmian/findex)). The KMS can also be used to perform encryption and decryption operations.

The Cosmian KMS is designed to [operate in **zero-trust** environments](./zero_trust.md), such as the public cloud, using confidential VMs and a fully application-level encrypted database.

!!! info "Quick start"
    To quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data inside the container, simply run

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.8.2
    ```

    Check the Cosmian KMS server version

    ```sh
    curl http://localhost:9998/version
    ```

#### Open source

The server's code is open-sourced on [Github](https://github.com/Cosmian/kms) so that it can be audited and improved by anyone.

#### KMIP 2.1 API

The Cosmian KMS server exposes a **KMIP 2.1** REST API on the `/kmip_2_1` endpoint that follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

Check the [KMIP 2.1](./kmip_2_1/index.md) page for details.

#### State-of-the-art authentication

State-of-the-art authentication facilitates integration with existing IT infrastructure and allows single sign-on scenarios.

Server access is secured using native TLS combined with [Open ID-compliant](https://openid.net/) JWT access tokens or TLS client certificates.

Check the enabling [TLS documentation](./tls.md) as well as the [authentication documentation](./authentication.md) for details.

#### High-availability and databases

The Cosmian KMS may be deployed either in [single-server mode](./single_server_mode.md) or for [high availability](./high_availability_mode.md) using simple horizontal scaling of the servers.

For additional security, the server supports concurrent user encrypted databases in single-server mode and an application-level encrypted database on top of Redis in a high-availability scenario.

#### Designed for the Cloud and Zero-Trust environments

Thanks to its "bootstrap" design, the use of confidential VMs, and a fully application-level encrypted database on top of Redis, the Cosmian KMS is able to securely operate in zero-trust environments, such as the public cloud.

See the dedicated page for [running the KMS in a zero-trust environment](./zero_trust.md).

#### Support for object tagging

The KMS server supports user tagging of objects to facilitate their management.
Specify as many user tags as needed when creating and importing objects.

In addition, the KMS server will automatically add a system tag based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key
- `_cert`: for a X509 certificate

In addition for the X509 certificate, KMIP Certificate object not having a `key block` with `Attributes`, the following tags are also added:

- `_cert_uid=<certificate_uid>` added on private key and public key to establish the link with the certificate
- `_cert_spki=<hash>` added on X509 certificates where the Subject Public Key Identifier is the hash of the public key
- `_cert_ca=<Subject Common Name>` on CA `Certificate` object

Use the tags to export objects, locate them, or request data encryption and decryption.

#### Command line interface client

The KMS has an easy-to-use command line interface client built for many operating systems.

 The **`ckms`** CLI can manage the server, and the keys and perform operations such as encryption or decryption.

 Check the [ckms documentation](./cli/cli.md) for details.

#### Easy to deploy: Docker image and pre-built binaries

The KMS server is available as a Docker image on the [Cosmian public Docker repository](https://github.com/Cosmian/kms/pkgs/container/kms).

Raw binaries for multiple operating systems are also available on the [Cosmian public packages repository](https://package.cosmian.com/kms/4.8.2/)

#### Integrated with Cloudproof libraries

To build the next generation of privacy-by-design applications with end-to-end encryption, the KMS server is integrated with the [**Cloudproof**](https://docs.cosmian.com/cloudproof_encryption/how_it_works/) libraries to deliver keys and secrets to the client-side cryptographic stacks or perform delegated encryption and decryption.

The libraries are available in many languages, including Javascript, Java, Dart, and Python. Check their [documentation](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/) for details.

#### Comprehensive inline help

Just like the [`ckms` Command Line Interface](./cli/cli.md), the KMS server has a built-in help system that can be accessed using the `--help` command line option.

```sh
docker run --rm ghcr.io/cosmian/kms:4.8.2 --help
```

The options are enabled on the docker command line or using the environment variables listed in the options help.

##### Options help

```sh
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

          The database configuration can be securely provided via the bootstrap server. Check the documentation.

          [env: KMS_DATABASE_TYPE=]
          [possible values: postgresql, mysql, sqlite, sqlite-enc, redis-findex]

      --database-url <DATABASE_URL>
          The url of the database for postgresql, mysql or findex-redis

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
          The KMS server (and bootstrap server) hostname

          [env: KMS_HOSTNAME=]
          [default: 0.0.0.0]

      --https-p12-file <HTTPS_P12_FILE>
          The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.

          The PKCS#12 can be securely provided via the bootstrap server. Check the documentation.

          [env: KMS_HTTPS_P12_FILE=]

      --https-p12-password <HTTPS_P12_PASSWORD>
          The password to open the PKCS#12 Certificates and Key file

          The PKCS#12 password can be securely provided via the bootstrap server. Check the documentation.

          [env: KMS_HTTPS_P12_PASSWORD=]
          [default: ]

      --authority-cert-file <AUTHORITY_CERT_FILE>
          The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication. If provided, this will require clients to present a certificate signed by this authority for authentication. The server must run in TLS mode for this to be used

          [env: KMS_AUTHORITY_CERT_FILE=]

      --jwt-issuer-uri <JWT_ISSUER_URI>
          The issuer URI of the JWT token

          For Auth0, this is the delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`

          For Google, this would be `https://accounts.google.com`

          [env: KMS_JWT_ISSUER_URI=]

      --jwks-uri <JWKS_URI>
          The JWKS (Json Web Key Set) URI of the JWT token

          For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`

          For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`

          Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` is not set

          [env: KMS_JWKS_URI=]

      --jwt-audience <JWT_AUDIENCE>
          The audience of the JWT token

          Optional: the server will validate the JWT `aud` claim against this value if set

          [env: KMS_JST_AUDIENCE=]

      --use-bootstrap-server
          Whether configuration should be finalized using a bootstrap server

          [env: KMS_USE_BOOTSTRAP_SERVER=]

      --bootstrap-server-subject <BOOTSTRAP_SERVER_SUBJECT>
          Subject as an RFC 4514 string for the RA-TLS certificate in the bootstrap server

          [env: KMS_BOOTSTRAP_SERVER_SUBJECT=]
          [default: "CN=cosmian.kms,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France"]

      --bootstrap-server-expiration-days <BOOTSTRAP_SERVER_EXPIRATION_DAYS>
          Number of days before the certificate expires

          [env: KMS_BOOTSTRAP_SERVER_EXPIRATION_DAYS=]
          [default: 365]

      --bootstrap-server-port <BOOTSTRAP_SERVER_PORT>
          The bootstrap server may be started on a specific port, The hostname will be that configured in --hostname

          [env: KMS_BOOTSTRAP_SERVER_PORT=]
          [default: 9998]

      --ensure-ra-tls
          Ensure RA-TLS is available and used. The server will not start if this is not the case

          [env: KMS_ENSURE_RA_TLS=]

      --root-data-path <ROOT_DATA_PATH>
          The root folder where the KMS will store its data A relative path is taken relative to the user HOME directory

          [env: KMS_ROOT_DATA_PATH=]
          [default: ./cosmian-kms]

      --tmp-path <TMP_PATH>
          The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution)

          [env: KMS_TMP_PATH=]
          [default: /tmp]

      --use-certbot
          Enable TLS and use Let's Encrypt certbot to get a certificate

          [env: KMS_USE_CERTBOT=]

      --certbot-use-tee-key
          Use TEE key generation to generate the certificate certificate (only available on tee)

          [env: KMS_CERTBOT_USE_TEE_KEY=]

      --certbot-hostname <CERTBOT_HOSTNAME>
          The hostname of the KMS HTTPS server that will be used as the Common Name in the Let's Encrypt certificate

          [env: KMS_CERTBOT_HOSTNAME=]
          [default: ]

      --certbot-email <CERTBOT_EMAIL>
          The email used during the Let's Encrypt certbot certification process

          [env: KMS_CERTBOT_EMAIL=]
          [default: ]

      --certbot-ssl-path <CERTBOT_SSL_PATH>
          The folder where the KMS will store the SSL material created by certbot

          A relative path is taken relative to the root_data_path

          [env: KMS_CERTBOT_SSL_PATH=]
          [default: ./certbot-ssl]

      --default-username <DEFAULT_USERNAME>
          The default username to use when no authentication method is provided

          [env: KMS_DEFAULT_USERNAME=]
          [default: admin]

      --force-default-username
          When an authentication method is provided, perform the authentication but always use the default username instead of the one provided by the authentication method

          [env: KMS_FORCE_DEFAULT_USERNAME=]

      --jwk-private-key <JWK_PRIVATE_KEY>
          Enable the use of encryption by providing a JWK private key as JSON

          [env: JWK_PRIVATE_KEY=]

      --tee-dir-path <TEE_DIR_PATH>
          The directory where the public key or other required files are located This path should not be encrypted by the enclave and should be directly readable from it

          A relative path is taken relative to the root_data_path

          [env: KMS_TEE_DIR_PATH=]
          [default: ./tee]

      --sgx-public-signer-key-filename <SGX_PUBLIC_SIGNER_KEY_FILENAME>
          The filename of the public key for SGX

          [env: KMS_SGX_PUBLIC_SIGNER_KEY_FILENAME=]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

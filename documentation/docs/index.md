The Cosmian Key Management System (KMS) is a high-performance server application written in [**Rust**](https://www.rust-lang.org/) that provides a KMIP REST API to store and manage keys and secrets used with Cosmian cryptographic stacks.

#### Open source

The server's code is open-sourced on [Github](https://github.com/Cosmian/kms) so that it can be audited and improved by the community.

#### KMIP 2.1 API

The Cosmian KMS server exposes a **KMIP 2.1** REST API on the `/kmip_2_1` endpoint that follows the [JSON profile](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html#_Toc32324415) of the OASIS-normalized [KMIP 2.1 specifications](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/cs01/kmip-spec-v2.1-cs01.html).

Check the [KMIP 2.1](./kmip_2_1/index.md) page for details.

#### State-of-the-art authentication

State-of-the-art authentication facilitates integration with existing IT infrastructure and allows single sign-on scenarios.

Server access is secured using native TLS combined with Open ID-compliant JWT access tokens or TLS client certificates.

Check the enabling [TLS documentation](./tls.md) as well as the [authentication documentation](./authentication.md) for details.

#### Packaged as a docker image and raw binary

The KMS server is available as a Docker image on the [Cosmian public Docker repository](https://github.com/Cosmian/kms/pkgs/container/kms).

Non-dockerized raw binaries are also available on the [Cosmian public packages repository](https://package.cosmian.com/kms/4.5.0/)

!!! info "Quick start"
    To quick-start a Cosmian KMS server on `http://localhost:9998` that stores its data inside the container, simply run

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:4.5.0
    ```

    Check the Cosmian KMS server version

    ```sh
    curl http://localhost:9998/version
    ```

#### High-availability and databases

The KMS server deploys either in [single-server mode](./single_server_mode.md) or in [replicated mode](./replicated_mode.md).

The server supports concurrent client-secret encrypted databases in single-server mode for additional security.


#### Support for Public Cloud and Zero-Trust environments

Using Redis-with-Findex as a backend (see [here](./replicated_mode.md)), the KMS server data can be encrypted by the KMS at the application level. The use of Findex encrypted indexes provides blazing search performance without compromising security.  All that is required is to deploy the KMS in a confidential VM.


#### Support for object tagging

The KMS server supports user tagging of objects to facilitate their management.
Specify as many user tags as needed when creating and importing objects.

In addition, the user server will automatically add a system tag based on the object type:

 - `_sk`: for a private key
 - `_pk`: for a public key
 - `_kk`: for a symmetric key
 - `_uk`: for a Covercrypt user decryption key

Use the tags to export objects, locate them, or request data encryption and decryption.


#### Command line interface client

The KMS has an easy-to-use command line interface client for many operating systems.

 The **`ckms`** CLI can manage the server and the keys and perform encryption or decryption.

 Check its [documentation](./cli/cli.md) for details.

#### Integrated with Cloudproof libraries

To build the next generation of privacy-by-design applications with end-to-end encryption, the KMS server is integrated with the [**Cloudproof**](https://docs.cosmian.com/cloudproof_encryption/use_cases_benefits/) libraries to deliver keys and secrets to the client-side cryptographic stacks or perform delegated encryption and decryption.

The libraries are available in many languages, including Javascript, Java, Dart, and Python. Check their [documentation](https://docs.cosmian.com/cloudproof_encryption/application_level_encryption/) for details.

#### Inline help

Like the `ckms` CLI, the KMS server has a built-in help system that can be accessed using the `--help` command line option.

```sh
docker run --rm ghcr.io/cosmian/kms:4.5.0 --help
```

The options are enabled on the docker command line or using the environment variables listed in the options help.

##### Options help

```
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

--database-type <DATABASE_TYPE>
    The type of database used as backend
    - postgresql: PostgreSQL. The database url must be provided
    - mysql: MySql or MariaDB. The database url must be provided
    - sqlite: SQLite. The data will be stored at the sqlite_path directory
    - sqlite-enc: SQLite encrypted at rest. the data will be stored at the sqlite_path directory.
    A key must be supplied on every call
    - redis-findex: and encrypted redis database with an encrypted index using Findex.
    The database url must be provided, as well as the redis-master-password and the redis-findex-label
    _
    
    [env: KMS_DATABASE_TYPE=]
    [default: sqlite]
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

--enclave-dir-path <ENCLAVE_DIR_PATH>
    The directory where the manifest and public key files are located This path should not be encrypted by the enclave and should be directly readable from it
    
    A relative path is taken relative to the root_data_path
    
    [env: KMS_ENCLAVE_DIR_PATH=]
    [default: ./enclave]

--manifest-filename <MANIFEST_FILENAME>
    The filename of the sgx manifest
    
    [env: KMS_ENCLAVE_MANIFEST_FILENAME=]
    [default: kms.manifest.sgx]

--public-key-filename <PUBLIC_KEY_FILENAME>
    The filename of the public key
    
    [env: KMS_ENCLAVE_PUBLIC_KEY_FILENAME=]
    [default: mr-signer-key.pub]

--use-certbot
    Enable TLS and use Let's Encrypt certbot to get a certificate
    
    [env: KMS_USE_CERTBOT=]

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

--port <PORT>
    The server http port
    
    [env: KMS_PORT=]
    [default: 9998]

--hostname <HOSTNAME>
    The server http hostname
    
    [env: KMS_HOSTNAME=]
    [default: 0.0.0.0]

--https-p12-file <HTTPS_P12_FILE>
    The server optional PKCS#12 Certificate file. If provided, this will start the server in HTTPS mode
    
    [env: KMS_HTTPS_P12_FILE=]

--https-p12-password <HTTPS_P12_PASSWORD>
    The password to open the PKCS#12 Certificate file
    
    [env: KMS_HTTPS_P12_PASSWORD=]
    [default: ]

--authority-cert-file <AUTHORITY_CERT_FILE>
    The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication. If provided, this will require clients to present a certificate signed by this authority for authentication. The server must run in TLS mode for this to be used
    
    [env: KMS_AUTHORITY_CERT_FILE=]

--jwk-private-key <JWK_PRIVATE_KEY>
    Enable the use of encryption by providing a JWK private key as JSON
    
    [env: JWK_PRIVATE_KEY=]

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

-h, --help
    Print help (see a summary with '-h')

-V, --version
    Print version
```

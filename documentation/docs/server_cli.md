# Comprehensive inline help

Just like the [Cosmian CLI](../cosmian_cli/index.md), the KMS server has a built-in help
system that can be accessed using the `--help` command line option.

```sh
docker run --rm ghcr.io/cosmian/kms:latest --help
```

The options are enabled on the docker command line or using the environment variables listed in the
options help.

```text
Cosmian Key Management Service

Usage: cosmian_kms_server [OPTIONS]

Options:
      --database-type <DATABASE_TYPE>
          The database type of the KMS server
          - postgresql: `PostgreSQL`. The database url must be provided
          - mysql: `MySql` or `MariaDB`. The database url must be provided
          - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
          - sqlite-enc: `SQLite` encrypted at rest. the data will be stored at the `sqlite_path` directory.
            A key must be supplied on every call
          - redis-findex: a Redis database with encrypted data and encrypted indexes thanks to Findex.
            The Redis url must be provided, as well as the redis-master-password and the redis-findex-label [env: KMS_DATABASE_TYPE=] [possible values: postgresql, mysql, sqlite, sqlite-enc, redis-findex]
      --database-url <DATABASE_URL>
          The url of the database for postgresql, mysql or findex-redis [env: KMS_DATABASE_URL=]
      --sqlite-path <SQLITE_PATH>
          The directory path of the sqlite or sqlite-enc [env: KMS_SQLITE_PATH=] [default: ./sqlite-data]
      --redis-master-password <REDIS_MASTER_PASSWORD>
          redis-findex: a master password used to encrypt the Redis data and indexes [env: KMS_REDIS_MASTER_PASSWORD=]
      --redis-findex-label <REDIS_FINDEX_LABEL>
          redis-findex: a public arbitrary label that can be changed to rotate the Findex ciphertexts without changing the key [env: KMS_REDIS_FINDEX_LABEL=]
      --clear-database
          Clear the database on start.
          WARNING: This will delete ALL the data in the database [env: KMS_CLEAR_DATABASE=]
      --port <PORT>
          The KMS server port [env: KMS_PORT=] [default: 9998]
      --hostname <HOSTNAME>
          The KMS server hostname [env: KMS_HOSTNAME=] [default: 0.0.0.0]
      --https-p12-file <HTTPS_P12_FILE>
          The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode [env: KMS_HTTPS_P12_FILE=]
      --https-p12-password <HTTPS_P12_PASSWORD>
          The password to open the PKCS#12 Certificates and Key file [env: KMS_HTTPS_P12_PASSWORD=]
      --authority-cert-file <AUTHORITY_CERT_FILE>
          The server optional authority X509 certificate in PEM format used to validate the client certificate presented for authentication. If provided, this will require clients to present a certificate signed by this authority for authentication. The server must run in TLS mode for this to be used [env: KMS_AUTHORITY_CERT_FILE=]
      --api-token-id <API_TOKEN_ID>
          The API token to use for authentication [env: KMS_API_TOKEN=]
      --jwt-issuer-uri <JWT_ISSUER_URI>...
          The issuer URI of the JWT token [env: KMS_JWT_ISSUER_URI=]
      --jwks-uri <JWKS_URI>...
          The JWKS (Json Web Key Set) URI of the JWT token [env: KMS_JWKS_URI=]
      --jwt-audience <JWT_AUDIENCE>...
          The audience of the JWT token [env: KMS_JST_AUDIENCE=]
      --root-data-path <ROOT_DATA_PATH>
          The root folder where the KMS will store its data A relative path is taken relative to the user HOME directory [env: KMS_ROOT_DATA_PATH=] [default: ./cosmian-kms]
      --tmp-path <TMP_PATH>
          The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution) [env: KMS_TMP_PATH=] [default: /tmp]
      --default-username <DEFAULT_USERNAME>
          The default username to use when no authentication method is provided [env: KMS_DEFAULT_USERNAME=] [default: admin]
      --force-default-username
          When an authentication method is provided, perform the authentication but always use the default username instead of the one provided by the authentication method [env: KMS_FORCE_DEFAULT_USERNAME=]
      --google-cse-kacls-url <GOOGLE_CSE_KACLS_URL>
          This setting enables the Google Workspace Client Side Encryption feature of this KMS server [env: KMS_GOOGLE_CSE_KACLS_URL=]
      --ms-dke-service-url <MS_DKE_SERVICE_URL>
          This setting enables the Microsoft Double Key Encryption service feature of this server. [env: KMS_MS_DKE_SERVICE_URL=]
      --otlp <OTLP>
          The OTLP collector URL
          (for instance, <http://localhost:4317>) [env: KMS_OTLP_URL=]
      --quiet
          Do not log to stdout [env: KMS_LOG_QUIET=]
      --info
          Print the server configuration information and exit
  -h, --help
          Print help (see more with '--help')
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
info = false
hsm_model = "proteccio"
hsm_admin = "[hsm admin username]" #for Create operation on HSM
hsm_slot = [number_of_slot1, number_of_slot2, ...]
hsm_password = [password_of_slot1, password_of_slot2, ...]


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

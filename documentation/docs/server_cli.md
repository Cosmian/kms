When no [configuration file](./server_configuration_file.md) is provided, the KMS server can be
configured using command line options.

The list of arguments can be printed using the `--help` command line option.

```sh
-> docker run --rm ghcr.io/cosmian/kms:latest --help

Cosmian Key Management Service

Usage: cosmian_kms [OPTIONS] [KEY_ENCRYPTION_KEY]

Arguments:
  [KEY_ENCRYPTION_KEY]
          Force all keys imported or created in the KMS, which are not protected by a key encryption key, to be wrapped by the specified key encryption key (KEK)

Options:
      --database-type <DATABASE_TYPE>
          The main database of the KMS server that holds default cryptographic objects and permissions.
          - postgresql: `PostgreSQL`. The database URL must be provided
          - mysql: `MySql` or `MariaDB`. The database URL must be provided
          - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
            A key must be supplied on every call
          - redis-findex: a Redis database with encrypted data and indexes thanks to Findex.
            The Redis URL must be provided, as well as the redis-master-password and the redis-findex-label
          
          [env: KMS_DATABASE_TYPE=]
          [possible values: postgresql, mysql, sqlite, redis-findex]

      --database-url <DATABASE_URL>
          The URL of the database for `Postgres`, `MySQL`, or `Findex-Redis`
          
          [env: KMS_DATABASE_URL=]

      --sqlite-path <SQLITE_PATH>
          The directory path of the `SQLite`
          
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

      --unwrapped-cache-max-age <UNWRAPPED_CACHE_MAX_AGE>
          When a wrapped object is fetched from the database,
          it is unwrapped and stored in the unwrapped cache.
          This option specifies the maximum age in minutes of the unwrapped objects in the cache
          after its last use.
          The default is 15 minutes.
          About 2/3 of the objects will be evicted after this time; the other 1/3 will be evicted
          after a maximum of 150% of the time.
          
          [env: KMS_UNWRAPPED_CACHE_MAX_AGE=]
          [default: 15]

      --socket-server-start
          Start the KMIP socket server? If this is set to true, the TLS config must be provided, featuring a server PKCS#12 file and a client certificate authority certificate file
          
          [env: KMS_SOCKET_SERVER_START=]

      --socket-server-port <SOCKET_SERVER_PORT>
          The KMS socket server port
          
          [env: KMS_SOCKET_SERVER_PORT=]
          [default: 5696]

      --socket-server-hostname <SOCKET_SERVER_HOSTNAME>
          The KMS socket server hostname
          
          [env: KMS_SOCKET_SERVER_HOSTNAME=]
          [default: 0.0.0.0]

      --tls-p12-file <TLS_P12_FILE>
          The KMS server optional PKCS#12 Certificates and Key file.
          Mandatory when starting the socket server.
          When provided, the Socket and HTTP server will start in TLS Mode.
          
          [env: KMS_HTTPS_P12_FILE=]

      --tls-p12-password <TLS_P12_PASSWORD>
          The password to open the PKCS#12 Certificates and Key file
          
          [env: KMS_HTTPS_P12_PASSWORD=]

      --clients-ca-cert-file <CLIENTS_CA_CERT_FILE>
          The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
          If provided, clients must present a certificate signed by this authority for authentication.
          Mandatory to start the socket server.
          
          [env: KMS_CLIENTS_CA_CERT_FILE=]

      --port <PORT>
          The KMS HTTP server port
          
          [env: KMS_PORT=]
          [default: 9998]

      --hostname <HOSTNAME>
          The KMS HTTP server hostname
          
          [env: KMS_HOSTNAME=]
          [default: 0.0.0.0]

      --api-token-id <API_TOKEN_ID>
          An optional API token to use for authentication on the HTTP server.
          
          [env: KMS_API_TOKEN=]

      --https-p12-file <HTTPS_P12_FILE>
          DEPRECATED: use the TLS section instead.
          The KMS server optional PKCS#12 Certificates and Key file. If provided, this will start the server in HTTPS mode.
          
          [env: KMS_HTTPS_P12_FILE=]

      --https-p12-password <HTTPS_P12_PASSWORD>
          DEPRECATED: use the TLS section instead.
          The password to open the PKCS#12 Certificates and Key file.
          
          [env: KMS_HTTPS_P12_PASSWORD=]

      --authority-cert-file <AUTHORITY_CERT_FILE>
          DEPRECATED: use the TLS section instead.
          The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
          If provided, clients must present a certificate signed by this authority for authentication.
          The server must run in TLS mode for this to be used.
          
          [env: KMS_AUTHORITY_CERT_FILE=]

      --proxy-url <PROXY_URL>
          The proxy URL:
            - e.g., "https://secure.example" for an HTTP proxy
            - e.g., "socks5://192.168.1.1:9000" for a SOCKS proxy
          
          [env: KMS_PROXY_URL=]

      --proxy-basic-auth-username <PROXY_BASIC_AUTH_USERNAME>
          Set the Proxy-Authorization header username using Basic auth.
          
          [env: KMS_PROXY_BASIC_AUTH_USERNAME=]

      --proxy-basic-auth-password <PROXY_BASIC_AUTH_PASSWORD>
          Set the Proxy-Authorization header password using Basic auth.
          
          [env: KMS_PROXY_BASIC_AUTH_PASSWORD=]

      --proxy-custom-auth-header <PROXY_CUSTOM_AUTH_HEADER>
          Set the Proxy-Authorization header to a specified value.
          
          [env: KMS_PROXY_CUSTOM_AUTH_HEADER=]

      --proxy-exclusion-list <PROXY_EXCLUSION_LIST>
          The No Proxy exclusion list to this Proxy
          
          [env: KMS_PROXY_NO_PROXY=]

      --jwt-issuer-uri <JWT_ISSUER_URI>...
          The issuer URI of the JWT token
          
          To handle multiple identity managers, add different parameters under each argument (jwt-issuer-uri, jwks-uri, and optionally jwt-audience), keeping them in the same order :
          
          --jwt-issuer-uri <`JWT_ISSUER_URI_1`> <`JWT_ISSUER_URI_2`> --jwks-uri <`JWKS_URI_1`> <`JWKS_URI_2`> --jwt-audience <`JWT_AUDIENCE_1`> <`JWT_AUDIENCE_2`>
          
          For Auth0, this is the delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`
          
          For Google, this would be `https://accounts.google.com`
          
          [env: KMS_JWT_ISSUER_URI=]

      --jwks-uri <JWKS_URI>...
          The JWKS (JSON Web Key Set) URI of the JWT token
          
          To handle multiple identity managers, add different parameters under each argument (jwt-issuer-uri, jwks-uri, and optionally jwt-audience), keeping them in the same order
          
          For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`
          
          For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`
          
          Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set
          
          [env: KMS_JWKS_URI=]

      --jwt-audience <JWT_AUDIENCE>...
          The audience of the JWT token
          
          Optional: the server will validate the JWT `aud` claim against this value if set - to set an identity provider configuration element to None, set its value to an empty string.
          
          [env: KMS_JWT_AUDIENCE=]

  -u, --ui-index-html-folder <UI_INDEX_HTML_FOLDER>
          The UI distribution folder
          
          [env: COSMIAN_UI_DIST_PATH=]
          [default: /usr/local/cosmian/ui/dist/]

      --ui-oidc-client-id <UI_OIDC_CLIENT_ID>
          The client ID of the configured OIDC tenant for UI Auth
          
          [env: UI_OIDC_CLIENT_ID=]

      --ui-oidc-client-secret <UI_OIDC_CLIENT_SECRET>
          The client secret of the configured OIDC tenant for UI Auth
          
          [env: UI_OIDC_CLIENT_SECRET=]

      --ui-oidc-issuer-url <UI_OIDC_ISSUER_URL>
          The issuer URI of the configured OIDC tenant for UI Auth
          
          [env: UI_OIDC_ISSUER_URL=]

      --ui-oidc-logout-url <UI_OIDC_LOGOUT_URL>
          The logout URI of the configured OIDC tenant for UI Auth
          
          [env: UI_OIDC_LOGOUT_URL=]

      --google-cse-enable
          This setting turns on endpoints handling Google CSE feature
          
          [env: KMS_GOOGLE_CSE_ENABLE=]

      --google-cse-disable-tokens-validation
          This setting turns off the validation of the tokens used by this server's Google Workspace CSE feature
          
          [env: KMS_GOOGLE_CSE_DISABLE_TOKENS_VALIDATION=]

      --google-cse-incoming-url-whitelist <GOOGLE_CSE_INCOMING_URL_WHITELIST>
          This setting contains the list of KACLS server URLs that can access this server for Google CSE migration, through the privilegedunwrap endpoint (used to fetch exposed jwks on server start)
          
          [env: KMS_GOOGLE_CSE_INCOMING_URL_WHITELIST=]

      --google-cse-migration-key <GOOGLE_CSE_MIGRATION_KEY>
          PEM PKCS8 RSA private key used to ensure consistency of certificate handling and privileged unwrap operations across server restarts and multiple server instances. If not provided, a random key will be generated at server startup
          
          [env: KMS_GOOGLE_CSE_MIGRATION_KEY=]

      --root-data-path <ROOT_DATA_PATH>
          The root folder where the KMS will store its data A relative path is taken relative to the user's HOME directory
          
          [env: KMS_ROOT_DATA_PATH=]
          [default: ./cosmian-kms]

      --tmp-path <TMP_PATH>
          The folder to store temporary data (non-persistent data readable by no one but the current instance during the current execution)
          
          [env: KMS_TMP_PATH=]
          [default: /tmp]

      --default-username <DEFAULT_USERNAME>
          The default username to use when no authentication method is provided
          
          [env: KMS_DEFAULT_USERNAME=]
          [default: admin]

      --force-default-username
          When an authentication method is provided, perform the authentication
          but always use the default username instead of the one provided by the authentication method
          
          [env: KMS_FORCE_DEFAULT_USERNAME=]

      --ms-dke-service-url <MS_DKE_SERVICE_URL>
          This setting enables the Microsoft Double Key Encryption service feature of this server.
          
          It should contain the external URL of this server as configured in Azure App Registrations
          as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
          
          The URL should be something like <https://cse.my_domain.com/ms_dke>
          
          [env: KMS_MS_DKE_SERVICE_URL=]

      --rust-log <RUST_LOG>
          An alternative to setting the `RUST_LOG` environment variable.
          Setting this variable will override the `RUST_LOG` environment variable
          
          [env: KMS_RUST_LOG=]

      --otlp <OTLP>
          The OTLP collector URL for gRPC
          (for instance, <http://localhost:4317>)
          If not set, the telemetry system will not be initialized
          
          [env: KMS_OTLP_URL=]

      --quiet
          Do not log to stdout
          
          [env: KMS_LOG_QUIET=]

      --log-to-syslog
          Log to syslog
          
          [env: KMS_LOG_TO_SYSLOG=]

      --enable-metering
          Enable metering in addition to tracing when telemetry is enabled
          
          [env: KMS_ENABLE_METERING=]

      --environment <ENVIRONMENT>
          The name of the environment (development, test, production, etc.)
          This will be added to the telemetry data if telemetry is enabled
          
          [env: KMS_ENVIRONMENT=]
          [default: development]

      --info
          Print the server configuration information and exit

      --hsm-model <HSM_MODEL>
          The HSM model.
          Trustway Proteccio and Utimaco General purpose HSMs are supported.
          
          [default: proteccio]
          [possible values: proteccio, utimaco]

      --hsm-admin <HSM_ADMIN>
          The username of the HSM admin. The HSM admin can create objects on the HSM, destroy them, and potentially export them
          
          [env: KMS_HSM_ADMIN=]
          [default: admin]

      --hsm-slot <HSM_SLOT>
          HSM slot number. The slots used must be listed.
          Repeat this option to specify multiple slots
          while specifying a password for each slot (or an empty string for no password)
          e.g.
          ```sh
            --hsm_slot 1 --hsm_password password1 \
            --hsm_slot 2 --hsm_password password2
          ```

      --hsm-password <HSM_PASSWORD>
          Password for the user logging in to the HSM Slot specified with `--hsm_slot`
          Provide an empty string for no password
          see `--hsm_slot` for more information

      --kms-public-url <KMS_PUBLIC_URL>
          The exposed URL of the KMS - this is required if Google CSE configuration is activated.
          If this server is running on the domain `cse.my_domain.com` with this public URL,
          The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
          The URL is also used during the authentication flow initiated from the KMS UI.
          
          [env: KMS_PUBLIC_URL=]

      --privileged-users <PRIVILEGED_USERS>
          List of users who have the right to create and import Objects
          and grant access rights for Create Kmip Operation.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version


```

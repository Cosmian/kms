# Server CLI

```text

Usage: cosmian_kms [OPTIONS] [KEY_ENCRYPTION_KEY]

Arguments:
  [KEY_ENCRYPTION_KEY]
          Force all keys imported or created in the KMS, which are not protected by a key encryption key, to be wrapped by the specified key encryption key (KEK)

Options:
  -c, --config <COSMIAN_KMS_CONF>
          Explicit configuration file path provided via -c / --config. When set, this file takes precedence over the `COSMIAN_KMS_CONF` environment variable and the default system path. All other command line arguments (except `--help` / `--version`) and environment variables are ignored once the configuration file is loaded

      --vendor-identification <VENDOR_IDENTIFICATION>
          The vendor identification string reported in KMIP `QueryServerInformation` responses

          [env: KMS_VENDOR_IDENTIFICATION=]
          [default: cosmian]

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

      --info
          Print the server configuration information and exit

      --print-default-config
          Serialize the default server configuration as TOML to stdout and exit. This is used to keep the documentation in sync with the Rust struct

      --hsm-model <HSM_MODEL>
          The HSM model.
          `Trustway Proteccio`, `Trustway Crypt2pay`, `Utimaco General Purpose HSM`,
          `Smartcard HSM`, and `SoftHSM2` are natively supported.
          Other HSMs are supported too; specify `other` and check the documentation

          [default: proteccio]
          [possible values: proteccio, crypt2pay, utimaco, softhsm2, smartcardhsm, other]

      --hsm-admin <HSM_ADMIN>...
          List of KMS usernames that are granted HSM admin privileges.
          HSM admins can create, destroy, and potentially export objects on the HSM.
          Use `"*"` as the only entry to grant all authenticated users admin access.
          Repeat the option or use a comma-separated list to specify multiple admins:
            `--hsm-admin alice@example.com --hsm-admin bob@example.com`
            or set `KMS_HSM_ADMIN=alice@example.com,bob@example.com`

          [env: KMS_HSM_ADMIN=]
          [default: admin]

      --hsm-slot <HSM_SLOT>
          HSM slot number. The slots used must be listed.
          Repeat this option to specify multiple slots
          while specifying a password for each slot (or an empty string for no password)
          e.g.
          ```sh
            --hsm-slot 1 --hsm-password password1 \
            --hsm-slot 2 --hsm-password password2
          ```

          [env: KMS_HSM_SLOT=]

      --hsm-password <HSM_PASSWORD>
          Password for the user logging in to the HSM Slot specified with `--hsm_slot`
          Provide an empty string for no password
          see `--hsm_slot` for more information.
          Set `KMS_HSM_PASSWORD` to avoid the password appearing in `ps` output.

          [env: KMS_HSM_PASSWORD=]

      --default-unwrap-type <DEFAULT_UNWRAP_TYPE>
          Specifies which KMIP object types should be automatically unwrapped when retrieved.
          Repeat this option to specify multiple object types
          e.g.
          ```sh
            --default-unwrap-type SecretData \
            --default-unwrap-type SymmetricKey
          ```

          [possible values: All, Certificate, CertificateRequest, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey]

      --kms-public-url <KMS_PUBLIC_URL>
          The exposed URL of the KMS - this is required if Google CSE configuration is activated.
          If this server is running on the domain `cse.my_domain.com` with this public URL,
          The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
          The URL is also used during the authentication flow initiated from the KMS UI.

          [env: KMS_PUBLIC_URL=]

      --database-type <DATABASE_TYPE>
          The main database of the KMS server that holds default cryptographic objects and permissions.
          - postgresql: `PostgreSQL`. The database URL must be provided
          - mysql: `MySql` or `MariaDB`. The database URL must be provided
          - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
            A key must be supplied on every call
          - redis-findex [non-FIPS]: a Redis database with encrypted data and indexes thanks to Findex.
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

      --clear-database
          Clear the database on start.
          WARNING: This will delete ALL the data in the database

          [env: KMS_CLEAR_DATABASE=]

      --max-connections <MAX_CONNECTIONS>
          Maximum number of connections for the relational database pool. When not provided, falls back to the current defaults: - `PostgreSQL`/`MySQL`: min(10, 2 × CPU cores), fallback 10 - `SQLite`: number of CPUs

          [env: KMS_DB_MAX_CONNECTIONS=]

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

      --unwrapped-cache-max-size <UNWRAPPED_CACHE_MAX_SIZE>
          Maximum number of entries in the unwrapped key cache.
          When the cache is full, the least-recently-used entry is evicted.
          Set this above the number of distinct wrapped keys in your deployment
          to avoid LRU thrashing. The default is 1000.

          [env: KMS_UNWRAPPED_CACHE_MAX_SIZE=]
          [default: 1000]

      --unwrapped-cache-max-ttl <UNWRAPPED_CACHE_MAX_TTL>
          Absolute time-to-live in minutes for entries in the unwrapped key cache.
          When set, a cached unwrapped key is evicted at most this many minutes after
          it was first inserted, regardless of how frequently it is accessed.
          This caps plaintext key residency for continuously-used (hot) keys and
          satisfies compliance policies that require a hard upper bound on in-memory
          key material exposure.
          When not set (the default), only the time-to-idle window applies and hot
          keys may remain cached indefinitely.
          When set, value must be ≥ `unwrapped-cache-max-age`.

          [env: KMS_UNWRAPPED_CACHE_MAX_TTL=]

      --disable-unwrapped-cache
          Disable the unwrapped key cache entirely.
          When set, every operation that needs plaintext key material will perform
          a full KEK-unwrap (or HSM call) on every request instead of serving the
          key from memory.
          Use this in high-security environments where no plaintext key material
          should persist in process memory beyond a single operation.
          Disabling the cache significantly increases CPU and HSM load.

          [env: KMS_DISABLE_UNWRAPPED_CACHE=]

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
          The KMS server optional PKCS#12 Certificates and Key file as an alternative
          to providing the key, certificate and chain in PEM format.
          When provided, the Socket and HTTP server will start in TLS Mode.

          [env: KMS_TLS_P12_FILE=]

      --tls-p12-password <TLS_P12_PASSWORD>
          The password to open the PKCS#12 Certificates and Key file

          [env: KMS_TLS_P12_PASSWORD=]

      --tls-cert-file <TLS_CERT_FILE>
          The server's X.509 certificate in PEM format.
          Provide a PEM containing the server leaf certificate,
          optionally followed by intermediate certificates (full chain). When provided along with
          `--tls-key-file`, the servers will start in TLS mode.
          Do not use in combination with `--tls-p12-file`.

          [env: KMS_TLS_CERT_FILE=]

      --tls-key-file <TLS_KEY_FILE>
          The server's private key in PEM format (PKCS#8 or traditional format).
          Must correspond to the certificate in `--tls-cert-file`.
          Do not use in combination with `--tls-p12-file`.

          [env: KMS_TLS_KEY_FILE=]

      --tls-chain-file <TLS_CHAIN_FILE>
          Optional certificate chain in PEM format (intermediate CAs).
          If not provided, the chain may be appended to `--tls-cert-file` instead.
          Do not use in combination with `--tls-p12-file`.

          [env: KMS_TLS_CHAIN_FILE=]

      --clients-ca-cert-file <CLIENTS_CA_CERT_FILE>
          The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
          If provided, clients must present a certificate signed by this authority for authentication.
          Mandatory to start the socket server.

          [env: KMS_CLIENTS_CA_CERT_FILE=]

      --tls-cipher-suites <TLS_CIPHER_SUITES>
          Colon-separated list of TLS cipher suites to enable:
          Example: --tls-cipher-suites `"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"`
          If not specified, OpenSSL default cipher suites will be used:
          ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:\
          ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
          DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:\
          ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:\
          ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:\
          DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:\
          EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:\
          AES256-SHA:DES-CBC3-SHA:!DSS"
          Otherwise, the ANSSI TLS 1.2 guide recommends prioritizing AEAD suites using ECDHE
          key exchange, with AES-GCM/AES-CCM (preferred) and ChaCha20-Poly1305 as an acceptable
          alternative.

          Example (TLS 1.2):
          `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`

          [env: KMS_TLS_CIPHER_SUITES=]

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

      --rate-limit-per-second <RATE_LIMIT_PER_SECOND>
          Maximum number of requests per second per IP address allowed by the rate limiter.
          When set, the server enforces this limit to mitigate `DoS` and brute-force attacks.
          Requests exceeding the limit receive HTTP 429 Too Many Requests.
          Leave unset (default) to disable rate limiting.

          [env: KMS_RATE_LIMIT_PER_SECOND=]

      --cors-allowed-origins <CORS_ALLOWED_ORIGINS>
          Comma-separated list of origins allowed to make cross-origin requests to the KMIP API.
          Required for any Web UI deployment: the browser Fetch API sends an `Origin` header on
          every POST request — even when the page is served by the KMS itself — and actix-cors
          rejects it unless the exact origin appears in this list.
          The value must match byte-for-byte what the user types in the browser address bar
          (scheme + hostname + port). The server bind address (`0.0.0.0`) and the server IP
          are not equivalent to a DNS hostname. The Docker image pre-populates loopback
          addresses; add any custom hostname explicitly. Example: `http://kms.example.com:9998`.

          [env: KMS_CORS_ALLOWED_ORIGINS=]

      --http-workers <HTTP_WORKERS>
          Number of actix-web HTTP worker threads.
          Defaults to the number of logical CPUs. On I/O-heavy workloads (e.g. `PostgreSQL` backend)
          setting this to `2 * <number of CPU cores>` improves throughput by keeping more Tokio
          threads busy while others are waiting on network I/O.
          Can also be set via the `TOKIO_WORKER_THREADS` environment variable (Tokio runtime),
          but this flag controls only the actix-web application workers.

          [env: KMS_HTTP_WORKERS=]

      --jwks-enabled
          Enable the `GET /.well-known/jwks.json` endpoint.

          When set, the server exposes all public keys with the `Verify` usage mask as a
          RFC 7517 JSON Web Key Set. Defaults to `false`; set to `true` to enable public key
          discovery for JWT verification.

          [env: KMS_JWKS_ENABLED=]

      --proxy-url <PROXY_URL>
          The proxy URL:
            - e.g., `https://secure.example` for an HTTP proxy
            - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy

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

      --jwt-auth-provider <JWT_AUTH_PROVIDER>
          JWT authentication provider configuration.

          The expected argument is --jwt-auth-provider="`PROVIDER_CONFIG_1`" --jwt-auth-provider="`PROVIDER_CONFIG_2`" ...
          where each `PROVIDER_CONFIG_N` defines one identity provider configuration.

          Each provider configuration `PROVIDER_CONFIG_N` should be in the format: "`JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE_1,JWT_AUDIENCE_2,...`"
          where:
          - `JWT_ISSUER_URI`: The issuer URI of the JWT token (required)
          - `JWKS_URI`: The JWKS (JSON Web Key Set) URI (optional, defaults to <JWT_ISSUER_URI>/.well-known/jwks.json)
          - `JWT_AUDIENCE_1..N`: One or more audience values for the JWT token (optional)

          Examples:
          --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs, kacls-migration, another-audience"
          --jwt-auth-provider="https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/v2.0,https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/discovery/v2.0/keys"
          --jwt-auth-provider="https://<your-tenant>.<region>.auth0.com/""
          This argument can be repeated to configure multiple identity providers.

          [env: KMS_JWT_AUTH_PROVIDER=]

      --enable
          Disable the embedded web UI. When set to false, the UI HTML assets are not served and all `/ui/` routes return 404

          [env: KMS_UI_ENABLE=]

  -u, --ui-index-html-folder <UI_INDEX_HTML_FOLDER>
          The UI distribution folder

          [env: COSMIAN_UI_DIST_PATH=]

      --ui-session-salt <UI_SESSION_SALT>
          A secret salt used to derive the session cookie encryption key.
          This MUST be identical across all KMS instances behind the same load balancer.
          This should only be provided when `ui_index_html_folder` is explicitly defined.

          [env: KMS_SESSION_SALT=]

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

      --azure-ekm-enable
          This setting turns on/off the endpoints handling Azure EKM features

          [env: KMS_AZURE_EKM_ENABLE=]

      --azure-ekm-path-prefix <AZURE_EKM_PATH_PREFIX>
          Optional path prefix set within Managed HSM during EKM configuration.

          Enables multi-customer use or isolation of different MHSM pools using the same proxy.
          Must be max 64 characters: letters (a-z, A-Z), numbers (0-9), slashes (/), dashes (-).

          [env: KMS_AZURE_EKM_PATH_PREFIX=]

      --azure-ekm-disable-client-auth
          WARNING: This bypasses mTLS authentication entirely. Only use for testing!

          [env: KMS_AZURE_EKM_DISABLE_CLIENT_AUTH=]

      --azure-ekm-proxy-vendor <AZURE_EKM_PROXY_VENDOR>
          Proxy vendor name to report in /info endpoint

          [env: KMS_AZURE_EKM_PROXY_VENDOR=]
          [default: Cosmian]

      --azure-ekm-proxy-name <AZURE_EKM_PROXY_NAME>
          Proxy name to report in /info endpoint

          [env: KMS_AZURE_EKM_PROXY_NAME=]
          [default: "EKM Proxy Service"]

      --azure-ekm-ekm-vendor <AZURE_EKM_EKM_VENDOR>
          EKMS vendor name report in the /info endpoint

          [env: KMS_AZURE_EKM_VENDOR=]
          [default: Cosmian]

      --azure-ekm-ekm-product <AZURE_EKM_EKM_PRODUCT>
          Product Name and Version of the EKMS to report in the /info endpoint

          [env: KMS_AZURE_EKM_PRODUCT=]
          [default: "Cosmian KMS v5.26.0"]

      --root-data-path <ROOT_DATA_PATH>
          The root folder where the KMS will store its data A relative path is taken relative to the user's HOME directory

          [env: KMS_ROOT_DATA_PATH=]
          [default: ./cosmian-kms]

      --tmp-path <TMP_PATH>
          The folder to store temporary data (non-persistent data readable by no one but the current instance during the current execution)

          [env: KMS_TMP_PATH=]
          [default: /tmp]

      --rust-log <RUST_LOG>
          An alternative to setting the `RUST_LOG` environment variable.
          Setting this variable will override the `RUST_LOG` environment variable

          [env: KMS_RUST_LOG=]

      --otlp <OTLP>
          The OTLP collector URL for gRPC
          (for instance, <https://localhost:4317>)
          If not set, the telemetry system will not be initialized.
          Must use https:// in production.
          Use --otlp-allow-insecure to permit plaintext http:// connections.

          [env: KMS_OTLP_URL=]

      --otlp-allow-insecure
          Allow insecure (plaintext HTTP) OTLP connections. WARNING: Enabling this exposes telemetry data (including encryption operation metadata) over an unencrypted channel. Only use for development or when the collector is on localhost

          [env: KMS_OTLP_ALLOW_INSECURE=]

      --quiet
          Do not log to stdout

          [env: KMS_LOG_QUIET=]

      --log-to-syslog
          Log to syslog

          [env: KMS_LOG_TO_SYSLOG=]

      --rolling-log-dir <ROLLING_LOG_DIR>
          The directory for daily rolling logs: <rolling_log_name>.YYYY-MM-DD.
          File logging is disabled unless this option is explicitly set.
          Suggested paths:
            Linux: /var/log/
            Windows: C:\Users\<username>\AppData\Local\Cosmian KMS Server
            macOS: ~/Library/Logs/

          WARNING: Windows environment variables (e.g. %LOCALAPPDATA%) are NOT
          expanded. Use the fully-resolved path.

          [env: KMS_ROLLING_LOG_DIR=]

      --rolling-log-name <ROLLING_LOG_NAME>
          The name of the rolling log file: <rolling_log_name>.YYYY-MM-DD.
          Defaults to `cosmian_kms` if not set.

          [env: KMS_ROLLING_LOG_NAME=]

      --enable-metering
          Enable metering in addition to tracing when telemetry is enabled

          [env: KMS_ENABLE_METERING=]

      --environment <ENVIRONMENT>
          The name of the environment (development, test, production, etc.)
          This will be added to the telemetry data if telemetry is enabled

          [env: KMS_ENVIRONMENT=]
          [default: development]

      --ansi-colors
          Enable ANSI colors in the logs to stdout

          [env: KMS_ANSI_COLORS=]

      --crypto-officer-users <CRYPTO_OFFICER_USERS>
          Users with the Crypto Officer role.

          May manage key lifecycle (create, import, certify, rekey, activate, revoke, destroy)
          and access raw key material.
          When active, gains ownership bypass on all Managed Objects.
          When set, only listed users (plus those explicitly granted the `Create` right) can
          create and import objects.

      --crypto-officer-require-ceremony
          Require a split-key ceremony to activate the Crypto Officer role.

          When `true`, users listed in `crypto_officer_users` are candidates only —
          the role is inactive until a KMIP `JoinSplitKey` with all shares tagged
          `x-cosmian-crypto-officer-ceremony` completes.

      --ceremony-secret <CEREMONY_SECRET>
          Hex-encoded 32-byte secret for ceremony record encryption.

          Required when any role has `require_ceremony = true`.
          All ceremony activation records are AES-256-GCM encrypted with keys
          derived from this secret, preventing forgery via direct database writes
          and protecting participant identities at rest.

          Generate with: `openssl rand -hex 32`

          [env: KMS_CEREMONY_SECRET=]

      --ceremony-key-id <CEREMONY_KEY_ID>
          UID of a KMS symmetric key to use as the ceremony record sealing key.

          When set, key material is fetched from the KMS object store after database
          initialization and used in place of `ceremony_secret`. This enables:
            - Key rotation via standard KMIP `ReKey` / `Rotate` operations.
            - HSM-backed sealing when the referenced key is HSM-resident.
            - Audit trail: each retrieval of the ceremony key is logged.

          If both `ceremony_secret` and `ceremony_key_id` are set, `ceremony_key_id` takes precedence.

          **Bootstrap constraint**: the ceremony sealing key must be created before
          enabling `crypto_officer_require_ceremony = true`. Create it while the server
          is in config-only CO mode (no ceremony required), then enable ceremony mode:

          ```bash
          # 1. Start server with require_ceremony = false
          # 2. Create the sealing key:
          ckms sym keys create --id ceremony-seal-2026 --number-of-bits 256
          # 3. Set ceremony_key_id = "ceremony-seal-2026" in kms.toml
          # 4. Enable require_ceremony = true and restart
          ```

          [env: KMS_CEREMONY_KEY_ID=]

      --ceremony-wrapping-key-id <CEREMONY_WRAPPING_KEY_ID>
          UID of a KMS symmetric key to use for AES-KW (RFC 5649) wrapping of split-key shares.

          When set, `CreateSplitKey` encrypts each share's raw bytes with this key (AES-128/192/256-KWP)
          before storing in the database.  `JoinSplitKey` automatically detects the
          `x-cosmian-share-wrapping-key` vendor attribute on each share and unwraps the bytes before
          XOR reconstruction.

          The wrapping key must already exist in the KMS object store and must be an AES symmetric key.
          When the KMS is HSM-backed, this key can be HSM-resident, providing hardware boundary
          protection equivalent to purpose-built HSM split-key solutions.

          Generate a suitable key before enabling ceremony mode:
          ```bash
          ckms sym keys create --id ceremony-wrap-2026 --number-of-bits 256
          ```

          Rotate by creating a new key, updating this value, and re-running the ceremony
          (existing wrapped shares require the original key; re-ceremony is mandatory on rotation).

          [env: KMS_CEREMONY_WRAP_KEY_ID=]

      --aws-xks-enable
          This setting turns on endpoints handling the AWS XKS feature

          [env: KMS_AWS_XKS_ENABLE=]

      --aws-xks-region <AWS_XKS_REGION>
          The AWS XKS region to use for signing requests (sigv4)

          [env: KMS_AWS_XKS_REGION=]

      --aws-xks-service <AWS_XKS_SERVICE>
          The AWS XKS service name to use for signing requests (sigv4)

          [env: KMS_AWS_XKS_SERVICE=]

      --aws-xks-sigv4-access-key-id <AWS_XKS_SIGV4_ACCESS_KEY_ID>
          The AWS XKS `SigV4` access key ID used to sign requests

          [env: KMS_AWS_XKS_SIGV4_ACCESS_KEY_ID=]

      --aws-xks-sigv4-secret-access-key <AWS_XKS_SIGV4_SECRET_ACCESS_KEY>
          [env: KMS_AWS_XKS_SIGV4_SECRET_ACCESS_KEY=]

      --kmip-policy-id <POLICY_ID>
          KMIP algorithm policy selector.

          Accepted values (case-insensitive):
          - `DEFAULT`: enforce the built-in conservative allowlists (aligned with ANSSI/NIST/FIPS).
          - `CUSTOM`: enforce the allowlists provided under `[kmip.allowlists]`.

          [env: KMS_POLICY_ID=]

      --auto-rotation-check-interval-secs <AUTO_ROTATION_CHECK_INTERVAL_SECS>
          Interval in seconds between background auto-rotation checks.
          Set to 0 (default) to disable the auto-rotation background task.
          When enabled, must be at least 60 seconds to avoid excessive database churn.

          [default: 0]

      --keyset-warn-depth <KEYSET_WARN_DEPTH>
          Depth at which a successful keyset chain decryption triggers a server-side warning.
          Keyset chain traversal is unbounded (stopped only by cycle detection);
          this threshold emits a warning log so operators can flag stale ciphertexts.
          Default: 5.

          [default: 5]

      --backend <BACKEND>
          Possible values:
          - vault:       `HashiCorp` Vault KV-v2. Path format: `secret://<mount>/<path>[#<field>]`
          - aws-ssm:     AWS Systems Manager Parameter Store. Path format: `secret://<region>/<parameter-name>`
          - azure-kv:    Azure Key Vault. Path format: `secret://<vault-name>/secrets/<name>[/<version>]`
          - cosmian-kms: Another Cosmian KMS server (KMIP Get). Path format: `secret://<host>[:<port>]/<object-id>`

          [env: KMS_SECRET_BACKEND=]

      --vault-addr <VAULT_ADDR>
          [env: VAULT_ADDR=]
          [default: http://127.0.0.1:8200]

      --vault-token <VAULT_TOKEN>
          [env: VAULT_TOKEN=]
          [default: ""]

      --aws-access-key-id <AWS_ACCESS_KEY_ID>
          [env: AWS_ACCESS_KEY_ID=]
          [default: ""]

      --aws-secret-access-key <AWS_SECRET_ACCESS_KEY>
          [env: AWS_SECRET_ACCESS_KEY=]
          [default: ""]

      --aws-session-token <AWS_SESSION_TOKEN>
          [env: AWS_SESSION_TOKEN=]

      --azure-tenant-id <AZURE_TENANT_ID>
          [env: AZURE_TENANT_ID=]
          [default: ""]

      --azure-client-id <AZURE_CLIENT_ID>
          [env: AZURE_CLIENT_ID=]
          [default: ""]

      --azure-client-secret <AZURE_CLIENT_SECRET>
          [env: AZURE_CLIENT_SECRET=]
          [default: ""]

      --cosmian-kms-secret-token <COSMIAN_KMS_SECRET_TOKEN>
          [env: COSMIAN_KMS_SECRET_TOKEN=]

      --cosmian-kms-insecure-certs
          [env: COSMIAN_KMS_INSECURE_CERTS=]

      --jwks-endpoint-enabled
          Enable the `GET /.well-known/jwks.json` endpoint.

          When set, the server publicly exposes all active public keys whose
          `CryptographicUsageMask` includes `Verify` as a RFC 7517 JSON Web Key Set.
          The endpoint is **unauthenticated** — no credentials are required to fetch it,
          and no authentication middleware is applied. Defaults to `false`.

          [env: KMS_JWKS_ENDPOINT_ENABLED=]

      --jwks-endpoint-max-keys <JWKS_ENDPOINT_MAX_KEYS>
          Maximum number of public keys returned in a single JWKS response.

          When the server holds more eligible keys than this limit, the response is
          truncated and an `X-JWKS-Truncated: true` header is added to signal consumers.
          Increase this value if your deployment performs frequent key rotation and all
          overlapping verification keys must be simultaneously discoverable.

          [env: KMS_JWKS_ENDPOINT_MAX_KEYS=]
          [default: 50]

      --jwks-endpoint-auto-tag
          Automatically tag key pairs created via the REST crypto API for JWKS inclusion.

          When `true` (the default), every key pair created via `POST /v1/crypto/keys`
          receives the `"jwks"` tag and immediately appears in
          `GET /.well-known/jwks.json`.

          Set to `false` to disable this behaviour globally.  Operators must then
          manually tag each public key via `POST /v1/crypto/keys/{kid}/tags` before
          it is published in the JWKS document.

          This setting has no effect on keys created directly through the KMIP protocol.

          [env: KMS_JWKS_ENDPOINT_AUTO_TAG=]

      --vault-api-enabled
          Enable the Vault-compatible `/v1/transit/` and `/v1/<vault_pki_mount>/` scopes.

          Defaults to `false`. Set to `true` to enable the Vault-compatible API. Requires `vault_auth_verifier_url` to be set.

          [env: KMS_VAULT_API_ENABLED=]

      --vault-auth-verifier-url <VAULT_AUTH_VERIFIER_URL>
          Base URL of the auth-verifier server used to validate `X-Vault-Token` headers.

          Required when `vault_api_enabled = true`. Example: `https://auth.example.com`

          [env: KMS_VAULT_AUTH_VERIFIER_URL=]

      --vault-auth-verifier-ca-cert <VAULT_AUTH_VERIFIER_CA_CERT>
          Path to a PEM-encoded CA certificate used to verify the auth-verifier's TLS certificate.

          Optional. When set, the KMS will trust this CA when connecting to `vault_auth_verifier_url`. Useful when auth-verifier uses a self-signed or private CA certificate.

          [env: KMS_VAULT_AUTH_VERIFIER_CA_CERT=]

      --vault-auth-verifier-accept-invalid-certs
          Skip TLS certificate verification when calling the auth-verifier.

          **Security warning**: only set this to `true` in test or development environments. In production, use `vault_auth_verifier_ca_cert` to provide the correct CA certificate. Defaults to `false`.

          [env: KMS_VAULT_AUTH_VERIFIER_ACCEPT_INVALID_CERTS=]

      --vault-transit-mount <VAULT_TRANSIT_MOUNT>
          Vault transit mount name used by the `/v1/<mount>/keys/…` routes.

          Transit keys are served at `/v1/<vault_transit_mount>/keys/<name>`.
          Defaults to `"transit"`.

          [env: KMS_VAULT_TRANSIT_MOUNT=]
          [default: transit]

      --vault-pki-mount <VAULT_PKI_MOUNT>
          Vault PKI mount name used by the `/v1/<mount>/root/sign-intermediate` route.

          Defaults to `"pki"`.

          [env: KMS_VAULT_PKI_MOUNT=]
          [default: pki]

      --vault-pki-ca-key-label <VAULT_PKI_CA_KEY_LABEL>
          KMIP label of the KMS key used as the intermediate CA signing key for the PKI engine.

          The key must already exist in the KMS (create with `ckms ec keys create --tag <label>`).
          Defaults to `"vault_pki_ca"`.

          [env: KMS_VAULT_PKI_CA_KEY_LABEL=]
          [default: vault_pki_ca]

      --vault-token-cache-ttl-secs <VAULT_TOKEN_CACHE_TTL_SECS>
          Lifetime of vault token validation cache entries in seconds.

          Successful `lookup-self` responses from the auth-verifier are cached
          for this duration to reduce round-trips on every transit/PKI request.
          Set to `0` to disable caching. Defaults to `30`.

          [env: KMS_VAULT_TOKEN_CACHE_TTL_SECS=]
          [default: 30]

      --crl-default-validity-days <CRL_DEFAULT_VALIDITY_DAYS>
          Default CRL validity period in days for CA certificates managed by this server.

          When a CRL is generated without an explicit validity override (e.g., via
          `GET /certificates/{id}/crl?validity_days=N`), this value is used.

          Production CAs often use 1–24 h for short-lived CRLs (code-signing,
          high-security); enterprise PKIs commonly use 7–28 days.

          Valid range: 1–365. Default: 7.

          [default: 7]

      --crl-refresh-check-hours <CRL_REFRESH_CHECK_HOURS>
          How often (in hours) the background CRL refresh scheduler wakes up to
          check whether any stored CRL needs to be regenerated.

          Set to 0 to disable the background scheduler entirely.
          When disabled, CRLs are only refreshed on certificate revocation events.

          Default: 1 (wake up hourly).

          [default: 1]

      --crl-refresh-overlap-hours <CRL_REFRESH_OVERLAP_HOURS>
          CRL overlap window in hours.

          The background scheduler regenerates a CRL when its `nextUpdate` timestamp
          is within this many hours of the current time.  This prevents relying parties
          from seeing an expired CRL during the window between expiry and the next
          revocation-triggered regeneration.

          Analogy: EJBCA "CRL Overlap Time" (default 10 % of validity); AWS PCA uses
          a 1-day overlap by default.

          Default: 24 (regenerate 24 hours before expiry).

          [default: 24]

      --ocsp-enabled
          Enable the OCSP responder endpoint at `GET/POST /ocsp/`.

          When `false` (default) all `/ocsp/` routes return 404.

      --ocsp-ca-uid <OCSP_CA_UID>
          UID of the CA certificate object in the KMS.

          Used to verify that incoming OCSP requests are for certificates issued by
          this CA (by comparing issuer name hash and key hash), and to retrieve
          certificate states for revocation lookup.

          Must be set when `ocsp_enabled = true`.

      --ocsp-responder-cert-uid <OCSP_RESPONDER_CERT_UID>
          UID of the dedicated OCSP signing certificate (RFC 6960 §4.2.2.2 authorized responder).

          When set, OCSP responses are signed by this delegated key+certificate rather
          than the CA's own private key.  The referenced certificate MUST have:
          - `extKeyUsage: OCSPSigning` (OID 1.3.6.1.5.5.7.3.9)

          It SHOULD also have the `id-pkix-ocsp-nocheck` extension (OID
          1.3.6.1.5.5.7.48.1.5, RFC 6960 §4.2.2.2.1) — this is only one of three
          RFC-sanctioned ways to let relying parties check the responder certificate's
          own revocation status (the others being a CDP/AIA pointer, or local policy), so
          its absence is not required, only logged as a warning.

          The `OCSPSigning` requirement is enforced at request time: the server rejects
          the delegated certificate (and refuses to sign) if it is missing.

          The referenced key may be backed by an HSM via the existing PKCS#11 routing —
          no additional configuration is required.

          When unset, the CA's own private key is used (acceptable for small deployments;
          not recommended for production CAs where the signing key must stay offline).

      --ocsp-cache-ttl-secs <OCSP_CACHE_TTL_SECS>
          OCSP response validity period in seconds (`thisUpdate` → `nextUpdate`).

          Determines how long a signed response may be cached by relying parties and
          CDN/proxy intermediaries per RFC 5019 §5.  Shorter values increase freshness;
          longer values reduce load on the KMS (and HSM) signing key.

          Default: 86400 (24 hours).

          [default: 86400]

      --ocsp-nonce-policy <OCSP_NONCE_POLICY>
          Nonce handling policy for OCSP responses (RFC 9654 §2.1).

          - `optional` (default): echo the nonce if present, proceed without one if absent.
          - `required`: reject requests that carry no nonce (returns `malformedRequest`).
          - `ignore`: never include a nonce in responses (suitable for pre-produced/cached responses).

          Per RFC 9654 §2.1, the responder MUST accept nonces of 16–128 octets and echo
          them verbatim.  Nonces shorter than 16 octets are silently ignored.

          [default: optional]

      --ocsp-include-cert-chain
          Include the signing certificate chain in OCSP `BasicResponse`s.

          Set to `true` (default) when `ocsp_responder_cert_uid` is configured so that
          clients can verify the delegated responder's authorization without additional
          fetches.  Safe to set `false` when the CA signs responses directly.

      --ocsp-archive-cutoff-secs <OCSP_ARCHIVE_CUTOFF_SECS>
          Archive-cutoff extension value in seconds (RFC 6960 §4.4.4).

          When non-zero, the `id-pkix-ocsp-archive-cutoff` extension is added to each
          `BasicResponse` with value = now − `ocsp_archive_cutoff_secs`. This tells clients
          how far back the responder maintains revocation records.

          Set to 0 (default) to disable the extension.
          Typical values: 365 days = 31536000.

          [default: 0]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

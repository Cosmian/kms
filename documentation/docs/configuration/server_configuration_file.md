# TOML configuration file

The KMS server can be configured using a TOML file. When a configuration file is provided,
the [command line arguments](./server_cli.md) are ignored (except `--help` / `--version`).

## Interactive configuration wizard

The fastest way to create a valid configuration file is the built-in interactive wizard:

```bash
cosmian_kms configure
```

The wizard guides you step-by-step through all configuration sections:

| Step | Section                | What it covers                                                                    |
| ---- | ---------------------- | --------------------------------------------------------------------------------- |
| 1/9  | **Database**           | Type (SQLite / PostgreSQL / MySQL / Redis-Findex), URL, paths, cache settings     |
| 2/9  | **HTTP server**        | Listening port and hostname                                                       |
| 3/9  | **TLS / Certificates** | Enable TLS; optionally generates a self-signed PKI (CA → server + client certs)   |
| 4/9  | **KMIP socket server** | Enable the binary KMIP socket listener (port 5696)                                |
| 5/9  | **Authentication**     | API token, JWT/OIDC providers, mTLS client certificates                           |
| 6/9  | **HSM**                | Model, admin user, slot numbers and passwords                                     |
| 7/9  | **Logging**            | Log level, OTLP endpoint, syslog, rolling logs                                    |
| 8/9  | **Proxy**              | Outbound proxy for JWKS fetch (URL, auth, exclusions)                             |
| 9/9  | **Advanced**           | Workspace paths, KEK, MS DKE, KMIP policy, Google CSE, Azure EKM, AWS XKS, Web UI |

At the end the wizard writes the resulting TOML file to the default system path
(`/etc/cosmian/kms.toml` on Linux/macOS, `C:\ProgramData\Cosmian\kms.toml` on Windows)
and prints the command to start the server:

```bash
Start the server with:
  cosmian_kms -c /etc/cosmian/kms.toml
```

### Self-signed PKI generation

When TLS is enabled and you choose to generate certificates, the wizard creates a
complete PKI under the chosen output directory (default `/etc/cosmian/`):

| File         | Description                                                           |
| ------------ | --------------------------------------------------------------------- |
| `ca.crt`     | Self-signed CA certificate (RSA-4096, valid 10 years by default)      |
| `server.crt` | Server leaf certificate signed by the CA (RSA-2048)                   |
| `server.key` | Server private key (PKCS#8 PEM)                                       |
| `client.crt` | Client leaf certificate signed by the CA — distribute to mTLS clients |
| `client.key` | Client private key (PKCS#8 PEM)                                       |

Distribute `client.crt` and `client.key` to any client that must authenticate
with mutual TLS.  You can verify the chain at any time with:

```bash
openssl verify -CAfile /etc/cosmian/ca.crt /etc/cosmian/server.crt
openssl verify -CAfile /etc/cosmian/ca.crt /etc/cosmian/client.crt
```

---

## Manual configuration

Configuration file loading precedence:

1. Command line flag `-c/--config <FILE>` (highest precedence). If the file does not exist, the server exits with an error.
2. Environment variable `COSMIAN_KMS_CONF` (must point to an existing file).
3. Default system path: `/etc/cosmian/kms.toml` (Linux/macOS) or `C:\\ProgramData\\Cosmian\\kms.toml` (Windows).
4. If none of the above files is found, the server falls back to parsing the [command line arguments](./server_cli.md) and environment variables.

> **Important:** If a configuration file is found via the default system path (rule 3) **and** extra
> command-line arguments are also provided, the server exits with an error. This prevents silently
> ignoring arguments the user intended to take effect. To use a different configuration, point
> explicitly to it with `-c/--config <FILE>`.
Examples:

```bash
# Explicit configuration file
./cosmian-kms -c ./test_data/configs/server/jwt_auth.toml

# Using an environment variable
export COSMIAN_KMS_CONF=./test_data/configs/server/jwt_auth.toml
./cosmian-kms
```

The file should be a TOML file with the following structure:

```toml
# The default username to use when no authentication method is provided
default_username = "admin"

# When an authentication method is provided, perform the authentication
# but always use the default username instead of the one provided by the authentication method
force_default_username = false

# This setting enables the Microsoft Double Key Encryption service feature of this server.
#
# It should contain the external URL of this server as configured in Azure App Registrations
# as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
#
# The URL should be something like <https://cse.my_domain.com/ms_dke>
# ms_dke_service_url = "<ms dke service url>"

# The exposed URL of the KMS - this is required if Google CSE configuration is activated.
# If this server is running on the domain `cse.my_domain.com` with this public URL,
# The configured URL from Google admin  should be something like <https://cse.my_domain.com/google_cse>
# The URL is also used during the authentication flow initiated from the KMS UI.
# kms_public_url = "kms-public-url"

# Print the server configuration information and exit
info = false

# The HSM model.
# `Trustway Proteccio`, `Trustway Crypt2pay`, `Utimaco General Purpose HSM`,
# `Smartcard HSM`, and `SoftHSM2` are natively supported.
# Other HSMs are supported too; specify `other` and check the documentation
# hsm_model = "<hsm_name>" # the name of the HSM model (see HSMs documentation)
# List of KMS usernames that are granted HSM admin privileges.
# HSM admins can create, destroy, and potentially export objects on the HSM.
# Use `"*"` as the only entry to grant all authenticated users admin access.
# Repeat the option or use a comma-separated list to specify multiple admins:
#   `--hsm-admin alice@example.com --hsm-admin bob@example.com`
#   or set `KMS_HSM_ADMIN=alice@example.com,bob@example.com`
# hsm_admin = ["admin"]   # list of HSM admin users; use ["*"] to allow all users to perform HSM operations
# HSM slot number. The slots used must be listed.
# Repeat this option to specify multiple slots
# while specifying a password for each slot (or an empty string for no password)
# e.g.
# ```sh
#   --hsm-slot 1 --hsm-password password1 \
#   --hsm-slot 2 --hsm-password password2
# ```
# hsm_slot = [1, 2, ...] # slot numbers
# Password for the user logging in to the HSM Slot specified with `--hsm_slot`
# Provide an empty string for no password
# see `--hsm_slot` for more information.
# Set `KMS_HSM_PASSWORD` to avoid the password appearing in `ps` output.
# hsm_password = ["<password_of_1st_slot1>", "<password_of_2bd_slot2>", ...] # corresponding user slot passwords/pins

# Force all newly created and imported keys to be wrapped by the key specified in this field.
# This is most useful to ensure that an HSM key wraps all keys in the KMS database.
# Note: This setting is ignored when a key is imported in JSON TTLV format and is already wrapped.
# key_encryption_key = "kek ID"

# Specifies which KMIP object types should be automatically unwrapped when retrieved.
# Repeat this option to specify multiple object types
# e.g.
# ```sh
#   --default-unwrap-type SecretData \
#   --default-unwrap-type SymmetricKey
# ```
# default_unwrap_type = ["SecretData", "SymmetricKey"]

# List of users who have the right to create and import Objects
# and grant access rights for Create Kmip Operation.
# privileged_users = ["<user_id_1>", "<user_id_2>"]

# Check the database configuration documentation pages for more information
[db]
# The main database of the KMS server that holds default cryptographic objects and permissions.
# - postgresql: `PostgreSQL`. The database URL must be provided
# - mysql: `MySql` or `MariaDB`. The database URL must be provided
# - sqlite: `SQLite`. The data will be stored at the `sqlite_path` directory
#   A key must be supplied on every call
# - redis-findex [non-FIPS]: a Redis database with encrypted data and indexes thanks to Findex.
#   The Redis URL must be provided, as well as the redis-master-password and the redis-findex-label
database_type = "sqlite"
# The URL of the database for `Postgres`, `MySQL`, or `Findex-Redis`
# database_url = "<database-url>"
# The directory path of the `SQLite`
# sqlite_path = "<sqlite-path>"
# redis-findex: a master password used to encrypt the Redis data and indexes
# redis_master_password = "<redis master password>"

# Clear the database on start.
# WARNING: This will delete ALL the data in the database
clear_database = false

# When a wrapped object is fetched from the database,
# it is unwrapped and stored in the unwrapped cache.
# This option specifies the maximum age in minutes of the unwrapped objects in the cache
# after its last use.
# The default is 15 minutes.
# About 2/3 of the objects will be evicted after this time; the other 1/3 will be evicted
# after a maximum of 150% of the time.
unwrapped_cache_max_age = 15 # minutes

# TLS configuration of the Socket server and HTTP server
[tls]
# The server's X.509 certificate in PEM format.
# Provide a PEM containing the server leaf certificate,
# optionally followed by intermediate certificates (full chain). When provided along with
# `--tls-key-file`, the servers will start in TLS mode.
# Do not use in combination with `--tls-p12-file`.
# tls_cert_file = "path/to/server.crt"
# The server's private key in PEM format (PKCS#8 or traditional format).
# Must correspond to the certificate in `--tls-cert-file`.
# Do not use in combination with `--tls-p12-file`.
# tls_key_file = "path/to/server.key"
# Optional certificate chain in PEM format (intermediate CAs).
# If not provided, the chain may be appended to `--tls-cert-file` instead.
# Do not use in combination with `--tls-p12-file`.
# tls_chain_file = "path/to/chain.pem"

# The KMS server optional PKCS#12 Certificates and Key file as an alternative
# to providing the key, certificate and chain in PEM format.
# When provided, the Socket and HTTP server will start in TLS Mode.
# tls_p12_file = "[tls p12 file]"
# The password to open the PKCS#12 Certificates and Key file
# tls_p12_password = "[tls p12 password]"

# The server's optional X. 509 certificate in PEM format validates the client certificate presented for authentication.
# If provided, clients must present a certificate signed by this authority for authentication.
# Mandatory to start the socket server.
# clients_ca_cert_file = "[authority cert file]"

# The socket server listens to KMIP binary requests on the IANA-registered 4696 port.
# The socket server will only start if the TLS configuration is provided **and** client certificate authentication
# is enabled.
[socket_server]
# Start the KMIP socket server? If this is set to true, the TLS config must be provided, featuring a server PKCS#12 file and a client certificate authority certificate file
# socket_server_start = false

# The KMS socket server port
# socket_server_port = 5696

# The KMS socket server hostname
# socket_server_hostname = "0.0.0.0"

# The HTTP server listens to KMIP requests on the /kmip and /kmip/2_1 endpoints.
# It also serves the web UI on the /ui endpoint.
# If the TLS configuration is provided, the server will start in HTTPS mode.
[http]
# The KMS HTTP server port
port = 9998
# The KMS HTTP server hostname
hostname = "0.0.0.0"

# An optional API token to use for authentication on the HTTP server.
# api_token_id = "<secret-api-token>"

# Maximum number of requests per second per IP address allowed by the rate limiter.
# When set, the server enforces this limit to mitigate `DoS` and brute-force attacks.
# Requests exceeding the limit receive HTTP 429 Too Many Requests.
# Leave unset (default) to disable rate limiting.
# rate_limit_per_second = 100

# Comma-separated list of origins allowed to make cross-origin requests to the KMIP API.
# Use this to allow browser-based clients (e.g. a Vite dev server) that run on a different
# port or host from the KMS server. In production, leave unset to restrict to same-origin
# only (the KMS serves its own UI). Example: `http://127.0.0.1:5173`.
# cors_allowed_origins = ["<origin-1>", "<origin-2>"]

# If using a forward proxy for outbound JWKS requests,
# set the proxy parameters here.
[proxy]
# The proxy URL:
#   - e.g., `https://secure.example` for an HTTP proxy
#   - e.g., `socks5://192.168.1.1:9000` for a SOCKS proxy
# proxy_url = "https://proxy.example.com:8080"

# Set the Proxy-Authorization header username using Basic auth.
# proxy_basic_auth_username = "[proxy username]"

# Set the Proxy-Authorization header password using Basic auth.
# proxy_basic_auth_password = "[proxy password]"

# Set the Proxy-Authorization header to a specified value.
# proxy_custom_auth_header = "my_custom_auth_token"

# The No Proxy exclusion list to this Proxy
# proxy_exclusion_list = ["domain1", "domain2"]

# Check the Authenticating Users documentation pages for more information.
[idp_auth]
# JWT authentication provider configuration.
#
# The expected argument is --jwt-auth-provider="`PROVIDER_CONFIG_1`" --jwt-auth-provider="`PROVIDER_CONFIG_2`" ...
# where each `PROVIDER_CONFIG_N` defines one identity provider configuration.
#
# Each provider configuration `PROVIDER_CONFIG_N` should be in the format: "`JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE_1,JWT_AUDIENCE_2,...`"
# where:
# - `JWT_ISSUER_URI`: The issuer URI of the JWT token (required)
# - `JWKS_URI`: The JWKS (JSON Web Key Set) URI (optional, defaults to <JWT_ISSUER_URI>/.well-known/jwks.json)
# - `JWT_AUDIENCE_1..N`: One or more audience values for the JWT token (optional)
#
# Examples:
# --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs, kacls-migration, another-audience"
# --jwt-auth-provider="https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/v2.0,https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174b69062c96/discovery/v2.0/keys"
# --jwt-auth-provider="https://<your-tenant>.<region>.auth0.com/""
# This argument can be repeated to configure multiple identity providers.
# jwt_auth_provider = [
#   "https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience,another_client_id",
#   "https://auth0.example.com,,my-app",
#   "https://keycloak.example.com/auth/realms/myrealm,,"
# ]

[workspace]
# The root folder where the KMS will store its data A relative path is taken relative to the user's HOME directory
# root_data_path = "./cosmian-kms"

# The folder to store temporary data (non-persistent data readable by no one but the current instance during the current execution)
# tmp_path = "/tmp"

# Check the logging documentation pages for more information
[logging]
# An alternative to setting the `RUST_LOG` environment variable.
# Setting this variable will override the `RUST_LOG` environment variable
rust_log = "info,cosmian_kms=info"

# The OTLP collector URL for gRPC
# (for instance, <https://localhost:4317>)
# If not set, the telemetry system will not be initialized.
# Must use https:// or grpcs:// in production.
# Use --otlp-allow-insecure to permit plaintext http:// connections.
# otlp = "http://localhost:4317"

# Do not log to stdout
quiet = false

# Log to syslog
log_to_syslog = false

# If set, daily rolling logs will be written to the specified directory
# using the name specified by `rolling_log_name`: <rolling_log_name>.YYYY-MM-DD.
# rolling_log_dir = "path_to_logging_directory"

# If `rolling_log_dir` is set, this is the name of the rolling log file:
#  <rolling_log_name>.YYYY-MM-DD.
# Defaults to "kms" if not set.
# rolling_log_name = "kms"

# Enable metering in addition to tracing when telemetry is enabled
# enable_metering = false

# The name of the environment (development, test, production, etc.)
# This will be added to the telemetry data if telemetry is enabled
# environment = "development"

# Enable ANSI colors in the logs to stdout
ansi_colors = false

# Generic configuration to edit the path to static UI application files
# To use the Web UI, ensure the `kms_public_url` is set to the correct public URL above.
[ui_config]
# The UI distribution folder
ui_index_html_folder = "/usr/local/cosmian/ui/dist"

# Configuration for the handling of authentication with OIDC from the KMS UI.
# This is used to authenticate users when they access the KMS UI.
# The same Identity Provider must **also** be configured in the [idp_auth] section above.
[ui_config.ui_oidc_auth]
# The client ID of the configured OIDC tenant for UI Auth
# ui_oidc_client_id = "<client id>"
# The client secret of the configured OIDC tenant for UI Auth
# ui_oidc_client_secret = "<client secret>" (optional)
# The issuer URI of the configured OIDC tenant for UI Auth
# ui_oidc_issuer_url = "<issuer-url>"
# The logout URI of the configured OIDC tenant for UI Auth
# ui_oidc_logout_url = "<logout-url>"

[google_cse_config]
# This setting turns on endpoints handling Google CSE feature
google_cse_enable = false

# This setting turns off the validation of the tokens used by this server's Google Workspace CSE feature
# google_cse_disable_tokens_validation = false

# This setting contains the list of KACLS server URLs that can access this server for Google CSE migration, through the privilegedunwrap endpoint (used to fetch exposed jwks on server start)
# google_cse_incoming_url_whitelist = ["[kacls_url_1]", "[kacls_url_2]"]

# PEM PKCS8 RSA private key used to ensure consistency of certificate handling and privileged unwrap operations across server restarts and multiple server instances. If not provided, a random key will be generated at server startup
# google_cse_migration_key = "<google_cse_existing_migration_key>"

[azure_ekm_config]
# This setting turns on/off the endpoints handling Azure EKM features
azure_ekm_enable = false

[aws_xks_config]
# This setting turns on endpoints handling the AWS XKS feature
aws_xks_enable = false

[kmip.allowlists]
```

---

## CORS configuration

Cross-Origin Resource Sharing (CORS) controls which browser origins are allowed
to make requests to the KMS HTTP API.

**Default behavior (no configuration needed for most deployments):**
the `[http]` section ships with an empty `cors_allowed_origins` list, which
restricts the KMIP API to same-origin requests only. Because the KMS already
serves its own Web UI from the same host and port, production deployments
typically do not need to change this setting.

Only set `cors_allowed_origins` when a browser client runs on a **different**
origin from the KMS server — for example a Vite dev server during development,
or a custom front-end hosted on a separate domain.

```toml
[http]
# Allow a Vite dev-server and a custom front-end to reach the KMIP API.
cors_allowed_origins = ["http://127.0.0.1:5173", "https://app.example.com"]
```

The same list can be provided via the environment variable
`KMS_CORS_ALLOWED_ORIGINS` (comma-separated) or the CLI flag
`--cors-allowed-origins`.

!!! warning "Security implications"
    Every origin in `cors_allowed_origins` can issue **authenticated**
    cross-origin requests to the KMS — session cookies and credentials are
    forwarded for each listed origin.

    - **Only add origins you fully control and trust.**  A compromised or
      malicious site listed here can read and manage all cryptographic objects
      accessible to the authenticated user.
    - **Never use a wildcard (`*`).**  `actix-cors` rejects a wildcard when
      `supports_credentials()` is active, and a wildcard CORS policy would
      expose every user's keys to any website on the internet.
    - **Omit this field entirely in production** unless your architecture
      genuinely requires a cross-origin browser client.  When the KMS serves
      its own UI (the default), no extra origin is needed.

    **Enterprise integration scopes are not affected by this setting.**
    The Google CSE, Microsoft DKE, and AWS XKS endpoints retain their own
    permissive CORS policy as required by their respective integration
    contracts — `cors_allowed_origins` has no effect on those routes.

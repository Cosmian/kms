# TOML configuration file

The KMS server can be configured using a TOML file. When a configuration file is provided,
the [command line arguments](./server_cli.md) are ignored.

By default, the configuration filepath is retrieved in the following order:

1. If the environment variable `COSMIAN_KMS_CONF` is set and the path behind exists, the KMS server will use this
   configuration file,
2. Otherwise, on Linux and macOS, if a file is found at `/etc/cosmian/kms.toml`, the KMS server will use this file.
   On Windows, it will look for a file at `C:\ProgramData\Cosmian\kms.toml`, Make sure that the file is readable
   by the user running the KMS server.
3. Finally, if none of the above is found, the KMS server will use the [command line arguments](./server_cli.md)

The file should be a TOML file with the following structure:

```toml
# The default username to use when no authentication method is provided.
default_username = "admin"

# When an authentication method is provided, perform the authentication
# but always use the default username instead of the one provided by the authentication method
force_default_username = false

# This setting enables the Microsoft Double Key Encryption service feature on this server.
# It should contain the external URL of this server as configured in Azure App Registrations
# as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
# The URL should be something like <https://cse.my_domain.com/ms_dke>
ms_dke_service_url = "<ms dke service url>"

# This setting defines the public URL where the KMS is accessible (e.g., behind a proxy).
# It is used :
# -  during the authentication flow initiated from the KMS UI. See the [ui_config] section below.
# - for cse endpoints: it is required if Google CSE configuration is activated;
# If this server is running on the domain `cse.my_domain.com` with this public URL,
# The configured URL from Google admin should be something like <https://cse.my_domain.com/google_cse>
kms_public_url = "kms-public-url"

# Print the server configuration information and exit
info = false

# The following fields are only needed if an HSM is used.
# Check the HSMs documentation pages for more information.
hsm_model = "<hsm_name>"
hsm_admin = "<hsm admin username>" #for Create operation on HSM
hsm_slot = [1, 2, ...]
hsm_password = ["<password_of_1st_slot1>", "<password_of_2bd_slot2>", ...]

# Force all newly created and imported keys to be wrapped by the key specified in this field.
# This is most useful to ensure that an HSM key wraps all keys in the KMS database.
# Note: This setting is ignored when a key is imported in JSON TTLV format and is already wrapped.
key_encryption_key = "kek ID"

# All users can create and import objects in the KMS by default.
# Only these users can create and import objects when this setting contains a user ID list.
privileged_users = ["<user_id_1>", "<user_id_2>"]

# Check the database configuration documentation pages for more information
[db]
database_type = "postgresql", "mysql", "sqlite", "redis-findex"
database_url = "<database-url>"
sqlite_path = "<sqlite-path>"
redis_master_password = "<redis master password>"
redis_findex_label = "<redis findex label>"
# Clear the database at startup. WARNING: This will delete all objects in the database.
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
# The KMS server's optional PKCS#12 Certificates and Key file.
# If provided, this will start the server in HTTPS mode.
tls_p12_file = "[tls p12 file]"
# The password to open the PKCS#12 certificates and key file.
tls_p12_password = "[tls p12 password]"
# The server's optional authority X509 certificate in PEM format
# used to validate the client certificate presented for authentication.
# If provided, clients must present a certificate signed by this authority for authentication.
# The server must run in TLS mode for this to be used.
clients_ca_cert_file = "[authority cert file]"

# The socket server listens to KMIP binary requests on the IANA-registered 5696 port.
# The socket server will only start if the TLS configuration is provided **and** client certificate authentication
# is enabled.
[socket_server]
# Start the socket server. See comments above on conditions for starting the server.
socket_server_start = false
# The socket server port - defaults to 5696
socket_server_port = 5696
# The socket server hostname - defaults to "0.0.0.0"
socket_server_hostname = "0.0.0.0"

# The HTTP server listens to KMIP requests on the /kmip and /kmip/2_1 endpoints.
# It also serves the web UI on the /ui endpoint.
# If the TLS configuration is provided, the server will start in HTTPS mode.
[http]
# The KMS server port - defaults to 9998
port = 9998
# The KMS server hostname - defaults to 0.0.0.0
hostname = "0.0.0.0"

# If using a forward proxy for outbound JWKS requests, 
# set the proxy parameters here.
[proxy]
# The URL of the proxy server, including the protocol and port.
#   - e.g., "https://secure.example" for an HTTP proxy
#   - e.g., "socks5://192.168.1.1:9000" for a SOCKS proxy
proxy_url = "https://proxy.example.com:8080"
# The username to use for basic authentication with the proxy server.
proxy_basic_auth_username = "[proxy username]"
# The password to use for basic authentication with the proxy server.   
proxy_basic_auth_password = "[proxy password]"
# Use a custom proxy authentication header instead of the standard Basic authentication.
proxy_custom_auth_header = "my_custom_auth_token"
# The list of domains to exclude from the proxy.
proxy_exclusion_list = ["domain1", "domain2"]

# Check the Authenticating Users documentation pages for more information.
[auth]
# The issuer URI of the JWT token
# To handle multiple identity managers, add different parameters
# under each argument (jwt-issuer-uri, jwks-uri, and optionally jwt-audience),
# keeping them in the same order in the three lists.
# For Auth0, this is the delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`
# For Google, this would be `https://accounts.google.com`
jwt_issuer_uri = ["<jwt issuer uri>"]

# The JWKS (Json Web Key Set) URI of the JWT token
# To handle multiple identity managers, add different parameters under each argument
#  (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in the same order
# To set an identity provider configuration element to None, set its value to an empty string.
# For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`
# For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`
# Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set
jwks_uri = ["<jwks uri>"]

# The audience of the JWT token
# Optional: the server will validate the JWT `aud` claim against this value if set
jwt_audience = ["<jwt audience>"]

[workspace]
# The root folder where the KMS will store its data
# A relative path is taken relative to the user's HOME directory
root_data_path = "./cosmian-kms"

# The folder to store temporary data (non-persistent data readable
# by no one but the current instance during the current execution)
tmp_path = "/tmp"

# Check the logging documentation pages for more information
[logging]
# The log level of the KMS server. This is an alternative to the `RUST_LOG` environment variable.
rust_log = "info,cosmian_kms=debug"

# The Open Telemetry OTLP collector URL.
otlp = "http://localhost:4317"

# If set to true, the KMS server will not output logs to stdout. Telemetry will still be sent to the OTLP collector,
# if configured.
quiet = false

# If set to true, the KMS server will log to syslog instead of stdout.
log_to_syslog = false

# If set, daily rolling logs will be written to the specified directory
# using the name specified by `rolling_log_name`: <rolling_log_name>.YYYY-MM-DD.
rolling_log_dir = "path_to_logging_directory"
# If `rolling_log_dir` is set, this is the name of the rolling log file:
#  <rolling_log_name>.YYYY-MM-DD.
# Defaults to "kms" if not set.
rolling_log_name = "kms"

# The Telemetry will also contain metering and tracing events if set to true.
enable_metering = false
# When using telemetry, this setting will show the KMS environment: "production", "development", "staging", "testing"...
environment = "development"

# Enable ANSI colors in the logs to stdout
ansi_colors = false

# Generic configuration to edit the path to static UI application files
# To use the Web UI, ensure the `kms_public_url` is set to the correct public URL above.
[ui_config]
ui_index_html_folder = "path/kms/ui/dist"

# Configuration for the handling of authentication with OIDC from the KMS UI.
# This is used to authenticate users when they access the KMS UI.
# The same Identity Provider must **also** be configured in the [auth] section above.
[ui_config.ui_oidc_auth]
ui_oidc_client_id = "<client id>"
ui_oidc_client_secret = "<client secret>" (optional)
ui_oidc_issuer_url = "<issuer-url>"
ui_oidc_logout_url = "<logout-url>"

[google_cse_config]
# This setting turns on endpoints, handling Google CSE feature
google_cse_enable = false

# This setting disables the validation of the tokens used by the Google Workspace CSE feature of this server
# Useful for testing purposes
google_cse_disable_tokens_validation = false

# This setting contains the list of KACLS server URLs that can access this server for Google CSE migration, through
# the privilegedunwrap endpoint (used to fetch exposed JWKS on server start)
google_cse_incoming_url_whitelist = ["[kacls_url_1]", "[kacls_url_2]"]

# PEM PKCS8 RSA private key used to ensure consistency of certificate handling and privileged unwrap operations
# across server restarts and multiple server instances. If not provided, a random key will be generated at server startup.
google_cse_migration_key = "<google_cse_existing_migration_key>"
```

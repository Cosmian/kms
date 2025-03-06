# TOML configuration file

The KMS server can be configured using a TOML file. When a configuration file is provided,
the [command line arguments](./server_cli.md) are ignored.

By default, the configuration filepath is retrieved in the following order:

1. if the environment variable `COSMIAN_KMS_CONF` is set and the path behind exists, the KMS server will use this
   configuration file,
2. otherwise if a file is found at `/etc/cosmian_kms/kms.toml`, the KMS server will use this file.
3. finally, if none of the above is found, the KMS server will use the [command line arguments](./server_cli.md)

The file should be a TOML file with the following structure:

```toml
# The default username to use when no authentication method is provided
default_username = "admin"
# When an authentication method is provided, perform the authentication
# but always use the default username instead of the one provided by the authentication method
force_default_username = false

# This setting enables the Google Workspace Client Side Encryption feature of this KMS server.
# It should contain the external URL of this server as configured
# in Google Workspace client side encryption settings For instance,
# if this server is running on domain `cse.my_domain.com`,
# the URL should be something like <https://cse.my_domain.com/google_cse>
google_cse_kacls_url = "<google cse kacls url>"

# This setting disables the validation of the tokens used by the Google Workspace CSE feature of this server
# Usefeull for testing purposes
google-cse-disable-tokens-validation = false

# This setting enables the Microsoft Double Key Encryption service feature of this server.
# It should contain the external URL of this server as configured in Azure App Registrations
# as the DKE Service (<https://learn.microsoft.com/en-us/purview/double-key-encryption-setup#register-your-key-store>)
# The URL should be something like <https://cse.my_domain.com/ms_dke>
ms_dke_service_url = "<ms dke service url>"

# Print the server configuration information and exit
info = false

# The following fields are only needed if an HSM is used.
# Check the HSMs pages for more information.
hsm_model = "<hsm_name>"
hsm_admin = "<hsm admin username>" #for Create operation on HSM
hsm_slot = [1, 2, ...]
hsm_password = ["<password_of_1st_slot1>", "<password_of_2bd_slot2>", ...]

# Check the database pages for more information
[db]
database_type = "postgresql", "mysql", "sqlite", "sqlite-enc", "redis-findex"
database_url = "<database-url>"
sqlite_path = "<sqlite-path>"
redis_master_password = "<redis master password>"
redis_findex_label = "<redis findex label>"
clear_database = false

# Check the Enabling TLS pages for more information
[http]
# The KMS server port - defaults to 9998
port = 9998
# The KMS server hostname - defaults to 0.0.0.0
hostname = "<hostname>"
# The KMS server optional PKCS#12 Certificates and Key file.
# If provided, this will start the server in HTTPS mode
https_p12_file = "<https p12 file>"
# The password to open the PKCS#12 Certificates and Key file
https_p12_password = "<https p12 password>"
#  The server optional authority X509 certificate in PEM format
# used to validate the client certificate presented for authentication.
# If provided, this will require clients to present a certificate signed by this authority for authentication.
# The server must run in TLS mode for this to be used
authority_cert_file = "<authority cert file>"

# Check the Auhtenticating Users for more information
[auth]
# The issuer URI of the JWT token
# To handle multiple identity managers, add different parameters
# under each argument (jwt-issuer-uri, jwks-uri and optionally jwt-audience),
# keeping them in the same order in the three lists.
# For Auth0, this is the delegated authority domain configured on Auth0, for instance `https://<your-tenant>.<region>.auth0.com/`
# For Google, this would be `https://accounts.google.com`
jwt_issuer_uri = ["<jwt issuer uri>"]
# The JWKS (Json Web Key Set) URI of the JWT token
# To handle multiple identity managers, add different parameters under each argument
#  (jwt-issuer-uri, jwks-uri and optionally jwt-audience), keeping them in the same order
# For Auth0, this would be `https://<your-tenant>.<region>.auth0.com/.well-known/jwks.json`
# For Google, this would be `https://www.googleapis.com/oauth2/v3/certs`
# Defaults to `<jwt-issuer-uri>/.well-known/jwks.json` if not set
jwks_uri = ["<jwks uri>"]
# The audience of the JWT token
# Optional: the server will validate the JWT `aud` claim against this value if set
jwt_audience = ["<jwt audience>"]

[ui_oidc_auth]
client_id = "[client id]"
issuer_url = "[issuer url]"
logout_url = "[logout url]"


[workspace]
# The root folder where the KMS will store its data
# A relative path is taken relative to the user HOME directory
root_data_path = "./cosmian-kms"
# The folder to store temporary data (non-persistent data readable
# by no-one but the current instance during the current execution)
tmp_path = "/tmp"

# Check the logging pages for more information
[telemetry]
# The Open Telemetry OTLP collector URL
otlp = "<url of the OTLP collector>"
# Do not log to stdout
quiet = false
```

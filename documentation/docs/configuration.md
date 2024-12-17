
# Configuration file

By default, the server expects to find:

- a TOML configuration file in `/etc/cosmian/cosmian.toml`.
- or an environment variable `COSMIAN_CLI_CONF` that contains the path to the configuration file.
- otherwise, the server will parse the arguments passed in command line.

## Example without authentication

```toml
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "http://0.0.0.0:9998"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
```

## Example with PKCS12 authentication

```toml
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "http://0.0.0.0:9990"
ssl_client_pkcs12_path = "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12"
ssl_client_pkcs12_password = "password"

[findex_config.http_config]
accept_invalid_certs = true
server_url = "https://0.0.0.0:6660"
ssl_client_pkcs12_path = "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12"
ssl_client_pkcs12_password = "password"
```

## Example with OpenID authentication

```toml
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "http://0.0.0.0:9998"
access_token = "eyJhbGciOiJSUz...jsFgROjPY84GRMmvpYZfyaJbDDql3A"

[kms_config.http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "G0ABCD-aAbBcDeFgHiJkLmNoPqRsTuVwXyZ"
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
access_token = "eyJhbGciOiJSUzI1...OjPY84GRMmvpYZfyaJbDDql3A"
```

## Example with S/MIME Gmail service account configuration for KMS server

```toml
[kms_config]
print_json = false

[kms_config.http_config]
server_url = "http://0.0.0.0:9998"
access_token = "eyJhbGciOiJSUz...jsFgROjPY84GRMmvpYZfyaJbDDql3A"

[kms_config.http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "G0ABCD-aAbBcDeFgHiJkLmNoPqRsTuVwXyZ"
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]

[kms_config.gmail_api_conf]
type = "service_account"
project_id = "project_id"
private_key_id = "abc123abc123abc123abc123abc123abc123"
private_key = "-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----"
client_email = "xxx@yyyy.iam.gserviceaccount.com"
client_id = "12345678901234567890"
auth_uri = "https://accounts.google.com/o/oauth2/auth"
token_uri = "https://oauth2.googleapis.com/token"
auth_provider_x509_cert_url = "https://www.googleapis.com/oauth2/v1/certs"
client_x509_cert_url = "https://www.googleapis.com/robot/v1/metadata/x509/xxx%40yyyy.iam.gserviceaccount.com"
universe_domain = "googleapis.com"

[findex_config.http_config]
server_url = "http://0.0.0.0:6668"
```

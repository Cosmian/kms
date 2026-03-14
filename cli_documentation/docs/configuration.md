
# Configuration file

The CLI looks for its configuration file in the following order:

1. The path in the `CKMS_CONF` environment variable (if set).
2. `~/.cosmian/ckms.toml` (user-level default).
3. `/etc/cosmian/ckms.toml` (system-wide fallback).
4. If none of the above exists, all options must be passed as command-line arguments.

Run `ckms configure` to create or update the file interactively.

## Minimal example

```toml
[http_config]
server_url = "http://0.0.0.0:9998"
```

## TLS client authentication

### With a PKCS#12 bundle

```toml
[http_config]
server_url = "https://kms.example.com"
ssl_client_pkcs12_path = "/path/to/client.p12"
ssl_client_pkcs12_password = "password"
```

### With PEM certificate and key

```toml
[http_config]
server_url = "https://kms.example.com"
ssl_client_pem_cert_path = "/path/to/client.crt"
ssl_client_pem_key_path  = "/path/to/client.key"
```

### Pinning a server certificate (instead of the system CA)

```toml
[http_config]
server_url = "https://kms.example.com"
# PEM-encoded certificate expected from the server
verified_cert = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
```

### Accepting invalid server certificates (testing only)

```toml
[http_config]
server_url = "https://kms.example.com"
accept_invalid_certs = true
```

## Custom HTTP headers

Some deployments place the KMS server behind a zero-trust proxy (e.g. Cloudflare
Zero Trust) that requires an extra HTTP header on every request.  Use the
`custom_headers` field — or the `--header` / `-H` CLI flag — to pass
arbitrary headers in `"Name: Value"` format.

### Via the configuration file

```toml
[http_config]
server_url = "https://kms.example.com"

# One or more headers in "Name: Value" format
custom_headers = [
    "cf-access-token: <your-cloudflare-access-token>",
    "X-Custom-Header: my-value",
]
```

### Via the command line or environment variable

The `--header` (short: `-H`) flag mirrors `curl`'s convention and can be
repeated for multiple headers:

```sh
# Single header
ckms --header "cf-access-token: <token>" server-version

# Multiple headers
ckms -H "cf-access-token: <token>" -H "X-Env: production" sym keys create
```

Set `CLI_HEADER` in the environment to apply headers without repeating the flag.
Multiple headers must be newline-separated:

```sh
export CLI_HEADER=$'cf-access-token: <token>\nX-Env: production'
ckms sym keys create
```

CLI flags merge with any `custom_headers` already present in `ckms.toml`.

## Forward proxy

Route all KMS traffic through an HTTP or SOCKS proxy using
`[http_config.proxy_params]` in the configuration file, or via CLI flags /
environment variables.

### Via the configuration file

```toml
[http_config]
server_url = "https://kms.example.com"

[http_config.proxy_params]
url = "http://proxy.corp:3128"

# Optional: exclude hosts from the proxy
exclusion_list = ["127.0.0.1", "*.internal"]

# Optional: proxy credentials — choose one of the two forms below.

# Form 1 – HTTP Basic auth
basic_auth_username = "proxyuser"
basic_auth_password = "proxypass"

# Form 2 – arbitrary Proxy-Authorization header value
# custom_auth_header = "Bearer <token>"
```

### Via the command line

| Flag | Environment variable | Description |
|------|---------------------|-------------|
| `--proxy-url <URL>` | `CLI_PROXY_URL` | Proxy URL (http://, https://, socks5://) |
| `--proxy-basic-auth-username` | `CLI_PROXY_BASIC_AUTH_USERNAME` | Basic-auth username |
| `--proxy-basic-auth-password` | `CLI_PROXY_BASIC_AUTH_PASSWORD` | Basic-auth password |
| `--proxy-custom-auth-header` | `CLI_PROXY_CUSTOM_AUTH_HEADER` | Full `Proxy-Authorization` header value |
| `--proxy-exclusion-list <HOST>` | `CLI_PROXY_NO_PROXY` | Hosts to bypass (repeatable) |

```sh
ckms --proxy-url http://proxy.corp:3128 \
     --proxy-basic-auth-username proxyuser \
     --proxy-basic-auth-password proxypass \
     sym keys create
```

### Combining a proxy with custom headers

Proxy settings and custom headers are independent and can be used together:

```sh
ckms --proxy-url http://proxy.corp:3128 \
     --header "cf-access-token: <token>" \
     --header "X-Tenant: acme" \
     sym keys create
```

Or fully in `ckms.toml`:

```toml
[http_config]
server_url = "https://kms.example.com"
custom_headers = ["cf-access-token: <token>", "X-Tenant: acme"]

[http_config.proxy_params]
url = "http://proxy.corp:3128"
```

## OpenID Connect / OAuth2 authentication

KMS can be configured with OpenID Connect (OIDC) authentication. In that case, KMS CLI must use the `oauth2_conf` field to authenticate to the server.

```toml
[http_config]
server_url = "http://0.0.0.0:9998"
access_token = "eyJhbGciOiJSUz...jsFgROjPY84GRMmvpYZfyaJbDDql3A"

[http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "XXX"
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]
```

## Advanced options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `http_config.cipher_suites` | string | (platform default) | Colon-separated list of TLS cipher suites, e.g. `"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"`. |
| `print_json` | bool | `false` | Print the raw KMIP JSON request and response for every operation. |

```toml
# Print raw KMIP JSON (useful for debugging)
print_json = true

[http_config]
server_url = "https://kms.example.com"
cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
```

## S/MIME Gmail service account configuration for KMS server

Google Workspace can delegate encryption/decryption of Gmail (and other services such as Drive, Meet, Calendar) to an external Key Management System (KMS). In that case, the KMS can be used to encrypt and decrypt the S/MIME elements (identities, key pairs) and store them securely.

When using S/MIME, the `gmail_api_conf` field should be set in the configuration file to provide the necessary information about the configured service account to interact with Gmail API, and handle identities and keypairs easily from the KMS.

```toml
[http_config]
server_url = "http://0.0.0.0:9998"
access_token = "eyJhbGciOiJSUz...jsFgROjPY84GRMmvpYZfyaJbDDql3A"

[http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "XXX"
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]

[gmail_api_conf]
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
```

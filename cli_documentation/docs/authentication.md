# CLI Authentication

This guide explains how to configure authentication for the KMS CLI when connecting to the KMS.

## Configuration File

The CLI reads its configuration from a TOML file:

- **Default location**: `~/.cosmian/ckms.toml`
- **Alternative location**: Set the `CKMS_CONF` environment variable

A basic configuration file is created automatically on first use:

```toml
[http_config]
server_url = "http://0.0.0.0:9998"
```

## Authentication Methods

The CLI supports multiple authentication methods for the KMS:

| Method | Configuration Elements | Use Case |
|--------|------------------------|----------|
| None (Default) | Only `server_url` | Development environments |
| Access Token | `access_token` | Simple API token authentication |
| TLS Client Certificate | `ssl_client_pkcs12_path`, `ssl_client_pkcs12_password` | Certificate-based auth |
| OAuth2/OIDC | `oauth2_conf` section | SSO with identity providers |
| Database Secret | `database_secret` | Encrypted database access |

## Authenticating Using TLS Client Certificates

To authenticate to the KMS using mutual TLS (mTLS), configure the `ssl_client_pkcs12_path` and
`ssl_client_pkcs12_password` options in the `http_config` section:

```toml
[http_config]
server_url = "https://kms.acme.com:9999"
ssl_client_pkcs12_path = "./certificates/machine.p12"
ssl_client_pkcs12_password = "pkcs12_password"
```

The `ssl_client_pkcs12_path` must point to a PKCS#12 file containing the client certificate and
private key. The KMS server authenticates the user using the Common Name (CN) field of the
certificate's subject.

## Common Configuration Options

Each product has its own `http_config` section with these options:

| Option | Description | Required |
|--------|-------------|----------|
| `server_url` | URL of the server | Yes |
| `accept_invalid_certs` | Accept self-signed certificates (set to "true") | No |
| `verified_cert` | PEM certificate for pinning | No |

For KMS, you can also configure Gmail API access for S/MIME operations - see the [S/MIME Gmail service account configuration](./smime_gmail.md).

## Quick Configuration Examples

### KMS with No Authentication

```toml
[http_config]
server_url = "http://127.0.0.1:9998"
```

## OAuth2/OIDC Authentication

### Basic Configuration

To authenticate using OAuth2/OIDC:

1. Configure the `oauth2_conf` section in your TOML file
2. Run `ckms login` to initiate authentication
3. Use `ckms logout` to clear the token

The `oauth2_conf` section requires:

```toml
[http_config.oauth2_conf]
client_id = "your-client-id"          # Required
authorize_url = "https://idp.example.com/authorize"  # Required
token_url = "https://idp.example.com/token"          # Required
scopes = ["openid", "email"]          # Recommended
client_secret = "your-client-secret"  # Optional with PKCE
```

### PKCE Authentication (Recommended)

PKCE (Proof Key for Code Exchange) enhances security by eliminating the need for client secrets. To use PKCE:

1. Configure OAuth2 in your TOML file but **omit** the `client_secret` field
2. Ensure your identity provider supports PKCE

```toml
[http_config.oauth2_conf]
client_id = "your-client-id"
authorize_url = "https://idp.example.com/authorize"
token_url = "https://idp.example.com/token"
scopes = ["openid", "email"]
# No client_secret needed with PKCE
```

PKCE is recommended for:

- CLI tools
- Desktop applications
- Mobile applications
- Any client that cannot securely store secrets

### Provider-Specific Examples

#### Microsoft Entra ID (Azure AD) with PKCE

```toml
[http_config.oauth2_conf]
client_id = "f052524e-7518-40e7-2579-219c0b48b125"
authorize_url = "https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174c4e562c96/oauth2/authorize"
token_url = "https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/oauth2/token"
scopes = ["email", "openid"]
# No client_secret needed with PKCE
```

> **Important**: In Entra ID, configure the redirect URL (<http://localhost:17899/authorization>) as Native/Desktop application type.

#### Auth0 with PKCE

```toml
[http_config.oauth2_conf]
client_id = "OUfH4FuzDAW99Ck3R4Rb7ROziOZEalIH"
authorize_url = "https://acme.eu.auth0.com/authorize"
token_url = "https://acme.eu.auth0.com/oauth/token"
scopes = ["email", "openid"]
# No client_secret needed with PKCE
```

> **Important**: In Auth0, configure the application as Native and ensure the redirect URL is allowed.

#### Google with Traditional OAuth2

```toml
[http_config.oauth2_conf]
client_id = "99999999-abababababababababab.apps.googleusercontent.com"
client_secret = "your-client-secret"  # Optional with PKCE
authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"
scopes = ["openid", "email"]
```

### Authentication Flow

When running `ckms login`:

1. The CLI generates a URL to open in your browser
2. You authenticate with your identity provider
3. The browser redirects to a local endpoint (<http://localhost:17899/authorization>)
4. The CLI captures the token and saves it in your configuration file

## Troubleshooting

- **Authentication Failures**: Verify client ID and URLs are correct
- **PKCE Issues**: Ensure your identity provider supports PKCE and has it enabled
- **Redirect Errors**: Check that your identity provider allows the redirect URL
- **Missing Email Claim**: Verify your identity provider includes the email claim in tokens

For more details about PKCE authentication, see the [PKCE Authentication Guide](../../documentation/docs/pkce_authentication.md).

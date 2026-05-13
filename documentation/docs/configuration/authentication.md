# Authentication

The KMS server offers flexible authentication options, supporting multiple authentication methods that can operate independently or in combination with each other, providing multi-factor authentication capabilities.

## Authentication Modes

### Non-authenticated Mode (Default)

By default, if no authentication methods are configured, the server operates in non-authenticated mode. All requests are mapped to the default user, which can be configured using:

```sh
    --default-username <DEFAULT_USERNAME>
    The default username to use when no authentication is configured

    [env: KMS_DEFAULT_USERNAME=]
    [default: admin]
```

### Authenticated Mode

When one or more authentication methods are enabled, the server requires successful authentication for all requests. The authentication mechanism works in a cascading fashion, attempting each configured method until one succeeds.

## Available Authentication Methods

The KMS server supports three primary authentication methods:

1. **TLS Client Certificates**: Authentication based on X.509 client certificates
2. **JWT Tokens**: Authentication with OpenID-compliant JWT access tokens
3. **API Tokens**: Authentication using a pre-shared API token

These methods can be used individually or in combination for enhanced security.

## Authentication Flow

When multiple authentication methods are configured, the server follows this process:

1. If TLS Client Certificate authentication is enabled and a valid certificate is presented, the user is authenticated
2. If JWT authentication is enabled and a valid JWT token is presented, the user is authenticated
3. If API Token authentication is enabled and a valid token is presented, the user is authenticated
4. If all configured authentication methods fail, access is denied with a 401 Unauthorized response

A successful authentication at any step will grant access and subsequent authentication methods will be skipped.

## Configuring Authentication Methods

### TLS Client Certificate Authentication

To enable certificate-based authentication, the server must be started with TLS and a certificate authority (CA) for client verification:

=== "Docker"

    ```sh
    # For FIPS mode (default build):
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms-fips:latest \
        --tls-cert-file server.crt \
        --tls-key-file server.key \
        --clients-ca-cert-file client_ca.cert.pem

    # For non-FIPS mode:
    # docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
    #     --tls-p12-file kms.server.p12 \
    #     --tls-p12-password password \
    #     --clients-ca-cert-file client_ca.cert.pem
    ```

=== "kms.toml"

    ```toml
    [tls]
    # For FIPS mode (default build):
    tls_cert_file = "server.crt"
    tls_key_file = "server.key"
    clients_ca_cert_file = "client_ca.cert.pem"

    # For non-FIPS mode:
    # tls_p12_file = "kms.server.p12"
    # tls_p12_password = "password"
    # clients_ca_cert_file = "client_ca.cert.pem"
    ```

The server extracts the username from the certificate's Subject Common Name (CN) field. Specifically, the Common Name of the client certificate subject is used directly as the username for authentication purposes. If the certificate is valid but does not contain a Common Name, authentication will fail.

Example of a subject with a CN field:

```text
C=FR, ST=Ile-de-France, L=Paris, O=Cosmian Tech, CN=john.doe@example.com
```

In this example, `john.doe@example.com` would become the authenticated username.

Clients must present a valid certificate signed by the specified authority.

### JWT Token Authentication

The server supports JWT tokens compatible with [OpenID Connect](https://openid.net/connect/). Configure JWT authentication with:

=== "Docker"

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
        --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms"
    ```

=== "kms.toml"

    ```toml
    [idp_auth]
    # issuer,jwks[,aud1[,aud2...]]  (jwks & audiences optional; any-of match when multiple)
    jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms,another_client_id"]
    ```

The JWT authentication provider configuration uses the format: `"JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE_1,JWT_AUDIENCE_2,..."` where:

- **JWT_ISSUER_URI**: The issuer URI of the JWT token (required)
- **JWKS_URI**: The JWKS (JSON Web Key Set) URI (optional, defaults to `<JWT_ISSUER_URI>/.well-known/jwks.json`)
- **JWT_AUDIENCE_n**: Zero or more allowed audiences (optional). If multiple are provided, validation succeeds if the token `aud` contains any of them (any-of). If omitted, audience validation is skipped.

Examples:

- `"https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience"`
- `"https://auth0.example.com,,my-app"` (JWKS URI will default)
- `"https://keycloak.example.com/auth/realms/myrealm,,"` (no audience, JWKS URI will default)
- `"https://issuer.example.com,https://issuer.example.com/jwks.json,frontend,cli"` (multi-audience)

JWT tokens must be passed in the HTTP Authorization header:

```text
Authorization: Bearer <JWT_TOKEN>
```

The server extracts the username from the token's `email` claim.

#### Supported Signing Algorithms

The KMS server automatically detects the signing algorithm from the JWT header (`alg` claim) and validates accordingly. The following signing algorithms from the [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken) library are supported; tokens using the `none` algorithm (for example, `Algorithm::None` / `alg: "none"`) are explicitly rejected:

| Category | Algorithms |
|----------|-----------|
| HMAC (symmetric) | HS256, HS384, HS512 |
| RSA PKCS#1 | RS256, RS384, RS512 |
| RSA-PSS | PS256, PS384, PS512 |
| ECDSA | ES256, ES384 |
| EdDSA | EdDSA (Ed25519) |

The algorithm is picked up from the token's `alg` header — no server-side configuration is required. The signing key must be published in the JWKS endpoint and matched by its `kid` claim.

#### PKCE Support

The KMS supports PKCE (Proof Key for Code Exchange) in two complementary ways:

- **CLI / API clients** (`ckms` and direct API usage): PKCE is used to obtain JWT tokens from the IDP. The client secret is **optional** — PKCE provides the security guarantee instead.
- **KMS Web UI**: PKCE is **mandatory**. The browser login flow always sends `code_challenge_method=S256`. The IDP application must be configured accordingly (see the [PKCE Authentication](pkce_authentication.md) guide for per-provider instructions).

For detailed information including required IDP settings, provider-specific examples, and troubleshooting, see the [PKCE Authentication](pkce_authentication.md) guide.

#### Multiple Identity Providers

To support multiple identity providers, repeat the JWT authentication provider parameter:

```sh
--jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms,another_client_id" \
--jwt-auth-provider="https://login.microsoftonline.com/<TENANT_ID>/v2.0,https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys,<CLIENT_ID>"
```

### API Token Authentication

API Token authentication uses a symmetric key stored in the KMS as the authentication token:

1. Generate a symmetric key and note its ID:

    ```sh
    ckms sym keys create
    ```

2. Export the key in base64 format:

    ```sh
    ckms sym keys export -k <SYMMETRIC_KEY_ID> -f base64 api_token.base64
    ```

3. Start the server with the API token ID:

=== "Docker"

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
        --api-token-id <SYMMETRIC_KEY_ID>
    ```

=== "kms.toml"

    ```toml
    [http]
    api_token_id = "<SYMMETRIC_KEY_ID>"
    ```

4. Configure the client to use the API token:

   ```text
   Authorization: Bearer <BASE64_TOKEN>
   ```

When using API token authentication, the authenticated user will be the default username.

## Force Default Username

If you want to enforce a consistent username regardless of the authentication method, use:

```sh
--force-default-username <true|false>
    Force using the default username regardless of the authentication method

    [env: KMS_FORCE_DEFAULT_USERNAME=]
    [default: false]
```

When enabled, the server still performs the authentication validation to ensure the client has valid credentials, but it ignores the username that would normally be extracted (such as the certificate's Common Name or JWT email claim) and instead maps all authenticated requests to the default username.

This feature is particularly useful in scenarios where:

- You want consistent user identity across all requests regardless of authentication method
- You prefer to manage access control independently from the authentication credentials
- You're transitioning between authentication methods but need to maintain consistent audit trails

When `force-default-username` is enabled with multiple authentication methods, the server will still cascade through the authentication methods, but always use the default username upon successful authentication.

## Multi-Factor Authentication Examples

### Example 1: Client Certificate and JWT Authentication

=== "Docker"

    ```sh
    # For FIPS mode (default build):
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms-fips:latest \
        --tls-cert-file server.crt \
        --tls-key-file server.key \
        --clients-ca-cert-file client_ca.cert.pem \
        --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"

    # For non-FIPS mode:
    # docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
    #     --tls-p12-file kms.server.p12 \
    #     --tls-p12-password password \
    #     --clients-ca-cert-file client_ca.cert.pem \
    #     --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"
    ```

=== "kms.toml"

    ```toml
    [tls]
    # For FIPS mode (default build):
    tls_cert_file = "server.crt"
    tls_key_file = "server.key"
    clients_ca_cert_file = "client_ca.cert.pem"

    # For non-FIPS mode:
    # tls_p12_file = "kms.server.p12"
    # tls_p12_password = "password"
    # clients_ca_cert_file = "client_ca.cert.pem"

    [idp_auth]
    # Empty audience example: leave trailing comma after jwks URL
    jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"]
    ```

In this configuration:

- Clients can authenticate using either a valid client certificate or a valid JWT token
- If both are provided, the certificate is checked first

### Example 2: JWT and API Token Authentication

=== "Docker"

    ```sh
    docker run -p 9998:9998 --name kms ghcr.io/cosmian/kms:latest \
        --jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs," \
        --api-token-id <SYMMETRIC_KEY_ID>
    ```

=== "kms.toml"

    ```toml
    [idp_auth]
    jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"]

    [http]
    api_token_id = "<SYMMETRIC_KEY_ID>"
    ```

- Clients can authenticate using either a valid JWT token or the API token
- JWT authentication is attempted first, followed by API token verification

## Common Identity Provider Configurations

### Google ID Tokens

```sh
--jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,"
```

### Auth0

```sh
--jwt-auth-provider="https://<your-tenant>.<region>.auth0.com/,,"
```

Note: the trailing `/` is required in the issuer URI. The JWKS URI will default to the well-known endpoint.

### Microsoft Entra ID (Azure AD)

```sh
--jwt-auth-provider="https://login.microsoftonline.com/<TENANT_ID>/v2.0,https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys,<CLIENT_ID>"
```

### Okta

```sh
--jwt-auth-provider="https://<OKTA_TENANT_NAME>.com,https://<OKTA_TENANT_NAME>.com/oauth2/v1/keys,<OKTA_CLIENT_ID>"
```

---

## Break-Glass / Local Authentication

> **Operational best practice**: always configure TLS client certificate authentication
> in addition to any OIDC/JWT-based method. The certificate acts as a *local,
> out-of-band* authentication path that remains available even when the identity
> provider is unreachable or misconfigured.

### Why you need a break-glass path

OIDC-based authentication depends on an external identity provider (Google, Entra,
Auth0, Okta…).  If that provider is:

- temporarily unavailable (outage, maintenance window, DNS failure),
- misconfigured (wrong tenant, expired signing key in JWKS),
- not reachable from the KMS host (network segmentation, firewall rule change),

then **no OIDC client can authenticate**, including the administrators who would
normally fix the misconfiguration.  A locally-issued client certificate is entirely
self-contained and does not contact any external service at validation time, so it
provides an independent recovery path — the *break-glass* account.

### Recommended setup

1. **Issue a break-glass administrator client certificate** from a local CA that you
   control.  Keep the private key and certificate in a hardware token or an offline
   vault rather than on the KMS host itself.

    ```bash
    # Create a local CA (done once; store securely)
    openssl genrsa -out local_ca.key 4096
    openssl req -x509 -new -nodes -key local_ca.key -sha256 \
        -days 3650 -out local_ca.crt \
        -subj "/CN=KMS Break-Glass CA"

    # Issue an administrator client certificate
    openssl genrsa -out admin_breakglass.key 2048
    openssl req -new -key admin_breakglass.key \
        -out admin_breakglass.csr \
        -subj "/CN=kms-admin@yourcompany.com"
    openssl x509 -req -in admin_breakglass.csr \
        -CA local_ca.crt -CAkey local_ca.key -CAcreateserial \
        -out admin_breakglass.crt -days 730 -sha256
    ```

2. **Start the KMS server with both authentication methods** enabled:

    ```toml
    [tls]
    tls_cert_file            = "server.crt"
    tls_key_file             = "server.key"
    clients_ca_cert_file     = "local_ca.crt"   # break-glass CA

    [idp_auth]
    jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience"]
    ```

    Most day-to-day logins will proceed via JWT; the client certificate path acts
    as a silent fallback and is only used when a certificate is actually presented.

3. **Use the break-glass certificate** from the `ckms` CLI when OIDC is unavailable:

    ```bash
    ckms --url https://kms.example.com:9998 \
         --cert admin_breakglass.crt \
         --key  admin_breakglass.key \
         sym keys list
    ```

4. **Protect the break-glass material** as you would any privileged secret:
    - Store the private key (`admin_breakglass.key`) in an HSM, air-gapped vault, or a
      hardware token such as a YubiKey.
    - Rotate the certificate before its expiry date.
    - Audit its use via server logs — every request authenticated by certificate will
      show the CN (`kms-admin@yourcompany.com` in the example) in the audit trail.

### Emergency recovery steps

If the primary OIDC authentication path fails:

1. Present the break-glass certificate to verify connectivity:

    ```bash
    curl --cert admin_breakglass.crt --key admin_breakglass.key \
         --cacert server_ca.crt \
         -X POST -H "Content-Type: application/json" -d '{}' \
         https://kms.example.com:9998/kmip/2_1
    # Expect HTTP 422 (not 401) — you are authenticated.
    ```

2. Diagnose the OIDC configuration with `ckms` or direct API calls.
3. Fix the OIDC misconfiguration and restart or reload the server configuration.
4. Once OIDC is restored, log the break-glass access in your incident management
   system and rotate the break-glass certificate if it was used in a potentially
   compromised environment.

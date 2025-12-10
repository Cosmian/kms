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
    # issuer,jwks,audience (jwks & audience optional)
    jwt_auth_provider = ["https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms"]
    ```

The JWT authentication provider configuration uses the format: `"JWT_ISSUER_URI,JWKS_URI,JWT_AUDIENCE"` where:

- **JWT_ISSUER_URI**: The issuer URI of the JWT token (required)
- **JWKS_URI**: The JWKS (JSON Web Key Set) URI (optional, defaults to `<JWT_ISSUER_URI>/.well-known/jwks.json`)
- **JWT_AUDIENCE**: The audience of the JWT token (optional, can be empty)

Examples:

- `"https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience"`
- `"https://auth0.example.com,,my-app"` (JWKS URI will default)
- `"https://keycloak.example.com/auth/realms/myrealm,,"` (no audience, JWKS URI will default)

JWT tokens must be passed in the HTTP Authorization header:

```text
Authorization: Bearer <JWT_TOKEN>
```

The server extracts the username from the token's `email` claim.

#### PKCE Support

The KMS authentication system supports PKCE (Proof Key for Code Exchange) for JWT authentication, which eliminates the need for client secrets. PKCE is a more secure OAuth 2.0 flow for public clients that don't need to store client secrets. The client generates a code verifier and code challenge pair, using the code challenge during authorization and the code verifier during token exchange.

This is particularly useful for:

- Mobile applications
- Single-page applications
- Desktop applications
- Any client that cannot securely store a client secret

When using PKCE, client secrets become optional in the OAuth2 configuration. The authorization server validates the code verifier against the previously provided code challenge, ensuring secure authentication without exposing client secrets.

For detailed information about implementing PKCE authentication with the KMS, see the [PKCE Authentication](pkce_authentication.md) guide.

#### Multiple Identity Providers

To support multiple identity providers, repeat the JWT authentication provider parameter:

```sh
--jwt-auth-provider="https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,cosmian_kms" \
--jwt-auth-provider="https://login.microsoftonline.com/<TENANT_ID>/v2.0,https://login.microsoftonline.com/<TENANT_ID>/discovery/v2.0/keys,<CLIENT_ID>"
```

### API Token Authentication

API Token authentication uses a symmetric key stored in the KMS as the authentication token:

1. Generate a symmetric key and note its ID:

    ```sh
    cosmian kms sym keys create
    ```

2. Export the key in base64 format:

    ```sh
    cosmian kms sym keys export -k <SYMMETRIC_KEY_ID> -f base64 api_token.base64
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

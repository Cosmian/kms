# Using PKCE Authentication with KMS

This document covers PKCE (Proof Key for Code Exchange) authentication with the Cosmian KMS, for two distinct contexts:

1. **CLI / API clients** — the `ckms` command-line tool and any direct API client uses PKCE to authenticate *against* the KMS server.  Client secrets are optional in this flow.
2. **KMS Web UI** — the browser-based UI uses PKCE to log users in *through* an OIDC Identity Provider (IDP).  PKCE is **mandatory** for the web UI flow and cannot be disabled.

## Overview

PKCE enhances the security of OAuth 2.0 authentication flows by eliminating the need for client secrets. This makes it particularly valuable for:

- Public clients that cannot securely store client secrets
- Mobile applications
- Single-page applications
- Desktop applications
- CLI tools

## Benefits of PKCE

- **Improved Security**: Eliminates the need to store and manage client secrets
- **Simplified Deployment**: Reduces configuration complexity for public clients
- **Protection Against CSRF & Authorization Code Interception**: The code verifier provides additional security
- **Standards Compliance**: Follows OAuth 2.0 and OpenID Connect standards

## How PKCE Works

1. **Authorization Request**:
   - Client generates a random code verifier and derives a SHA-256 code challenge from it
   - Client requests authorization with the code challenge (`code_challenge_method=S256`)
   - User authenticates and the IDP issues an authorization code

2. **Token Exchange**:
   - Client sends the authorization code and the original code verifier to the token endpoint
   - The IDP verifies that the code verifier matches the previously received challenge
   - The IDP issues access and ID tokens upon successful verification

---

## Web UI — Configuring Your Identity Provider

The KMS web UI login flow is a strict OIDC Authorization Code + PKCE flow.  Every parameter listed below is **hardcoded** by the server; your IDP application must be configured to match them exactly.

### Mandatory IDP Application Settings

| Requirement | Value the KMS sends | What to configure in the IDP |
|---|---|---|
| **Grant type** | `grant_type=authorization_code` | Enable the *Authorization Code* grant on the IDP application |
| **Token endpoint auth method** | Client credentials are sent as **form body fields** (`client_id` + optional `client_secret`) | Set the token endpoint authentication method to **`client_secret_post`** — not `client_secret_basic` (HTTP Basic), which is the default in many IDPs |
| **PKCE** | `code_challenge_method=S256` with a 32-byte random verifier | Enable PKCE on the application; S256 must be supported (plain is not accepted) |
| **Response type** | `response_type=code` | Ensure the *Authorization Code* response type is allowed |
| **Scopes** | `scope=openid email` | Allow both `openid` and `email` scopes; the `email` claim must be included in the returned ID token — without it the KMS cannot identify the user |
| **Audience (`aud`) claim** | Validated against the configured `client_id` (exact match) | The ID token's `aud` claim must **exactly equal** the `client_id` string. Some IDPs (e.g. Keycloak) add extra audience values or service-account names by default — disable this or add an audience mapper that restricts `aud` to the `client_id` only |
| **Redirect URI** | `<KMS_PUBLIC_URL>/ui/callback` | Register this exact URI as an allowed redirect/callback URI in the IDP application |

### Client Secret

The client secret is **optional**.  If configured, it is sent as a `client_secret` form field alongside the other token exchange parameters (`client_secret_post` method).  If your IDP requires a client secret, set it via:

```toml
[oidc]
ui_oidc_client_secret = "your-secret-here"
```

### Provider-Specific Notes

#### Auth0

- In the Auth0 dashboard, set **Token Endpoint Authentication Method** to `POST` (this corresponds to `client_secret_post`).
- Enable **PKCE** on the application (Applications → Settings → Advanced → Grant Types → tick *Authorization Code*).
- Under **Advanced Settings → OAuth**, set *OIDC Conformant* to ON.
- The `aud` claim in Auth0 ID tokens equals the `client_id` by default — no extra configuration needed.

#### Microsoft Entra ID (Azure AD)

- Register a **Single-Page Application** (SPA) or **Web** application.  Entra ID enables PKCE automatically for SPA registrations.
- The `aud` claim in Entra ID ID tokens equals the Application (client) ID — this matches the KMS expectation.
- Entra ID uses `client_secret_post` by default for web applications that have a secret; for SPA applications no secret is used.
- Required scopes: `openid`, `email` (or `profile` if `email` is provided via Microsoft Graph).

#### Keycloak

- In Client Settings, set **Access Type** to *confidential* (if using a secret) or *public* (secret-less).
- **Standard Flow Enabled**: ON.
- **Proof Key for Code Exchange Code Challenge Method**: S256.
- **Client Authentication** → set **Client Authenticator** to *Client Id and Secret* and **Token Endpoint Auth Method** to *POST* (`client_secret_post`).
- **Audience**: by default Keycloak may add the Keycloak-internal service account to the `aud` claim. Add a **Hardcoded audience** mapper (or **Audience resolve** mapper restricted to the client ID) to ensure `aud` contains only the `client_id`.

#### Google

- Google's OAuth2 endpoints officially support PKCE but still require a client secret.
- The ID token's `aud` equals the OAuth2 client ID.
- Required scopes: `openid`, `email`.

---

## CLI / API Client — PKCE with Optional Client Secret

The KMS CLI (`ckms`) and API clients use PKCE to authenticate against the KMS server.  The client secret is optional in this flow.

### Example: Entra ID

1. CLI configuration

    ```toml
    [http_config.oauth2_conf]
    client_id = "f052524e-7518-40e7-2579-219c0b48b125"
    authorize_url = "https://login.microsoftonline.com/612da4de-35c0-42de-ba56-174c4e562c96/oauth2/authorize"
    token_url = "https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/oauth2/token"
    scopes = [
        "email",
        "openid",
    ]
    # client_secret = <-- Not Set
    ```

2. KMS Server Configuration

    *Important*: on Entra ID, configure the redirect URL (`http://localhost:17899/authorization`) as Native/Desktop (not Single Page Application).

    ```toml
    [idp_auth]
    # issuer,jwks,audience (audience omitted)
    jwt_auth_provider = ["https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/v2.0,https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/discovery/v2.0/keys,"]
    ```

### Example: Auth0

1. CLI configuration

    ```toml
    [http_config.oauth2_conf]
    client_id = "OUfH4FuzDAW99Ck3R4Rb7ROziOZEalIH"
    authorize_url = "https://acme.eu.auth0.com/authorize"
    token_url = "https://acme.eu.auth0.com/oauth/token"
    scopes = [
        "email",
        "openid",
    ]
    # client_secret = <-- Not Set
    ```

    *Note*: Google's IdP officially supports PKCE but still requires a client secret.

2. KMS Server Configuration

    ```toml
    [idp_auth]
    jwt_auth_provider = ["https://acme.eu.auth0.com/,https://acme.eu.auth0.com/.well-known/jwks.json,"]
    ```

The client handles:

- Code challenge generation using SHA-256
- Automatic inclusion of PKCE parameters in authorization requests
- Code verifier inclusion during token exchange

### Server-Side Handling

The KMS server validates JWT tokens using JWKS (JSON Web Key Sets), which is compatible with PKCE-obtained tokens. The server:

1. Extracts the JWT token from the `Authorization: Bearer` header
2. Validates the token's signature using the JWKS endpoint
3. Verifies the token's claims (issuer, audience, expiration, etc.)
4. Extracts the user's identity from the `email` claim

---

## Transitioning from Client Secret to PKCE

1. Update your client code to use the PKCE-enabled client library
2. Configure your identity provider to support PKCE (see provider notes above)
3. Remove client secrets from your configuration (CLI flow only — the web UI always uses `client_secret_post` if a secret is present)

The server-side JWT validation remains unchanged.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Token exchange returns 401 | IDP requires `client_secret_basic` but the KMS sends `client_secret_post` — change the IDP application's token endpoint auth method |
| `Token validation failed: InvalidAudience` | The ID token `aud` does not exactly match `client_id` — see the Keycloak or provider-specific notes above |
| `Missing email claim` / user ID is empty | The IDP application does not include `email` in the ID token — enable the `email` scope and/or add an email claim mapper |
| IDP rejects the authorization request | The IDP application does not support `response_type=code` or PKCE with `code_challenge_method=S256` — enable these in the IDP application settings |
| `Missing PKCE verifier` on callback | The browser session was lost (e.g. the session cookie expired or the server restarted between login and callback) |

## References

- [OAuth 2.0 PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth.net PKCE Documentation](https://oauth.net/2/pkce/)
- [KMS Authentication Documentation](authentication.md)

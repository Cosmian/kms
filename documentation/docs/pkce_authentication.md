# Using PKCE Authentication with KMS

This document provides a comprehensive guide on using PKCE (Proof Key for Code Exchange) authentication with the Cosmian KMS.

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
   - Client generates a random code verifier and code challenge
   - Client requests authorization with the code challenge
   - User authenticates and server issues an authorization code

2. **Token Exchange**:
   - Client exchanges the authorization code and code verifier for tokens
   - Server verifies that the code verifier matches the challenge
   - Server issues access and ID tokens upon successful verification

## Implementation Details

### Client-Side Changes

The KMS client library now supports PKCE authentication with optional client secrets:

#### Example: Entra ID

1. CLI configuration

    ```toml
    [kms_config.http_config.oauth2_conf]
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

    _important_: on Entra ID, configure the redirect URL (<http://localhost:17899/authorization>) to be for Native/Desktop (not Single Page Application)

    ```toml
    [idp_auth]
    # issuer,jwks,audience (audience omitted)
    jwt_auth_provider = ["https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/v2.0,https://login.microsoftonline.com/612da4de-35c0-42de-f3c6-174b69062c96/discovery/v2.0/keys,"]
    ```

#### Example: Auth0

1. CLI configuration

    ```toml
    [kms_config.http_config.oauth2_conf]
    client_id = "OUfH4FuzDAW99Ck3R4Rb7ROziOZEalIH"
    authorize_url = "https://acme.eu.auth0.com/authorize"
    token_url = "https://acme.eu.auth0.com/oauth/token"
    scopes = [
        "email",
        "openid",
    ]
    # client_secret = <-- Not Set
    ```

    _Note_: the Google IdP officially support PKCE, but still requires a client secret.

2. KMS Server Configuration

    _important_: on Entra ID, configure the redirect URL to be for Native/Desktop (not Single Page Application)

    ```toml
    [idp_auth]
    jwt_auth_provider = ["https://acme.eu.auth0.com/,https://acme.eu.auth0.com/.well-known/jwks.json,"]
    ```

    The client code handles:

    - Code challenge generation using SHA-256
    - Automatic inclusion of PKCE parameters in authorization requests
    - Code verifier inclusion during token exchange

### Server-Side Handling

The KMS server validates JWT tokens using JWKS (JSON Web Key Sets), which is compatible with PKCE-obtained tokens. The server:

1. Extracts the JWT token from the Authorization header
2. Validates the token's signature using the JWKS endpoint
3. Verifies the token's claims (issuer, audience, expiration, etc.)
4. Extracts the user's identity from the email claim

## Transitioning from Client Secret to PKCE

If you're currently using client secrets for authentication, you can transition to PKCE by:

1. Updating your client code to use the new PKCE-enabled client library
2. Configuring your identity provider to support PKCE
3. Removing client secrets from your configuration

The server-side JWT validation remains unchanged, making this a seamless transition.

## Troubleshooting

Common issues and solutions:

- **Authentication Failed**: Ensure your identity provider supports PKCE and has PKCE enabled for your application
- **Token Validation Error**: Verify that the JWKS URI is correct and accessible
- **Missing Email Claim**: Ensure your identity provider includes the email claim in the ID token

## References

- [OAuth 2.0 PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [OAuth.net PKCE Documentation](https://oauth.net/2/pkce/)
- [KMS Authentication Documentation](authentication.md)
- [PKCE Authentication Example](pkce_auth_example.md)

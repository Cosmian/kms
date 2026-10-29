# Auth Verifier SAML single sign-on for the Web UI

## Features

### Server

- Add Web UI SAML single sign-on through the Authentication Verifier: the new `auth_verifier_saml_realm` setting
  advertises `AUTH_VERIFIER_SAML` in `GET /ui/auth_method`, adds `GET /ui/login_saml` to start sign-in, and accepts the
  Authentication Verifier `_ea_` session cookie on the KMIP, REST crypto and tokenize APIs and in `GET /ui/whoami`
- Revoke the Authentication Verifier session and expire its `_ea_` cookie on `GET /ui/logout`

### UI

- Add a **Single sign-on (SSO)** login option when the KMS advertises `AUTH_VERIFIER_SAML`: it starts the
  Authentication Verifier SAML sign-in at `/ui/login_saml`, and the SAML session user is shown in the header with a
  **Logout** button

## Security

- Accept the Authentication Verifier `_ea_` session cookie only when `auth_verifier_saml_realm` is configured and
  only for tokens issued for that realm; an explicit bearer token always takes precedence over the cookie
- Refuse to start when `auth_verifier_saml_realm` is set and `kms_public_url` does not use `https://`
- Refuse to start when `auth_verifier_saml_realm` is empty or the Authentication Verifier admin realm `_`, or when
  `auth_verifier_url` does not use `https://`
- Do not authenticate state-changing requests carried by the `_ea_` cookie unless their `Content-Type` is
  `application/json` or `application/octet-stream` (CSRF from same-site sibling origins)
- `GET /ui/logout` revokes the Authentication Verifier session and expires the `_ea_` cookie only for a valid session
  of the SAML realm; other cookie values are no longer forwarded
- Restrict the CORS policy of the `/ui` routes to `cors_allowed_origins` instead of any origin, so `GET /ui/whoami` is
  not readable from other origins

## Build

- Move the `authentication` submodule to the Authentication Verifier release that ships SAML single sign-on (0.5.0),
  and run the local SAML test stack with `cargo run -p auth_verifier --features saml` from that submodule
- Add the `test:ui-saml` mise task (also run by `test:ui` on non-FIPS with Docker): an end-to-end SAML single
  sign-on test (Keycloak IdP and nginx in Docker, Authentication Verifier SAML build and KMS on the host,
  Playwright in `ui/tests/e2e-saml/`)

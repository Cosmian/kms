## Features

### Server

- Add Web UI SAML single sign-on through the Authentication Verifier: the new `auth_verifier_saml_realm` setting
  advertises `AUTH_VERIFIER_SAML` in `GET /ui/auth_method`, adds `GET /ui/login_saml` to start sign-in, and accepts the
  Authentication Verifier `_ea_` session cookie on the KMIP, REST crypto and tokenize APIs and in `GET /ui/whoami`
- Revoke the Authentication Verifier session and expire its `_ea_` cookie on `GET /ui/logout`

## Security

- Accept the Authentication Verifier `_ea_` session cookie only when `auth_verifier_saml_realm` is configured and
  only for tokens issued for that realm; an explicit bearer token always takes precedence over the cookie
- Refuse to start when `auth_verifier_saml_realm` is set and `kms_public_url` does not use `https://`

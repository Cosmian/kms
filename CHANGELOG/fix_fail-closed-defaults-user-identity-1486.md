## Security

- Refuse to start without any authentication method on a non-loopback address unless `insecure_allow_unauthenticated = true` (`KMS_INSECURE_ALLOW_UNAUTHENTICATED=true`, development only; Helm `kms.insecureAllowUnauthenticated`). The Docker image, the packaged `kms.toml` and the Helm chart bind `0.0.0.0`, so they need an authentication method or the opt-in (COSMIAN-2026-070, [#1486](https://github.com/Cosmian/kms/issues/1486))
- Reject Auth Verifier bearer tokens of the admin realm (`_`) and, when `auth_verifier_realm` is set, of any other realm; the UI login enforces the same realm (COSMIAN-2026-071)
- Require `email_verified: true` for JWT and UI OIDC logins and identify users of the second and later `jwt_auth_provider` entries as `email#<jwt_issuer_uri>` (the UI OIDC identity too, unless its issuer is the first provider's). Access grants and role lists for those users must use that form; IdPs that omit `email_verified`, such as Microsoft Entra ID access tokens, are rejected (COSMIAN-2026-072)
- Reject with 401 any client certificate CN, JWT identity, Auth Verifier or SAML subject or UI session user equal to `default_username` (HTTP scopes and KMIP socket server); only the API token or the non-authenticated mode acts as `default_username`. Choose a `default_username` distinct from every real identity; provision with an API token (COSMIAN-2026-073)

## Bug Fixes

### Hardening
- Require the `exp`, `iss`, `aud` and `sub` claims in the UI OIDC `id_token`; a missing email is now a 401 instead of a 500

---

Refs #1486

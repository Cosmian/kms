## Security

- A server with no authentication method refuses to start on a non-loopback address unless `insecure_allow_unauthenticated = true` (`KMS_INSECURE_ALLOW_UNAUTHENTICATED=true`, development only); the packaged `kms.toml`, the Docker image and the Helm chart bind `0.0.0.0`, so they need an authentication method or the opt-in (Helm: `kms.insecureAllowUnauthenticated`) ([#1486](https://github.com/Cosmian/kms/issues/1486))
- Auth Verifier bearer tokens of the admin realm (`_`) are always rejected, and tokens must be issued for `auth_verifier_realm` when it is set
- A client certificate CN, JWT identity, Auth Verifier or SAML subject equal to `default_username` is rejected with 401; only the API token or the non-authenticated mode acts as `default_username`. Choose a `default_username` distinct from every real identity
- JWT and UI OIDC logins require `email_verified: true` (IdPs that omit it, such as Microsoft Entra ID access tokens, are rejected); users of the second and later `jwt_auth_provider` entries are identified as `email#<jwt_issuer_uri>`, so their access rights and role lists must use that form; the UI OIDC identity is namespaced the same way unless its issuer is the first provider's
- The UI OIDC `id_token` must carry the `exp`, `iss`, `aud` and `sub` claims; a missing email is a 401 instead of a 500

---

Closes #1486

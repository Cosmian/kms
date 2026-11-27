## Bug Fixes

### Google CSE
- Restrict the Google CSE privileged endpoints: `privilegedwrap` and `privilegedprivatekeydecrypt` now accept only the identity-provider tokens of the emails listed in the new `google_cse_privileged_users` option (`--google-cse-privileged-users`, `KMS_GOOGLE_CSE_PRIVILEGED_USERS`, empty by default), and `privilegedunwrap` accepts only such a user or a KACLS migration token. Operator action: list the administrators allowed to call these endpoints in `google_cse_privileged_users` ([#1485](https://github.com/Cosmian/kms/issues/1485))
- Accept a KACLS migration token on `privilegedunwrap` only when its `kacls_url` claim is this KACLS and its `resource_name` claim is the requested resource. The tokens of the KACLS listed in `google_cse_incoming_url_whitelist` no longer authenticate end users on the other CSE endpoints nor on the KMIP API ([#1485](https://github.com/Cosmian/kms/issues/1485))
- Sign the KACLS migration tokens with OpenSSL instead of the `rsa` crate, so the server performs no `rsa` private-key operation (RUSTSEC-2023-0071); correct the Marvin statements of `deny.toml`, `.cargo/audit.toml`, `sbom/openvex.json` and `SECURITY.md` accordingly ([#1485](https://github.com/Cosmian/kms/issues/1485))

### Hardening
- Refuse to start with `google_cse_disable_tokens_validation` or `azure_ekm_disable_client_auth` set unless the KMS is built with the `insecure` feature. Operator action: remove these options from production configurations ([#1485](https://github.com/Cosmian/kms/issues/1485))
- Stop answering cross-origin browser requests (permissive CORS) on the Microsoft DKE `/ms_dke` scope: its clients are native Office applications that send no `Origin` ([#1485](https://github.com/Cosmian/kms/issues/1485))

## Documentation

- Document `google_cse_privileged_users`, the migration token rules, and the `insecure` build requirement of the authentication bypass options.

---

Closes #1485

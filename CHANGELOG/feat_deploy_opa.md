# Changelog — feat_deploy_opa

## Features

- **deploy/opa**: add OPA + KMS docker-compose stack with `--disable-telemetry` on OPA ([#995](https://github.com/Cosmian/kms/pull/995))
- **deploy/rbac**: add full RBAC stack — step-ca TLS, Keycloak IDP, OPA, and KMS with JWT auth ([#995](https://github.com/Cosmian/kms/pull/995))
- **deploy/rbac**: add `keycloak/realm-export.json` with `kms` realm, 4 pre-configured users/roles, and audience mapper for `cosmian-kms` client ([#995](https://github.com/Cosmian/kms/pull/995))
- **deploy/rbac**: add `test.sh` smoke-test script covering token issuance, role validation, and authenticated KMS calls ([#995](https://github.com/Cosmian/kms/pull/995))

## Bug Fixes

- **jwt**: fix `UserClaim` serde deserialization failing with `missing field 'aud'` when tokens omit the audience claim — add `#[serde(default)]` to the `aud` field ([#995](https://github.com/Cosmian/kms/pull/995))

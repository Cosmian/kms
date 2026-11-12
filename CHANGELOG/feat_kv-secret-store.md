## Features

### API
- Add a Vault KV v2-compatible secret store backed by KMIP `SecretData` objects, served on `/<kv_mount>` and `/v1/<kv_mount>` so the `vault` and `bao` CLIs can use the KMS as a secrets backend: versioned writes, reads (`?version=N`), soft delete, metadata read, listing and hard delete ([#863](https://github.com/Cosmian/kms/issues/863))
- KV access rights are taken from the path's metadata object: write needs `Import`, read needs `Get`, metadata and listing need `Locate` (or `Get`), deletes need `Destroy`; a read-only grantee cannot replace or delete a secret ([#863](https://github.com/Cosmian/kms/issues/863))
- KV writes accept a positive `options.ttl`; a background sweep destroys expired versions. Destroyed versions (TTL expiry or hard delete) have their secret bytes wiped, as with KMIP `Destroy` ([#863](https://github.com/Cosmian/kms/issues/863))
- A KV path's metadata object lives at an identifier derived from the path with a server key (`kv_metadata_uid_key` in the database `parameters` table), so other KMIP users cannot occupy, hide or take over a path ([#863](https://github.com/Cosmian/kms/issues/863))
- Concurrent KV writes to the same path are serialized by a database compare-and-swap (SQLite, PostgreSQL, MySQL, Redis-Findex) and the loser gets `409 Conflict` ([#863](https://github.com/Cosmian/kms/issues/863))
- Add KMS-managed short-lived OpenSSH certificate issuance (`/v1/ssh/*`) and password generation (`/v1/secrets/password`) for external secret rotation. Subject and CA RSA keys must be at least 3072 bits ([#864](https://github.com/Cosmian/kms/issues/864))
- SSH roles take an `allowed_users` list: only the listed users and active Crypto Officers can sign with a role (an empty list restricts it to Crypto Officers) ([#864](https://github.com/Cosmian/kms/issues/864))
- The SSH endpoints and `/v1/secrets/password` refuse requests without a valid `X-Vault-Token` when the Vault token verifier is the only configured authentication method, instead of running them as the default user ([#864](https://github.com/Cosmian/kms/issues/864))
- The KV metadata route also answers the Vault `LIST` HTTP verb ([#863](https://github.com/Cosmian/kms/issues/863))
- KV writes accept `options.cas` (Vault check-and-set; `0` = create only) and the Cosmian `options.expected_owner`; writing a path owned by another identity needs an `Import` grant plus `expected_owner`. Every write is checked as a KMIP `Import`: under role enforcement an Operator needs the Create permission. A missing path and a forbidden path both answer `403 permission denied`; an empty list answers `404`; `version=0` reads the latest version; all malformed requests return the Vault `errors` envelope without echoing the body ([#863](https://github.com/Cosmian/kms/issues/863))
- KV TTL expiry is recorded per version and enforced on read even when the sweep is disabled; the sweep is bounded (1,000 versions per run), reports errors instead of dropping them and only destroys versions it can match to their path. Paths are limited to 1,000 versions and 10,000 list candidates with explicit `400` errors ([#863](https://github.com/Cosmian/kms/issues/863))
- KV listing shows a path only to its owner or to holders of a `Locate`/`Get` grant; secret JSON is zeroized when dropped; user-supplied system (`_`) tags are stripped on `Import` and rejected on `Create` (symmetric keys, secret data, PGP keys, DSA and Covercrypt user keys), so forged `_kv::` tags cannot grant or block access or fill the TTL sweep ([#863](https://github.com/Cosmian/kms/issues/863))
- UI session-cookie writes on the KV scopes must send `Content-Type: application/json` (or `application/octet-stream`), otherwise `415`; bearer, `X-Vault-Token`, mTLS and default-user callers are unaffected ([#863](https://github.com/Cosmian/kms/issues/863))
- `PUT /v1/ssh/config/ca` grants `Sign` on the CA key to the reserved SSH signing identity, so role users need no raw `Sign` right on the CA key; a missing role and a forbidden role both return `401`. HSM CA keys must be created sensitive. The configured CA key is re-validated at signing time, the certificate Key ID is `<requester>/<role>/<serial>`, and each issuance emits an `SSH_CERTIFICATE_ISSUED` audit event. SSH CA and role records are stored at identifiers keyed with a server secret ([#864](https://github.com/Cosmian/kms/issues/864))
- SSH and KV TTLs share one grammar (bare seconds or `s`/`m`/`h`/`d` suffix, positive) ([#864](https://github.com/Cosmian/kms/issues/864))

### Server
- New `[kv]` settings `kv_enabled` (default `false`), `kv_mount` (default `kv`) and `kv_ttl_check_interval_secs` (default `30`, `0` disables the sweep), also offered by the configuration wizard. A `kv_mount` that would shadow another route is refused at startup, including an empty value that resolves to the default mount ([#863](https://github.com/Cosmian/kms/issues/863))
- The KV scopes use the same authentication stack as the default scope, so session cookies and Auth Verifier bearer tokens are accepted on `/<kv_mount>` and `/v1/<kv_mount>` ([#863](https://github.com/Cosmian/kms/issues/863))
- The SSH record owner `cosmian-ssh-api-internal` is a reserved service identity that no externally authenticated user can take ([#864](https://github.com/Cosmian/kms/issues/864))
- Atomic compare-and-swap compares object versions (owner and not-destroyed are also checked) instead of serialized content on SQLite, PostgreSQL, MySQL and Redis-Findex. The server identifier key is computed once per instance; on Redis it is AES-256-GCM encrypted under `kms::parameter::<name>` ([#863](https://github.com/Cosmian/kms/issues/863))

### CLI
- Add `ckms kv put|get|list|delete` to read and write the KV secret store (`--mount`, `--ttl`, `--expected-owner`, `--from-file`, `--version`, `--field`, `--destroy`). `--from-file` preserves JSON types; request and response bodies are no longer traced ([#863](https://github.com/Cosmian/kms/issues/863))

### UI
- Add a "Secrets (KV)" page mirroring `ckms kv`, with a KV mount field, an expected-owner field, and loading a secret from a JSON file with JSON types preserved ([#863](https://github.com/Cosmian/kms/issues/863))

### Documentation
- Document the KV secret store, OpenBao KMIP auto-unseal against the KMS, SSH CA setup, certificate issuance and a database-agnostic external credential rotation pattern with recovery (PostgreSQL and MySQL examples)

## Build

- Bump `actix-web` to 4.18.2, `actix-http` to 3.20.3 and `actix-files` to 0.7.4 to pick up upstream advisory fixes
- Add the `ssh-key` 0.6.7 dependency for OpenSSH certificate encoding

## Testing

- Add the `test:interop:openbao`, `test:db:openbao` (PostgreSQL and MySQL) and `test:interop:openbao-kmip` MISE tasks driving the real OpenBao CLI against the KV store and the KMIP socket server, plus `test:interop:ssh-secrets` (SSH certificates, and secret rotation tested on PostgreSQL and MySQL)
- `tests::hsm::ssh_ca` now runs a real `sshd` against the HSM-signed certificates (accepted before expiry, refused after), and the rotation script checks that password generation requires authentication
- Add the `no-committed-credentials` pre-commit hook, which rejects well-known provider credential formats (AWS access key ids, GitHub, Slack and Vault tokens) outside `test_data/`
- Server and CLI tests now cover two-user denial on KV, CAS races on every database backend, protected Redis parameters, Auth Verifier/session auth on KV scopes, SSH role/caller authorization with a role user lacking raw `Sign`, and a real `sshd` expiry cycle with HSM CA keys; the interop scripts use complete `test_data` fixtures (`auth/vault_kv.toml`) and no fixed ports

---

Refs #863, #864

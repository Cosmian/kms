# 5.27.1 release notes (full text)

Full text of the `## [5.27.1]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.27.1] - 2026-09-08

### ⚡ Performance & Internal Optimizations

#### HSM & PKCS#11 Layer

- **HSM Session Pooling**: Introduced long-lived per-slot PKCS#11 session pooling (`checkout_session`/`checkin_session`) in `SlotManager`, eliminating `C_OpenSession`/`C_CloseSession` churn on every cryptographic operation and improving direct HSM throughput by ~35% (45k → 61k ops/s).
- **Async Worker Isolation**: Wrapped synchronous PKCS#11 FFI calls (`sign`, `verify`, `encrypt`, `decrypt`, `get_key_type`, `get_key_metadata`) in `tokio::task::spawn_blocking` within `BaseHsm` to prevent synchronous blocking of Tokio/Actix async runtime worker threads during HSM operations.
- **Redundant Key Metadata Lookup Removal**: Eliminated duplicate `get_key_type` queries in `HsmStore::sign` and `HsmStore::signature_verify`, reusing the `KeyMetadata` struct returned by `get_key_metadata`.
- **Concurrent Sign Scaling Regression Test**: Added `concurrent_sign_does_not_degrade` test in `cosmian_kms_base_hsm` and `softhsm2_pkcs11_loader` asserting throughput stability across thread scaling.
- *Note*: Multi-threaded client-side phase profiling during concurrency sweeps confirmed that over 99.9% of request latency under load is spent inside remote HTTP network round-trips (`kms_client_sign`), with negligible client-side lock or runtime contention. In co-located benchmarks (client, Actix server, and SoftHSM2 software crypto all competing for the same 24 physical cores on a single host), throughput scales linearly up to concurrency 4 and sustains elevated performance (concurrency 16 throughput remains well above single-thread baseline, satisfying the non-degradation threshold across all algorithms).

#### AWS XKS Authorization ([#1107](https://github.com/Cosmian/kms/pull/1107))

- **Key usage no longer restricted to the creator principal** ([#1093](https://github.com/Cosmian/kms/issues/1093)): the XKS proxy previously authorized each `Encrypt`/`Decrypt`/`GetKeyMetadata` request using the caller's `awsPrincipalArn`, and `CreateKey` granted usage only to the ARN that first created the key, breaking AWS's IAM-as-source-of-truth model for dynamic/numerous roles (CI/CD, Lambda, EC2, SSO/Control Tower). XKS operations now run under a stable, reserved KMS service identity (any correctly SigV4-signed request may use the key); `awsPrincipalArn` is retained for audit logging only. Keys stay owned by `default_username`, the reserved identity is granted only `Encrypt`/`Decrypt`/`GetAttributes` (least privilege), and legacy XKS keys are migrated to the reserved identity idempotently at server startup
- Close 5 reserved-identity and scope-containment gaps found in threat-model review: `CreateKey`'s idempotent-collision path now also requires the `aws-xks` tag before granting the reserved identity; externally-derived identities (OIDC, Auth Verifier JWT, mTLS CN, SPIRE SVID, UI session) are rejected if they collide with the reserved identity string; `crypto_officer.users` and `default_username` are rejected at startup if they collide with it; the legacy-key migration now grants on behalf of each key's actual persisted owner (not just the current `default_username`), queries direct (non-inherited) permissions so a wildcard `*` grant no longer masks a missing reserved-identity grant, propagates `retrieve_object` failures instead of silently skipping a key, and runs on a dedicated background thread so it no longer blocks HTTP server startup
- Reject `ReKey` (manual or via the auto-rotation scheduler) on `aws-xks`-tagged keys: rotating one in place would assign a new internal unique identifier that AWS KMS has no way to learn about, silently breaking the key. To rotate material behind an external key, create a new external key (CMK) in AWS KMS and destroy the old one via `ckms`/the Web UI once traffic has moved
- Warn at startup when AWS XKS is enabled and `crypto_officer.users` is empty, since AWS never calls back to list/rotate/revoke/destroy key material and a Crypto Officer must be configured for XKS keys to remain manageable through `ckms`/the Web UI

#### OCSP

- `GET /ocsp/{base64url-DER}` now accepts both padded and unpadded base64url input (RFC 6960 Appendix A does not mandate padding); previously well-formed requests from clients such as `openssl ocsp` were rejected with a spurious 422

### 🧪 Testing

- Add an AWS XKS CI test running against a remote server ([#1114](https://github.com/Cosmian/kms/pull/1114)), covering that the real-credentialed key owner can monitor/administer XKS keys end to end, that the reserved service identity stays unreachable for that purpose, and that `ReKey` on an `aws-xks`-tagged key is rejected
- Enable Proteccio and Crypt2Pay HSM backends in CI ([#1175](https://github.com/Cosmian/kms/pull/1175))

### ⚙️ Build

- Fix the `build/wasm` MISE task failing when the `ui/src/wasm` directory doesn't already exist before copying the package into it ([#1174](https://github.com/Cosmian/kms/pull/1174))
- Bump `pnpm/action-setup` from 6.0.10 to 6.1.0 ([#1176](https://github.com/Cosmian/kms/pull/1176))

### 📚 Documentation

- Document that lifecycle management of XKS keys (monitoring, revocation, destruction) is entirely an operator responsibility exercised by a designated Crypto Officer, and warn against ever granting the reserved AWS XKS service identity a real credential

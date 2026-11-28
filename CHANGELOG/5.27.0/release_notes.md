# 5.27.0 release notes (full text)

Full text of the `## [5.27.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.27.0] - 2026-09-05

### 🔒 Security

- **SSRF via attacker-controlled CRL Distribution Points in KMIP `Validate`/`Import`** (`COSMIAN-2026-021`, [GHSA-rwc8-xwm6-52xc](https://github.com/Cosmian/kms/security/advisories/GHSA-rwc8-xwm6-52xc)): the CRL-fetch client used by `Validate` and `Import` now rejects private/loopback/link-local IP ranges and internal hostnames before any network I/O, disables HTTP redirects, applies a 30-second timeout and a 10 MiB response cap, and no longer resolves filesystem-path or `file://` CRL Distribution Point values in production builds ([#987](https://github.com/Cosmian/kms/pull/987))
- **`Get` grant on wildcard uid `*` bypasses the Create/Import authorization gate** (`COSMIAN-2026-020`): `"*"` is now a reserved object identifier rejected at the database layer for every backend, closing a path where a `Get` grant on a colliding `"*"` object could be used to satisfy the `Create`/`Import` privileged-user/Crypto-Officer check ([#909](https://github.com/Cosmian/kms/issues/909), [#1151](https://github.com/Cosmian/kms/pull/1151))

### 🚀 Features

#### PKI — CRL & OCSP ([#987](https://github.com/Cosmian/kms/pull/987), [#1164](https://github.com/Cosmian/kms/pull/1164))

- Auto-inject a `crlDistributionPoints` extension (RFC 5280 §4.2.1.13) into issued certificates, pointing at the KMS's own public CRL endpoint, when `kms_public_url` is configured
- `GET /certificates/{issuer_id}/crl`: X.509 v2 CRL generation (RFC 5280 §5); `ckms certificates generate-crl` CLI command; Web UI support (Certificates → Certs → Generate CRL)
- `GET /public/certificates/{issuer_id}/crl`: new unauthenticated, cached CRL Distribution Point endpoint for PKI relying parties
- OCSP responder (RFC 6960, RFC 9654, RFC 5019, RFC 5280): `GET /ocsp/{base64url-DER}` and `POST /ocsp/`, configurable nonce policy, delegated responder signing key, CA key-compromise cascade, new `--ocsp-*` CLI flags / `[ocsp]` TOML section
- KMIP `Validate`: internal KMS-state cascade now also catches a compromised self-signed root CA, which has no CRL Distribution Point of its own
- PQC key export (ML-KEM, ML-DSA, SLH-DSA) as `KeyFormatType::Raw` via on-the-fly PKCS#8→Raw conversion
- Extended vendor-extension `RevocationReasonCode` coverage: `CertificateHold`, `RemoveFromCRL`, `AaCompromise` (KMIP 2.1 §11.48 8XXXXXXX range)

#### Split-Key Ceremony & Two-Role RBAC ([#991](https://github.com/Cosmian/kms/pull/991), [#1146](https://github.com/Cosmian/kms/pull/1146))

- Two-role RBAC (`Operator` / `CryptoOfficer`) replaces the flat `privileged_users` list, aligned with FIPS 140-3 / NIST SP 800-57 Pt 2 §4.8; unknown users default to `Operator` (fail-secure)
- `CreateSplitKey` / `JoinSplitKey` KMIP 2.1 (and 1.4) operations implementing an XOR n-of-n secret-sharing ceremony, with optional AES-KW (RFC 5649) share wrapping
- Self-revoke and peer-revocation endpoints for the active Crypto Officer, without a server restart (NIST SP 800-152 FR:6.119)
- CLI: `ckms access-rights crypto-officer status`/`disable`, new `create-split-key` subcommand
- Web UI: Crypto Officer status dashboard, Split-Key/Join-Split-Key dialogs (XOR n-of-n only), refreshed dark/light theme palette for WCAG AA contrast

#### Web UI Internationalization ([#1113](https://github.com/Cosmian/kms/pull/1113), [#1124](https://github.com/Cosmian/kms/pull/1124))

- Bilingual English / Simplified Chinese UI via `react-i18next`, plus a third French locale, covering the sidebar, layout, and every action form
- Cryptographic algorithm/standard names (`RSA`, `AES`, `EC`, `PQC`, `Covercrypt`, `MAC`, `FPE`, `HSM`, `ML-KEM`, `ML-DSA`, `SLH-DSA`, …) are kept untranslated across all locales; business/user-facing copy is translated
- `localeRegistry.ts` ([#1119](https://github.com/Cosmian/kms/pull/1119)): single source of truth for per-locale configuration (label, Ant Design/`dayjs` locale, browser-language matcher, translation bundle), so adding a future locale is a single registry entry plus its JSON bundle

#### Authentication

- Web UI login page now supports multiple configured authentication methods at once: the highest-priority method is shown as the primary action and the rest as a secondary control; priority order is OIDC (JWT) > username/password (auth-verifier) > client certificate. `GET /ui/auth_method` gained an ordered `auth_methods` array; the existing `auth_method` field is kept for backward compatibility ([#1117](https://github.com/Cosmian/kms/pull/1117))
- `ckms login approle`: Vault-compatible AppRole login for automation/service accounts, exchanging a `role_id` (+ optional `secret_id`) for a token via `POST /v1/auth/approle/login`
- `ckms login cosmian`: Cosmian authentication-server login (`POST /login?realm=<realm>` with HTTP Basic credentials); server gained a matching `CosmianAuth` bearer-token validation middleware and a `/ui/login_as` Web UI login route using the same session-cookie (BFF) pattern as OIDC
- BFF (Backend for Frontend) rework of the Web UI OIDC flow: discovery document and JWKS cached at server startup with refresh-on-miss; only `user_id` is stored in the session cookie; `id_token` never reaches the browser; `/ui/token` renamed to `/ui/whoami`

### 🐛 Bug Fixes

#### PKI / CRL

- CRL freshness (`nextUpdate`, RFC 5280 §6.3/§5.1.2.5) now hard-enforced; HTTP(S) CRLs with an unverifiable signature are rejected instead of only warned about ([#987](https://github.com/Cosmian/kms/pull/987))
- Fixed revocation reason not being persisted in an object's own attributes when revoking a certificate or key ([#987](https://github.com/Cosmian/kms/pull/987))
- `file://` CRL Distribution Points were incorrectly treated as web URLs and skipped during validation ([#987](https://github.com/Cosmian/kms/pull/987))
- Fixed a KMIP 1.4 `RevocationReason` TTLV deserialization failure caused by the post-serialization normalizer collapsing structured `AttributeValue` nodes into scalars ([#987](https://github.com/Cosmian/kms/pull/987))
- CRL Number is now seeded from `max(unix_timestamp, highest stored CRL Number)` across server restarts, restoring RFC 5280 §5.2.3 monotonicity ([#987](https://github.com/Cosmian/kms/pull/987))
- `generate_crl`: the issuer's `cRLSign` `keyUsage` bit is now enforced (RFC 5280 §4.2.1.3), since OpenSSL's `X509_CRL_sign()` does not check it itself ([#987](https://github.com/Cosmian/kms/pull/987))
- MySQL `get_max_crl_number` no longer panics on an empty `crls` table ([#987](https://github.com/Cosmian/kms/pull/987))

#### OCSP Responder ([#1164](https://github.com/Cosmian/kms/pull/1164))

- Hardening fixes from an internal STRIDE-A threat-model review, applied before release: unbounded batch requests capped at 128 queries; response cache now keyed on the actual per-request nonce presence (previously never activated under the documented default policy); cache bypassed immediately on CA compromise or certificate revocation; an independently-compromised delegated signing key is refused; delegated signer certificates now require `extKeyUsage: OCSPSigning`; unsigned `malformedRequest` returned for oversized GET-encoded requests
- Fixed the issuer-hash digest algorithm being hardcoded to SHA-256, rejecting valid requests using a different `hashAlgorithm` (e.g. the standard `openssl ocsp` client's SHA-1 default)
- Fixed the nonce extension being triple-wrapped, breaking RFC 9654 nonce verification in standard clients
- `nonce_policy = required` now returns a proper unsigned `malformedRequest` OCSP response instead of a raw HTTP 500
- Fixed an intermittent `unknown` status for freshly-issued certificates caused by inconsistent leading-zero-byte handling between the database and crypto layers' serial-number hex extraction

#### PKCS#11 / OpenSSH

- Backend fallback when a private key referenced by `CKA_ID` is not yet in the in-memory object store, fixing an OpenSSH "cannot find private key" regression left by the class-aware `CKA_ID` lookup fix in `5.26.0` ([#1111](https://github.com/Cosmian/kms/issues/1111), [#1076](https://github.com/Cosmian/kms/issues/1076), [#1112](https://github.com/Cosmian/kms/pull/1112))

#### Database

- Release PostgreSQL pool connections before retry back-off waits, instead of holding them idle ([#1027](https://github.com/Cosmian/kms/issues/1027), [#1152](https://github.com/Cosmian/kms/pull/1152))
- Fixed a `PgPool` startup deadlock with a single-connection pool (`max_connections = 1`) and database clearing enabled ([#1152](https://github.com/Cosmian/kms/pull/1152))
- PostgreSQL deadlock/serialization-failure retry detection now preserves the SQLSTATE code instead of collapsing every database error to a generic message ([#1152](https://github.com/Cosmian/kms/pull/1152))

#### Web UI / CORS

- `kms_public_url` is now automatically added to the in-RAM CORS allow-list when `cors_allowed_origins` is not explicitly configured, fixing the Web UI becoming inaccessible on upgrades where only `kms_public_url` was set ([#987](https://github.com/Cosmian/kms/pull/987))

#### Docker / Nix packaging ([#1133](https://github.com/Cosmian/kms/pull/1133))

- Added the missing `grep` binary to the `kms`/`kms-fips` Docker images, fixing a silently-failing CA-bundle validity check ([#1132](https://github.com/Cosmian/kms/issues/1132))
- Fixed `fakeRootCommands` failing with "Permission denied" on Nix-store symlinked directories during Docker image packaging

### 🧪 Testing

- CRL/OCSP: end-to-end CRL validation lifecycle test; RFC 5280 §5 CRL compliance suite (partial revocation, cross-CA isolation, all revocation-reason codes, validity period, required extensions); black-box `mise run test:ocsp` and `mise run test:pki-revocation` customer-facing suites driving `ckms`/`openssl ocsp`/`curl` directly, wired into CI for both FIPS and non-FIPS ([#987](https://github.com/Cosmian/kms/pull/987), [#1164](https://github.com/Cosmian/kms/pull/1164))
- Split-key / RBAC: ceremony vector tests (2-of-2, 3-of-3, failure scenarios), CLI RBAC permission-matrix tests, and Playwright RBAC-flow E2E smoke tests ([#991](https://github.com/Cosmian/kms/pull/991))
- PQC export-as-Raw round-trip regression tests for ML-DSA-44, ML-KEM-768, SLH-DSA-SHA2-128s ([#987](https://github.com/Cosmian/kms/pull/987))

### ♻️ Refactor

- `crate/crypto` now depends directly on `foreign-types` instead of the internal `foreign-types-shared` sub-crate ([#987](https://github.com/Cosmian/kms/pull/987))
- CRL generation's Authority Key Identifier extension is now built manually per RFC 5280 §5.2.1 instead of via OpenSSL's `X509V3_EXT_nconf_nid`, which fell back to a non-FIPS-approved SHA-1 EVP call when the issuer certificate lacked a `subjectKeyIdentifier` ([#987](https://github.com/Cosmian/kms/pull/987))
- Extracted `verify_cosmian_jwt_subject()` so the bearer-token `CosmianAuth` middleware and the new `/ui/login_as` handler share JWT/JWKS trust logic instead of duplicating it

### ⚙️ Build

- Bump the `authentication` git submodule, picking up the authentication server's `0.4.0` release changelog; no `auth_verifier`-related KMS code changes were required (verified via `cargo test -p cosmian_kms_server auth_verifier`)
- Windows CI: resolve `vcpkg`/Ninja lookup failures on runners where Ninja is not on `PATH` by default, with a Chocolatey fallback ([#991](https://github.com/Cosmian/kms/pull/991))

### 📚 Documentation

- PKI: documented CRL/OCSP configuration and status mapping, added a manual `openssl ocsp` verification runbook, and split "PKI Support" navigation into Introduction / Revocation & CRL Distribution / OCSP Responder pages ([#1164](https://github.com/Cosmian/kms/pull/1164))
- Added Delta CRLs (RFC 5280 §5.4) to the documented "Not supported" PKI features ([#987](https://github.com/Cosmian/kms/pull/987))
- Key ceremony guide (two-role RBAC, XOR n-of-n, NIST references) and an updated authorization/permission-evaluation reference ([#991](https://github.com/Cosmian/kms/pull/991))
- Added a manual end-to-end test plan for the new Web UI Cosmian-authentication-server login flow, since there is no mock harness for a live external auth server in this repo
- `.github/instructions/rust.instructions.md`: added a mandatory four-layer test-coverage rule (unit, DB persistence, functional, security/non-regression) for every new Rust feature, using the CRL test suite as the reference implementation

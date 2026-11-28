# 5.29.0 release notes (full text)

Full text of the `## [5.29.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.29.0] - 2026-10-28

### 🔒 Security

- Enforce read-only attribute rules for client updates: `SetAttribute` returns `Read_Only_Attribute` (HTTP 422) for `UniqueIdentifier`, `ObjectType`, `CryptographicLength`, `CertificateLength`, `Digest`, `InitialDate`, `LastChangeDate`, `OriginalCreationDate` and `Fresh`, which were previously accepted and persisted (COSMIAN-2026-030, [#1004](https://github.com/Cosmian/kms/issues/1004), [#1259](https://github.com/Cosmian/kms/pull/1259))
- Refuse client edits of every attribute that KMIP 2.1 marks read-only (`CryptographicAlgorithm`, `CryptographicDomainParameters`, `KeyFormatType`, `CertificateType`, the X.509 subject/issuer, the lifecycle dates, …) on `AddAttribute`, `SetAttribute`, `ModifyAttribute` and `DeleteAttribute`, and check stored keys against the `[kmip.policy]` allowlists from the key material when an attribute is missing (curve read from the key, wrapped keys of unknown curve refused, stored `CryptographicParameters` checked on use), so stripping or relabelling attributes no longer escapes the algorithm policy (COSMIAN-2026-044). **Upgrade action:** under a curve allowlist, imported PKCS#8 EC and Ed25519 keys are now curve-checked (an imported Ed25519 key is refused by the `DEFAULT` policy, like a created one)
- Apply the role check and the request-time KMIP algorithm policy to every operation of a batched KMIP `RequestMessage`, as on the single-operation path, and the policy to a `MAC` request whose root tag is spelled `Mac`: batched requests skipped the policy, so any user could create keys and send parameters that `[kmip.policy]` forbids, and a user who is not a Crypto Officer could run a batched `CreateSplitKey` (`JoinSplitKey` stays open to every user by design) (COSMIAN-2026-047). **Audit action:** after the upgrade, `Locate` the keys whose algorithm, length or curve the policy forbids, created through a `RequestMessage` before it, and revoke or re-key them
- Require HSM admin rights or an explicit `Decrypt` grant on an HSM key to unwrap with it, on `Import` and when reading a stored key wrapped by it, and an explicit `Encrypt` grant (instead of `Get`) to wrap with it on `Create`, `Import` or `Export`; authorize reads served from the shared unwrapped-object cache exactly like uncached reads. The 5.13.0 fix of COSMIAN-2025-009 missed these paths, so any user allowed to `Import` could decrypt arbitrary data with any HSM key (COSMIAN-2026-041). The configured `key_encryption_key`, in the HSM or in the database, still unwraps keys at rest for every user. **Upgrade action:** grant `Decrypt` on the HSM key to the owners of keys wrapped by a non-KEK HSM key, and `Encrypt` to the users who create, import or export keys wrapped by it
- Stop the server `key_encryption_key` from acting as a decryption oracle: `Import` and `Register` of a key block already wrapped by the KEK (or its `_pk` alias, its uid written as an integer, or a public key or certificate whose `PrivateKeyLink` points at the KEK), and an `Import` unwrapping with the KEK, are accepted only from users allowed to decrypt with the KEK (HSM admins or explicit `Decrypt` grantees for an HSM KEK; the existing owner/grant rule for a database KEK); everyone else gets `Invalid_Request`. Plain imports are still wrapped by the KEK at rest, and the at-rest exemption applies only when the stored key block names the KEK uid or `<kek>_pk` literally: a key reached through a `PrivateKeyLink` must be a private key and needs the usual grant (COSMIAN-2026-046). **Upgrade action:** to import KEK-wrapped key blocks (for example client-side generated keys wrapped with KMIP `Encrypt` under the KEK, or a KEK-wrapped export), the importing user needs HSM admin rights or a `Decrypt` grant on the KEK
- Check the caller's grant on the selected key when a bare keyset UID (for example `hsm::<slot>::<name>`) is used for `Encrypt`, `Sign`, `MAC`, …; callers with no grant get `Item_Not_Found` (COSMIAN-2026-042)
- Count on a CA's CRL and in its OCSP answers only the certificates it issued (issuer name and signature checked against the CA, then, among copies sharing a serial, those owned by the CA owner or by a user allowed to issue with the CA key), with a revoked copy winning over an active one: any user allowed to `Import` could link a forged or copied certificate to a CA and so put another certificate's serial on its CRL or make OCSP answer `good` for a revoked certificate (COSMIAN-2026-048). This release extends CRL and OCSP signing to HSM-backed CAs with the same checks. **Upgrade notes:** if no copy of a serial is owned by an authorized user (for example after the issuer lost the grant), all copies count again; each CRL generation now reads every certificate linked to the CA once, which can be slow for a CA with a very large number of certificates; check the CRLs published before the upgrade for serials the CA owner did not revoke
- Refuse Authentication Verifier tokens (bearer or `_ea_` cookie) whose session has ended through logout, admin revocation or idle timeout: after the signature check, the KMS asks `GET {auth_verifier_url}/whoami`, through the `[proxy]` settings when configured, and trusts a live answer for 30 s (COSMIAN-2026-043). **Upgrade action:** the KMS must reach `auth_verifier_url` at runtime; requests carrying an Authentication Verifier token are refused while it is unreachable, and CLI bearer tokens now expire with the realm idle timeout
- Stop returning Sensitive Opaque Objects and Split Keys in plaintext when the `Get`/`Export` request carries a `KeyWrappingSpecification`, which the export path never applies to these types: a Sensitive object is refused with `Sensitive`, a non-sensitive one with `Key_Wrap_Type_Not_Supported` (COSMIAN-2026-045). Clients must export these objects without a wrapping specification
- Stop `Get`/`Export` of a key with `Fresh = true` from writing the auto-unwrapped key back to the database when `default_unwrap_types` is set (COSMIAN-2026-031)
- Harden the KMIP socket server: close connections idle for more than 120 s, abort TLS handshakes not completed within 10 s in total (however slowly the client sends), accept at most 1,024 concurrent connections (clients that keep a connection open between requests must reconnect) and reject messages above 64 MiB before allocation (COSMIAN-2026-032); apply the HTTPS mTLS client-certificate CN checks (no empty, `*` or reserved CN, whitespace trimmed) (COSMIAN-2026-033); reject a client certificate with `CN=[aws-xks-service]` (COSMIAN-2026-040)
- Verify each JWT only against the JWKS of its issuer, for every identity provider, whitelisted Google CSE KACLS and Google CSE token issuer, and refresh the keys of the token's own issuer (Google CSE authorization keys included) after a key rotation, at most once every 60 s (COSMIAN-2026-034)
- Close the Google CSE `rewrap` SSRF bypass: no redirects, IPv6 and IPv4-mapped literals checked, host resolved, checked and pinned (COSMIAN-2026-035)
- Fail KMIP requests above 10,000 batch items with `Invalid_Message`, and reject `DeriveKey` PBKDF2 with fewer than 1 or more than 10,000,000 iterations and RSA key generation above 16,384 bits (COSMIAN-2026-036); return `Item_Not_Found` instead of `Permission_Denied` from crypto operations (`Encrypt`, `Decrypt`, `Sign`, `MAC`, …) on a key the caller has no grant on, so the existence or state of keys the caller may not use is not revealed (COSMIAN-2026-037)
- Mask the AWS XKS SigV4 secret access key in startup and debug configuration logs (COSMIAN-2026-038)
- Apply the KMIP-scope CORS policy (same-origin plus `cors_allowed_origins`) to `/v1/crypto/*`, `/tokenize/*` and `/ui/*` (so `GET /ui/whoami` is no longer readable from other origins), and require `Content-Type: application/json` on `POST /kmip/2_1` (other types, and an invalid UTF-8 body, return HTTP 422), so other origins of the same site cannot reuse a logged-in UI session (COSMIAN-2026-039)
- Enforce `sslmode` and certificate verification on `PostgreSQL` connections (COSMIAN-2026-029, [#1262](https://github.com/Cosmian/kms/pull/1262)): `require`, `verify-ca` and `verify-full` fail at startup when TLS cannot be established and unknown values are rejected, so check that the `PostgreSQL` server accepts TLS before upgrading; `sslrootcert` trusts only the given CA, `verify-ca` no longer checks the hostname and, as in libpq, refuses to start without `sslrootcert` (add it to `verify-ca` URLs, or use `verify-full`)

### 🚀 Features

#### EST & SCEP Enrollment ([#871](https://github.com/Cosmian/kms/issues/871))

- Add EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)): `cacerts`, `csrattrs`, `simpleenroll` (TLS client certificate or HTTP Basic bootstrap) and `simplereenroll`; enable with `[est] est_enabled = true` and `est_ca_uid`; `csrattrs` answers in DER with `extensionRequest` and one key type, `id-ecPublicKey` with the first `allowed_ec_curves` entry of the template (or `rsaEncryption` with `min_rsa_key_bits` when no curve is listed), as a hint only: enrollment still accepts every key the template allows; a CSR carrying a `challengePassword` must hold the RFC 7030 §3.5 tls-unique value of its TLS 1.2 connection, otherwise it is refused with `400` (including over TLS 1.3, where tls-unique is undefined) ([#1257](https://github.com/Cosmian/kms/pull/1257))
- Add SCEP ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)) at `/scep`: `GetCACaps`, `GetCACert` and `PKIOperation` (`PKCSReq`, `RenewalReq`); enable with `[scep] scep_enabled = true`, `scep_ca_uid` and `scep_challenge_password`; only AES-128/192/256-CBC envelopes with RSA key transport and SHA-256/384/512 signer digests are accepted. FIPS builds accept only RSAES-OAEP key transport and answer RSA signers with RSAES-OAEP: PKCS#1 v1.5 clients, including the native macOS client, need the non-FIPS build
- Add per-endpoint certificate templates (`[templates.<name>]`, `est_template`/`scep_template`): RSA size, EC curves, EKUs, validity and anchored regular expressions for the subject CN and DNS/e-mail/UPN SANs; a CSR SAN without a matching `san_dns_regex`/`san_email_regex`/`san_upn_regex` is refused (422/`badRequest`), and iPAddress and URI SANs need `allow_any_identity = true` and no `san_*_regex`
- Issue EST/SCEP certificates as the reserved identity `[enrollment-service]`, mark every enrolled certificate with a `certificatePolicies` entry (`1.3.6.1.4.1.16376.9.2.1`) that mTLS and the KMIP socket refuse for authentication, and validate CSRs fail-closed (`msExtReq`, undecodable or repeated `extensionRequest`). **Setup action:** `ckms access-rights grant "[enrollment-service]" -i <ca cert uid> certify`, the same for the CA private key, and `create` when `crypto_officer_users` is configured
- Protect enrollment: lockout with `429` + `Retry-After`, at most 16 concurrent enrollments, 64 KiB bodies, SCEP replay protection, fixed error messages, masked secrets, refusal of DES/3DES/RC2 envelopes and SHA-1/MD5 signatures, renewal checks that count only certificates owned by the CA owner (a copy carrying a forged `_enrolled_serial` tag cannot revive a revoked certificate), and every attempt logged and audited ([#1257](https://github.com/Cosmian/kms/pull/1257))
- Accept dotted OIDs in extended-key-usage entries of X.509 extension files
- Add `mise run test:scep-interop`, `test:est-interop` and `test:scep-apple` black-box tests

#### Audit Logging

- Add a `PostgreSQL` audit backend as an alternative to the JSONL file (`--audit-postgres-url`, `--audit-instance-id`): session advisory lock per instance, append-only `kms_audit_events`, hardened deployments with `SELECT`/`INSERT` only, and the audit database must differ from the object database
- Always start the `PostgreSQL` audit backend: on content corruption, seal the latest chain generation as evidence and start a new one with an `audit:reanchor` event carrying a SHA-256 evidence digest; connectivity, TLS, schema and lock failures still abort startup
- Record a final `audit:size-cap-reached` event in the file backend and report a row that does not chain to its predecessor as `broken_link`
- Honor `sslmode=verify-ca`/`verify-full`, `sslrootcert`, `sslcert` and `sslkey` on the audit connection, and refuse to start when the four append-only triggers are missing in a no-DDL deployment
- Read PostgreSQL audit chains with `ckms audit export`/`verify` through `--audit-postgres-url` (optional `--audit-instance-id`) in bounded pages ([#1189](https://github.com/Cosmian/kms/pull/1189))
- Fix `ckms audit` flags: reject `--audit-instance-id` with a file source, fail `export` and `verify` on an instance with no events, verify every chain generation, include instance and generation in PostgreSQL exports, and stop reading `KMS_AUDIT_INSTANCE_ID`
- Make the `PostgreSQL` audit seal-and-roll write atomic and serialize concurrent schema bootstrap across instances
- Read the audit client address from the rightmost `X-Forwarded-For` entry that is not a trusted proxy instead of the leftmost one, which the client controls; update log/SIEM correlation rules
- Generalize the audit writer/store to an `AuditSink` interface shared by the file and `PostgreSQL` backends
- Add a live `PostgreSQL` audit suite (restricted writer role, tamper → restart → seal-and-roll), run in CI
- Reorganize the Audit & SIEM docs (shared overview, file and `PostgreSQL` backend pages, audit events reference, audit tables in the database tables reference) and document CEF export and read-only collection accounts; state that `--audit-failure-mode reject` only governs queue admission and that the SHA-256 chain is unkeyed, so detecting a privileged rewrite needs a chain head (`id`, `row_hash`) exported outside the database
- Upgrading from 5.28.0 needs no audit migration: the `PostgreSQL` audit tables are new and created on first connection, file audit logs keep their hash-chain format, and every new configuration key is optional

#### OpenPGP

- Add the `ckms pgp` subcommand group (non-FIPS): `keys create` (Ed25519, RSA 2048/3072/4096), `keys revoke`, `keys destroy`, `export`, `import`, `encrypt`, `decrypt`, `sign` and `sign-verify`, with `pgp-secret-binary` and `pgp-public-binary` GnuPG-compatible exports; transferable keys are version 4 or 6 only, and building requires Rust 1.88 (rPGP 0.21.0) ([#1240](https://github.com/Cosmian/kms/pull/1240))
- Add the Web UI OpenPGP section (create, encrypt, decrypt, sign, verify, armored and binary `.gpg` export) with WASM bindings, FIPS filtering, `en`/`fr`/`zh-CN` translations and Playwright coverage
- Generate keys on the blocking thread pool, decrypt DEFLATE-compressed messages with the decompressed plaintext capped at 64 MiB, preserve signed encryption-subkey metadata, and use for `Encrypt` and `SignatureVerify` only subkeys bound to the primary key by a verified binding signature (and back-signature for signing subkeys), not revoked by the primary key and not past their Key Expiration Time ([RFC 9580](https://www.rfc-editor.org/rfc/rfc9580)); a certificate that is key-revoked or whose primary key has expired is refused by `Encrypt` (`OpenPGP certificate is revoked`/`expired`) and gives `Invalid` on `SignatureVerify`, so import an up-to-date certificate
- Run RSA private-key operations on OpenPGP keys (decrypt with implicit rejection, sign, key generation and self-signature) in OpenSSL instead of the `rsa` crate (RUSTSEC-2023-0071)
- Refuse `Get`/`Export` of a Sensitive OpenPGP key with `Sensitive` even when a `KeyWrappingSpecification` is given, and answer a wrapping request with `Key_Wrap_Type_Not_Supported`: OpenPGP keys are never wrapped on export
- Discover RSA keys and certificates tagged `gnupg-card` (override with `COSMIAN_PKCS11_GNUPG_KEY_TAG`) so `gnupg-pkcs11-scd` can expose them as a GnuPG smartcard
- Add a 24-test GnuPG interoperability matrix, `.mise/scripts/test/test_gnupg.sh` and a `gnupg` CI job

#### Web UI SAML Single Sign-On

- Add Web UI SAML single sign-on through the Authentication Verifier: the new `auth_verifier_saml_realm` setting advertises `AUTH_VERIFIER_SAML` in `GET /ui/auth_method`, `GET /ui/login_saml` starts sign-in, the UI shows a **Single sign-on (SSO)** button and the session user with a **Logout** button, and the Authentication Verifier `_ea_` session cookie is accepted on the KMIP, REST crypto and tokenize APIs and in `GET /ui/whoami` ([#1252](https://github.com/Cosmian/kms/pull/1252))
- Accept the `_ea_` cookie only when `auth_verifier_saml_realm` is configured and only for tokens of that realm (an explicit bearer token takes precedence), and authenticate state-changing cookie requests only with `Content-Type: application/json` or `application/octet-stream`
- Refuse to start when `auth_verifier_saml_realm` is set and `kms_public_url` does not use `https://`, when the realm is empty or the Authentication Verifier admin realm `_`, or when `auth_verifier_url` does not use `https://`
- Revoke the Authentication Verifier session and expire the `_ea_` cookie on `GET /ui/logout`, only for a valid session of the SAML realm
- Move the `authentication` submodule to the Authentication Verifier release that ships SAML single sign-on (0.5.0), and add the `test:ui-saml` end-to-end task (Keycloak IdP and nginx in Docker, Authentication Verifier and KMS on the host with complete `test_data` fixtures, Playwright in `ui/tests/e2e-saml/`), also run by `test:ui` on non-FIPS with Docker

#### HSM

- Add Thales Luna Network HSM support (`hsm_model = "luna"`) with a 25-test PKCS#11 suite, a `prepare_luna.sh` client installer, and Kubernetes guides ([#1275](https://github.com/Cosmian/kms/pull/1275), [#1281](https://github.com/Cosmian/kms/pull/1281))
- Add Azure Cloud HSM support (`hsm_model = "azure_cloud_hsm"`, Linux x86_64): the KMS loads `/opt/azurecloudhsm/lib64/libazcloudhsm_pkcs11.so`, overridable with `AZURE_CLOUD_HSM_PKCS11_LIB`; the new Azure Cloud HSM page covers client setup, Crypto User creation, slot-id discovery, configuration and limits ([#1211](https://github.com/Cosmian/kms/pull/1211))
- Delegate RSA-PSS signing, EC key generation (P-224/P-256/P-384/P-521), ECDSA signing, EdDSA (Ed25519/Ed448) signing and RSA `SignatureVerify` to the HSM ([#1154](https://github.com/Cosmian/kms/issues/1154), [#1157](https://github.com/Cosmian/kms/issues/1157))
- Add HSM trait MAC generate/verify with bridging ([#1263](https://github.com/Cosmian/kms/pull/1263)), `non-fips` gating on every PKCS#11 loader crate, and `Session` helpers for message-based AES-GCM, HKDF, generic secret keys and multi-part AES-CBC
- Add the Helm `command` value so the FIPS image can start with `OPENSSL_CONF` unset for HSM libraries that embed OpenSSL (Trustway Proteccio)
- Add `ckms bench --hsm`/`--hsm-slot` and `mise run bench:hsm --delegated`, with `bench:pkcs11` reports for every signature algorithm
- Sign and verify through the PKCS#11 v3.0 message API (`C_MessageSignInit`/`C_SignMessage`, `C_MessageVerifyInit`/`C_VerifyMessage`, persistent per-session contexts) when the provider sets `supports_message_sign_verify` and the library exports it, falling back to the classic API for each mechanism the HSM rejects ([#1340](https://github.com/Cosmian/kms/pull/1340))
- Add `key_encryption_key_wrapping_algorithm` (`aes-gcm`, `aes-key-wrap`, `aes-key-wrap-padding`, `rsa-oaep`; env `KMS_KEY_ENCRYPTION_KEY_WRAPPING_ALGORITHM`) to choose how `key_encryption_key` wraps keys at rest; unset keeps AES-GCM for an HSM AES key, RSA-OAEP (SHA-256) for an HSM RSA key and AES-KWP for a software AES key, and a software RSA key requires `rsa-oaep` ([#1341](https://github.com/Cosmian/kms/pull/1341))
- Support AES-KW (NIST SP 800-38F, RFC 3394) and AES-KWP (RFC 5649) with HSM wrapping keys and honour the wrapping mode requested on `Export`/`Get`; wrapped objects record the mode actually used, and objects wrapped by earlier versions still unwrap ([#1341](https://github.com/Cosmian/kms/pull/1341))
- Check at startup that an HSM AES `key_encryption_key` can wrap with its configured mode, otherwise stop with an actionable error; for AES-KW/KWP, set `CKA_WRAP`/`CKA_UNWRAP` once on a KEK created by an earlier version (only on a slot that offers AES key wrap) and clear them again if that does not fix wrapping. **Note:** every new HSM AES key is now created with `CKA_WRAP` and `CKA_UNWRAP` enabled, not only key-wrapping keys; restricting them is still under review ([#1341](https://github.com/Cosmian/kms/pull/1341))

#### PKCS#11 v3.x Provider

- Implement `C_GetInterfaceList`/`C_GetInterface` (`CK_INFO.cryptokiVersion` 3.1; `C_GetFunctionList` v2.40 unchanged), `C_LoginUser`, the `CKO_PROFILE` conformance profiles, `CKA_UNIQUE_ID`, the v3.0 function list stubs, and one-shot EdDSA message signing (`C_MessageSignInit` returns `CKR_FUNCTION_NOT_SUPPORTED` for any other mechanism, whatever its parameters); PINs, user names and tokens passed to `C_Login`/`C_LoginUser`, and the copy of the HSM slot PIN made for each login, are wiped from memory after use (the configured slot PIN stays in memory for later logins) ([#1166](https://github.com/Cosmian/kms/pull/1166))
- Implement `C_VerifyInit`/`C_Verify`/`C_VerifyUpdate`/`C_VerifyFinal` through KMIP `SignatureVerify` (previously `CKR_FUNCTION_NOT_SUPPORTED`) and native `CKM_AES_GCM`
- Add `CKA_MODULUS_BITS` on RSA key objects and report `CKF_VERIFY` in `C_GetMechanismInfo`
- Probe the v3.0 interface of loaded HSM libraries additively, degrading to v2.40 when unsupported

#### PKI & Certificates

- Add `POST /certificates/csr`, `ckms certificates generate-csr` and a **Certificates > Certs > Generate CSR** page to generate a PKCS#10 CSR for a private key held by the KMS, for example to have an offline root CA sign a sub-CA: an HSM key signs through the crypto oracle and can stay non-extractable (`--sensitive`), the caller needs only `Sign`, the KMIP algorithm policy applies, keys that are not Active, lack `Sign` in their usage mask or cannot sign (X25519, ML-KEM) are refused with a 4xx, and the user-settable `PublicKeyLink` is never followed ([#1328](https://github.com/Cosmian/kms/pull/1328))
- Create the key pair during CSR generation: `ckms certificates generate-csr --algorithm <nist-p256|rsa4096|…>` (the `certify --generate-key-pair` algorithms; add `--private-key-id hsm::<slot>::<id> --sensitive` for a non-extractable HSM key), a **Generate a new key pair** option on the page, and `algorithm`/`sensitive` request fields, the response returning the key ids; the KMIP algorithm policy is checked before the key pair is created, so a refused request leaves no key ([#1328](https://github.com/Cosmian/kms/pull/1328))
- Sign certificates (`Certify`, `ReCertify`), CRLs and OCSP responses with an issuer private key held in an HSM, including a non-extractable one: the HSM signs the TBS bytes and the result is verified with the issuer public key before it is stored; an issuer given only by its sensitive HSM key id is resolved through the certificate's `PrivateKeyLink`; Ed25519/Ed448 HSM keys (non-FIPS) work for CSRs, certificates, CRLs and OCSP; EST issues through `Certify`, and SCEP answers `NotSupported` for a sensitive HSM CA key. `Certify` given an HSM private key id with no `PublicKeyLink` (for example the ID Placeholder after an HSM `CreateKeyPair`, including a non-extractable RSA key) certifies its public key `<sk>_pk`, with the caller's own `Certify` rights on it. **Upgrade action:** this applies to every HSM issuer key, including non-sensitive ones that used to be exported for signing: grant `Certify` on the HSM CA key to the users who issue certificates or CRLs with it (HSM grants are per operation); HSM CA keys other than RSA, EC, Ed25519 and Ed448 are refused, and EC HSM CAs sign with the digest matching their curve (SHA-256 for P-256, SHA-384 for P-384, SHA-512 for P-521) ([#1328](https://github.com/Cosmian/kms/pull/1328))
- Tag every certificate created by `Certify`/`ReCertify` or imported (PKCS#12 included) with the system tag `_serial=<UPPERCASE HEX>` so `Locate` by tag finds it by serial number; on the first start after the upgrade, existing certificates get the tag in a one-time database write (SQLite, PostgreSQL, MySQL/MariaDB, Redis-Findex) recorded by a completion marker ([#1328](https://github.com/Cosmian/kms/pull/1328))

#### REST

- Unwrap the CEK of `POST /v1/crypto/decrypt` with `RSA-OAEP`/`RSA-OAEP-256` through the HSM crypto oracle when `kid` designates an HSM key pair (a public `kid` is resolved through `PrivateKeyLink` or the `_pk` suffix), so the private key never leaves the HSM; SoftHSM2 2.6.1 cannot do RSA-OAEP decryption with explicit parameters, use another HSM such as Kryoptic ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Import a public-only RSA key with `POST /v1/crypto/keys` (`n` and `e` without `d`, `key_ops` among `encrypt`, `wrapKey` and `verify`), and accept a caller-chosen `kid` on every import ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Accept `cek_kid` in `POST /v1/crypto/encrypt` (`RSA-OAEP`/`RSA-OAEP-256` only): an active, extractable KMS AES key on which the caller has `Export`, used as the CEK of a complete JWE; the key that wraps it (the public key of `kid`, or the private key when it has no linked public key) must have the `WrapKey` usage and the RSA-OAEP hash must pass the KMIP algorithm policy, otherwise HTTP 422: `RSA-OAEP` (SHA-1) is refused when the configured policy excludes it (the `DEFAULT` policy does; no policy, or a custom allowlist that includes SHA-1, still accepts it), and public keys imported through `POST /v1/crypto/keys` need `wrapKey` in `key_ops` ([#1338](https://github.com/Cosmian/kms/pull/1338))

#### Packaging & Deployment

- Publish signed Alpine Linux `.apk` packages for `cosmian_kms` (OpenRC service, run as the unprivileged `kms` system user with `kms.toml` as `root:kms` `0640`) and `ckms`, for x86_64 and aarch64: dynamically-linked musl for FIPS, fully static musl for non-FIPS; add the `test:musl-crosscheck`, `test_alpine_musl.sh` and `alpine-native-build` validation paths and gate `publish-apk` on the Alpine smoke tests ([#1237](https://github.com/Cosmian/kms/pull/1237))
- Ship the C++ runtime (`libstdc++`, `libgcc_s`) in the Docker image for vendor PKCS#11 libraries

#### Server Configuration & KMIP

- Report the real generator (DRBG, CTR, AES-256) in `Query` with `QueryRNGs`
- Decide per attribute and per operation whether an edit is allowed, needs a grant or is server-managed with one policy table (`Tag::edit_policy`)
- Support `Certify` over KMIP 1.x, with the X.509 extensions in the Custom Attribute `y-cosmian::x509-extension` ([#1335](https://github.com/Cosmian/kms/pull/1335))

#### Crypto & KEM

- Thread an OpenSSL property query and a FIPS-indicator check through ML-KEM, ML-DSA, SLH-DSA and hybrid KEM key generation; a `fips=yes` request fails closed when the indicator is unavailable, as required by NIST SP 800-227 RS2 readiness ([#1253](https://github.com/Cosmian/kms/pull/1253))
- Give `RNGSeed` zero entropy credit, zeroize the split-key seed and return `ServerError` on RNG failures ([#1253](https://github.com/Cosmian/kms/pull/1253))
- Add the non-FIPS `secp192k1` curve: `ckms ec keys create --curve secp192k1`, `ckms ec sign` and `sign-verify` on the software path, and HSM key generation (OID `1.3.132.0.31`); it signs with OpenSSL's randomised ECDSA

### 🐛 Bug Fixes

#### Hybrid KEM & HSM Key Encryption Key

- Fix hybrid KEM keys (`ConfigurableKEM`, `X25519MLKEM768`, `X448MLKEM1024`) with an HSM `key_encryption_key`: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`; wrap, unwrap, export with the stored `KeyFormatType` and TTLV deserialization now work ([#1330](https://github.com/Cosmian/kms/pull/1330))
- Unwrap with a KMS wrapping key that is itself wrapped (for example by the HSM KEK), checking its stored usage mask
- Keep the requested `CryptographicUsageMask` of `ConfigurableKEM` keys instead of OR-ing `Unrestricted`, and inherit `CommonAttributes` in per-key attributes
- Reject non-empty `Data` in KEM `Encrypt`, and decapsulate the encapsulation component in `ckms bench`
- Fix `Import` of `X25519MLKEM768`, `X448MLKEM1024` and `ConfigurableKEM` keys failing with `Unsupported key format type`, and `Get`/`Export` of a `ConfigurableKEM` key, by skipping the OpenSSL round trip ([#1268](https://github.com/Cosmian/kms/pull/1268))

#### HSM

- Fix every HSM `Encrypt` failing on Thales Luna (non-sensitive RSA-OAEP probe key), AES-GCM `Encrypt` on Luna ("Failed to initialize message-based encryption"), the Luna FIPS IV layout (`ciphertext || tag || iv`), and creation of non-sensitive keys; cache the supported algorithms per slot (AES-GCM on Luna from 288 to about 4,000 req/s)
- Create HSM benchmark keys as sensitive and destroy leaked keys; give `ckms bench` setup keys deterministic `bench-<purpose>` identifiers
- Make key-date handling capability-driven (`supports_key_dates`, false for Crypt2pay, AWS CloudHSM and SoftHSM2) and refuse RSA-OAEP wrapping where unsupported
- Fix delegated signing: pre-digested ECDSA uses `CKM_ECDSA`, pre-digested RSA-PSS uses `CKM_RSA_PKCS_PSS`, pre-digested PKCS#1 v1.5 wraps a `DigestInfo`, `data` together with `digested_data` is rejected, Ed25519/Ed448 reject pre-hashed requests, a mismatched `CryptographicAlgorithm` returns a clear KMIP error, and a malformed DER ECDSA signature is reported as invalid ([#1169](https://github.com/Cosmian/kms/pull/1169))
- Infer the RSA PKCS#1 v1.5 hash from the input length only for a digest (`digested_data`): a raw message with no explicit hash always signs with SHA-256
- Preserve EC-family HSM metadata (Ed25519/Ed448/X25519 key types and `CKA_EC_PARAMS` encodings, curve domain parameters, `CKA_START_DATE`/`CKA_END_DATE` read failures) and refuse HSM-backed X25519 key-pair creation until a `DeriveKey` path exists
- Bound async session checkouts per slot (`max_concurrent_sessions`, default 128), resolve signing in one session, avoid the second `C_Sign` call, cache non-rotated HSM keyset UIDs for 1 hour, and pool only read-write sessions
- Issue one `C_EncryptMessage`/`C_DecryptMessage` call per AES-GCM operation, and pin the decrypt IV to 12 bytes and the tag to 16
- Fix `SignatureVerify` resolving `data` and `digested_data` inconsistently on the crypto-oracle path
- Refuse `Get`/`Export` of a sensitive HSM key even with a key-wrapping specification: the KMS cannot read such a key, so it has nothing to wrap ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Use the matching public key when wrapping or encrypting with an explicit RSA algorithm on an HSM private-key UID, as the default algorithm already did ([#1341](https://github.com/Cosmian/kms/pull/1341))
- Generate AES-GCM IVs inside production HSMs in FIPS builds (FIPS 140-3 IG C.H), through the PKCS#11 v3.0 message API or an HSM-generated IV; an HSM offering neither fails with a message pointing to `key_encryption_key_wrapping_algorithm = "aes-key-wrap-padding"`, only the SoftHSM2 and Kryoptic development tokens keep caller-supplied IVs, and `hsm_model = "other"` is treated as a FIPS-validated module ([#1341](https://github.com/Cosmian/kms/pull/1341))

#### PKCS#11 Provider

- Fix `C_Login`/`C_LoginUser` rejecting OIDC bearer tokens above 4 KiB when `pkcs11_use_pin_as_access_token = true` (PIN cap raised to 64 KiB)
- Match `C_GetInterface` versions exactly and bound the `pInterfaceName` read to 8 bytes
- Fix the secp256k1 OID (`1.3.132.0.33` was secp224r1's; correct is `1.3.132.0.10`), Ed25519/Ed448 key types (`CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY`), and `CKM_RSA_PKCS_PSS` treating its input as a message instead of a digest
- Sign a `CKM_RSA_PKCS` DER `DigestInfo` (SHA-1/256/384/512) as a pre-computed digest for `gnupg-pkcs11-scd` and OpenSSH
- Stop serializing every Cryptoki operation process-wide: one lock per session instead of one global lock (`sign-eddsa` throughput 19 → 82 ops/s at concurrency 8)
- Reuse a `C_Sign` length-query signature only for the same data
- Return `CKR_BUFFER_TOO_SMALL` with the required length in `pulDataLen` from `C_Decrypt` on a length query or a too-small buffer, and keep the decrypt operation active so the caller can retry

#### Crypto

- Fix `ecdsa_verify()`/`ed_verify()` returning a hard `CryptoError` instead of `ValidityIndicator::Invalid` for tampered, malformed or wrong-curve signatures, which affected every KMIP `Verify` client, not only PKCS#11 ([#1183](https://github.com/Cosmian/kms/issues/1183))
- Sign NIST P-256 ECDSA (non-FIPS builds) with OpenSSL's RFC 6979 deterministic nonce mode instead of the pure-Rust `p256` crate, about 20x faster; the randomised OpenSSL signer is used when a pre-digested input is not exactly the hash length. secp256k1 keeps `k256` with low-S ([#1320](https://github.com/Cosmian/kms/pull/1320))
- Unwrap AES-GCM-wrapped keys with 128- and 192-bit key encryption keys; unwrapping always assumed AES-256 ([#1341](https://github.com/Cosmian/kms/pull/1341))

#### PKI

- Fix the OCSP responder answering `unauthorized` to every request about a sub-CA: issuer hashes were computed from the CA's issuer name instead of its subject name ([#1328](https://github.com/Cosmian/kms/pull/1328))
- Fix automatic CRL regeneration (after `Revoke` and from the refresh cron) failing silently, and leaving the CRL stale, when the revoking user or `default_username` had no access to the CA key: it now signs as the owner of the issuer certificate ([#1328](https://github.com/Cosmian/kms/pull/1328))
- Sign certificates, CSRs, CRLs and OCSP responses of EC CAs with the digest matching the CA curve (ecdsa-with-SHA256 for P-256, SHA384 for P-384, SHA512 for P-521, as RFC 5480 §4 recommends) instead of always SHA-256. **Upgrade note:** existing P-384 and P-521 software CAs now issue certificates, CRLs and OCSP responses signed with SHA-384 or SHA-512; relying parties that only accept ecdsa-with-SHA256 must be updated

#### Web UI

- Hide PQC, FPE, Anonymize and Covercrypt (and the new OpenPGP section) in FIPS mode, failing closed while `/server-info` loads
- Stop offering `CryptographicAlgorithm` and `CryptographicLength` in the attribute Set, Modify and Delete forms: they are read-only (COSMIAN-2026-044)

#### KMIP

- Return one `Encrypt` response layout for every KEM public key (ML-KEM, `X25519MLKEM768`, `X448MLKEM1024`, `ConfigurableKEM`): `Data` is the serialized `(shared secret, encapsulation)` tuple and `IVCounterNonce` is empty, instead of returning the encapsulation in `IVCounterNonce`; ML-KEM and native hybrid KEM clients unpack `Data` ([#1330](https://github.com/Cosmian/kms/pull/1330))
- Restrict `RNGSeed` to Crypto Officers once roles are configured (add seeding callers to `crypto_officer_users`), and answer `Unauthorized` instead of `RouteNotFound` for unimplemented KMIP operations (`Archive`, `Ping`, …) in that case
- Return Result Reason `Read_Only_Attribute` (0x1D) instead of `Attribute_Read_Only` (0x22) from `AddAttribute` on a read-only attribute, as KMIP 2.1 requires (`ModifyAttribute` and `DeleteAttribute` keep 0x22), and refuse `AddAttribute` of `Fresh`, `LastChangeDate` and `State` the same way (`State` used to return `Invalid_Request`). Clients matching 0x22 on `AddAttribute` must accept 0x1D
- Use the ID Placeholder in a batched `Certify` or `ReCertify` that has no Unique Identifier, and set the placeholder to the new certificate afterwards (KMIP 2.1 and 1.x batches); after `CreateKeyPair` the placeholder holds the private key, and `Certify` follows its public-key link to certify the created public key

#### REST

- Require a JSON object for protected headers in `/v1/crypto/decrypt`, `/v1/crypto/verify` and `/v1/crypto/keys/unwrap` (arrays and duplicate parameters fail with HTTP 400)
- Return error responses of every route as `text/plain; charset=utf-8` with `X-Content-Type-Options: nosniff` instead of `text/html`
- Report an Azure EKM wrap/unwrap with a KEK that is not in an accepted lifecycle state (for example `PreActive` or `Deactivated`) as `KeyDisabled` (HTTP 403) instead of `InternalError`
- Derive `use` and `alg` of RSA keys in `GET /.well-known/jwks.json` from the public key usage mask instead of always publishing `use=sig` with `RS*`: `Verify` only publishes `use=sig` with `alg=RS256/384/512`, `Encrypt`/`WrapKey` only publishes `use=enc` without `alg`, and keys with both (such as HSM RSA public keys) or neither publish neither; keys without a usage mask are unchanged. Clients that assumed every RSA JWK is `use=sig`/`RS*` must select keys by `kid` ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Import a public key from `POST /v1/crypto/keys` with RSA `n` and `e` but no `d` instead of ignoring them and generating a key pair, and reject a `kid` on a key generation request with HTTP 400 instead of ignoring it. Clients must omit `kid` when generating keys and read the server-assigned `kid` from the response ([#1338](https://github.com/Cosmian/kms/pull/1338))

#### Database

- Fix Redis/Findex concurrent `Upsert` and stale tag index: every write is one two-phase Lua script with compare-and-swap, lost races retry, stale Findex keywords are removed and discarded on read; Redis Cluster is not supported ([#940](https://github.com/Cosmian/kms/issues/940), [#1258](https://github.com/Cosmian/kms/pull/1258))
- Invalidate `RotateNameCache` by keyset name and member UID, and never cache empty results
- Empty the `crls` table in `clear_database` (SQLite, PostgreSQL, MySQL)

#### CLI

- Include the JOSE AES-GCM benchmarks in `ckms bench --algorithm aes-gcm`, and drop the secp256k1 and Ed25519 sign/verify modes of the `ckms` PKCS#11 benchmarks from FIPS builds
- Send curve-appropriate `CryptographicParameters` from `ckms ec sign`, and reject `--digested` for Ed25519/Ed448
- Remove `--cryptographic-algorithm`/`-a` and `--cryptographic-length` from `ckms attributes set`, `modify` and `delete`: the server rejects edits of these read-only attributes (COSMIAN-2026-044), and scripts passing them now fail at argument parsing
- Remove the `--authenticated-additional-data` option of `ckms` key export and the matching Web UI fields: the value has been silently ignored since KMS v5 ([#1341](https://github.com/Cosmian/kms/pull/1341))

#### Hardening

- Fail the KMIP socket TLS handshake when no client certificate is presented, instead of after the first KMIP bytes ([#1276](https://github.com/Cosmian/kms/issues/1276), [#1278](https://github.com/Cosmian/kms/pull/1278))
- Compare the AWS XKS SigV4 access key ID and `MACVerify` tags in constant time ([#1339](https://github.com/Cosmian/kms/pull/1339))
- Log only lengths, not the plaintext or ciphertext in hexadecimal, from the PKCS#11 provider `C_Encrypt`, `C_Decrypt` and KMS encrypt paths at debug level
- Drop reserved `_`-prefixed system tags from the objects of an imported PKCS#12 file
- Count audit events that the backend fails to write (for example while the `PostgreSQL` audit database is down) in the next `audit:eviction` sentinel, now worded `N events dropped (channel full or write failed)`, instead of losing them silently
- Reject `crit` and nested-JWT `cty` headers in every JWKS-keyed authenticator (Google CSE, OIDC, Auth Verifier, UI SSO `id_token`); Google CSE tokens must carry non-blank `alg` and `kid`
- Warn at startup when no authentication method, no `key_encryption_key` or no `rate_limit_per_second` is configured
- Draw every key, nonce/IV and secret token from `KmsRng` (OpenSSL AES-256 CTR-DRBG, fail-closed) instead of `rand_bytes`, `CsRng` or `rand::rng()`, including `C_GenerateRandom`; ban every other entropy source with a workspace `clippy.toml`; nonces, IVs and serials come from the public DRBG so private-DRBG output never leaves the server ([#1274](https://github.com/Cosmian/kms/pull/1274))
- Check every `ConfigurableKEM` key against the algorithm policy on each use, judged only by the ML-KEM variant and curve read from its key bytes: relabelled or stripped KMIP attributes neither deny nor allow it ([#1330](https://github.com/Cosmian/kms/pull/1330))
- Make `CKA_EXTRACTABLE` follow `sensitive` on HSM-generated AES and RSA keys (`sensitive = true` ⇒ non-extractable) instead of always `true`, and set `CKA_EXTRACTABLE=false` explicitly on sensitive AES keys of HSMs that reject `CKA_SENSITIVE` (Thales Luna, Azure, AWS and GCP Cloud HSM) instead of relying on the vendor default; existing keys must be regenerated
- Refuse the reserved service identity `[aws-xks-service]` regardless of ASCII case or trailing spaces
- Enforce `objectVersion` in the Kubernetes CSI provider: when set, it must equal the lower-case hexadecimal SHA-256 digest of the object's current content, otherwise the mount fails with `FailedPrecondition`
- Audit `/v1/crypto` requests like the KMIP scope, recording the operation as the HTTP method and route (for example `POST /v1/crypto/encrypt`) and the key involved; a request refused before its handler (for example with HTTP 401) is recorded with the operation `v1`. The API documentation lists which scopes are audited

### ♻️ Refactor

- **KMIP / Server**: cut per-request allocations on the TTLV-JSON, binary TTLV, KMIP `ByteString` decoding, database, audit and middleware paths (4 KiB `Encrypt` decode: 166 µs → 7 µs; `retrieve_object_for_operation` on a cached key: 36 → 3 allocations) ([#1280](https://github.com/Cosmian/kms/pull/1280))
- **Workspace**: remove every `#[allow(dead_code)]`/`#[expect(dead_code)]`, declare crate versions and shared dependencies once in the root `Cargo.toml`, use safe OpenSSL APIs instead of raw FFI in PQC ([#1267](https://github.com/Cosmian/kms/pull/1267), [#1260](https://github.com/Cosmian/kms/pull/1260))
- **HSM**: group the `HsmCapabilities` vendor flags into `aes` (`supports_sensitive_attribute`, `key_wrap_pad_is_rfc5649` and the `aes.gcm` sub-struct `supports_caller_iv`, `allows_caller_iv_in_fips`, `supports_message`, which replaces `supports_aes_gcm_message`), `rsa` (`supports_sensitive_attribute`, `oaep_requires_source_data_ptr`, `supports_oaep_key_wrap`) and `ec` (`supports_sensitive_attribute`, `enforces_ecdsa_digest_strength`) sub-structs, add the top-level `supports_message_sign_verify` flag, and remove vendor names from `base_hsm` session code; custom HSM providers must adapt ([#1340](https://github.com/Cosmian/kms/pull/1340), [#1341](https://github.com/Cosmian/kms/pull/1341))
- **Code consolidation** (no behaviour change):
    - Server: one auth middleware stack for the `/tokenize`, `/v1/crypto` and default scopes; shared attribute dispatch arms; shared helpers for the AWS XKS error mapping, Google CSE responses, Azure EKM parameter checks, the JWS signing input, wizard prompt errors and the Crypto Officer `Create` grant/revoke checks.
    - HSM and PKCS#11: one session-checkout helper in `BaseHsm`; shared output-buffer copy and `C_EncryptInit`/`C_DecryptInit` key resolution in the PKCS#11 module.
    - KMIP and crypto: macro-generated KMIP 1.4 response and key-block conversions; one raw-key path for Ed25519, Ed448, X25519 and X448 key pairs.
    - SQL stores: shared helpers for merging granted operations, rotation filtering and CRL numbers.
    - CLI: one `RevokeKeyAction` and one destroy helper for every key group except PQC, which keeps its own `RevokeKeyAction` (different help text). The `revoke_key` modules of the other key groups of `cosmian_kms_cli_actions` and `RevokePgpKeyAction` are removed; use `actions::shared::RevokeKeyAction`.

### 🧪 Testing

- Add SoftHSM2-backed hybrid KEM lifecycle and TTLV-wrapped import tests, `ConfigurableKEM` server tests (usage masks, policy on use, revocation) and `pqc_import_tests`
- Add live `PostgreSQL` TLS tests for every `sslmode`
- Add a PKCS#11 v3.x conformance tier (`pkcs11-tool`, Kryoptic suite, `ckms pkcs11 verify`), a Luna test suite and a Crypt2pay simulator, and wire shared HSM tests into every backend
- Add `test:k8s:hsm --model proteccio|crypt2pay --variant fips|non-fips` and a Helm `command` render check
- Add the EST/SCEP interoperability suites and Apple SCEP fixtures replayed in CI
- Validate Thales Luna, AWS CloudHSM, GCP Cloud HSM and Azure Cloud HSM manually against real hardware only: no CI runner has these HSMs, so their CI matrix entries are commented out with the reason
- Add `mise run test:jose-hsm` (JWKS, RSA-OAEP-256 decryption through a Kryoptic HSM, `cek_kid` encryption), also run by `test:jose`, and run the key-byte export and JOSE decryption cases in `test_hsm_all` (JOSE decryption skipped on SoftHSM2) ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Prove on real Crypt2pay hardware that an extractable AES-256 key can be exported (RSA-OAEP-SHA256 wrap, recovery, AES-GCM decryption outside the HSM), run the hardware suite serially and clean up leftover `kms-test-*` objects; the Crypt2pay simulator's FIPS suite checks the refusal of HSMs that generate no AES-GCM IV ([#1338](https://github.com/Cosmian/kms/pull/1338), [#1341](https://github.com/Cosmian/kms/pull/1341))
- Add PKCS#11 v3.0 message sign/verify tests against a C stub and a SoftHSM2 v3 adapter ([#1340](https://github.com/Cosmian/kms/pull/1340))
- Build in-process server test instances only through `test_kms()`/`test_kms_with_config()`, enforced by the `no-direct-kms-instantiate` pre-commit hook ([#1341](https://github.com/Cosmian/kms/pull/1341))
- Keep `postgres-mtls` and `mysql-mtls` (profile `mtls`) and `jaeger` and `otel-collector` (profile `otel-test`) out of a bare `docker compose up -d` of the test backends; start them with `--profile <name>` or by service name ([#1298](https://github.com/Cosmian/kms/pull/1298))

### ⚙️ Build

- Merge Dependabot bumps (`rcgen` 0.14, `k256` 0.14, `num-bigint-dig` 0.9, `etcetera` 0.11, `redis` 1.x, `num-bigint` 0.5, `quick-xml` 0.42, `vite`), adapting the TTLV XML parser and secp256k1 ECDSA, enabling `uuid` `js` for WASM, allowing `BSL-1.0` in `deny.toml` and recording `cargo-vet` exemptions ([#1289](https://github.com/Cosmian/kms/pull/1289), [#1297](https://github.com/Cosmian/kms/pull/1297), [#1327](https://github.com/Cosmian/kms/pull/1327))
- Upgrade `rustls` and group Dependabot minor/patch and security updates per ecosystem; ignore semver-major bumps
- Override `smol-toml` (≥ 1.9.0) and `source-map-js` (≥ 1.2.2) in the Web UI build to resolve Dependabot security alerts ([#1255](https://github.com/Cosmian/kms/pull/1255))
- Add Nix builds for the Alpine musl packages (`nix/kms-server-musl.nix`, `nix/cli-musl.nix`)
- Use rPGP 0.21.0 without its `bzip2` feature and build without `clap-config-fallback`'s `yaml` feature
- Build the FIPS provider from the CMVP-validated OpenSSL 3.1.2 (certificate #4985) instead of the 3.6.2 sources, which hold no certificate; the main library stays on OpenSSL 3.6.2 ([#1253](https://github.com/Cosmian/kms/pull/1253))
- Pin the supply chain: add `cargo-vet`, hash-pinned Python requirements with `pip-audit`, `govulncheck`, SHA-pinned GitHub Actions and base images, pre-commit policy hooks and wider Dependabot coverage ([#1273](https://github.com/Cosmian/kms/pull/1273))
- Drop the unmaintained `unsafe-libyaml` (RUSTSEC-2024-0449): use `serde-saphyr`, upgrade `kube` to 4.2, `k8s-openapi` to 0.28 and `schemars` to 1; the server no longer accepts `.yaml`/`.yml` configuration files (TOML and JSON remain supported) ([#1269](https://github.com/Cosmian/kms/pull/1269))
- Make `shell.nix` add the glibc include path only on Linux, so `nix-shell` evaluates on macOS ([#1338](https://github.com/Cosmian/kms/pull/1338))

### ⚙️ CI

- Authenticate Docker Hub pulls and collapse the `packages-test` and `alpine-packages-test` matrix axes into in-job loops (56 → 14 and 12 → 6 legs)
- Pin `ubuntu-latest` to `ubuntu-24.04`, keep the SAP ASE test image on `ubuntu:22.04`, pin `azure/setup-helm` and `medyagh/setup-minikube` by commit SHA, and add `cargo-vet`, `pip-audit` and `govulncheck` jobs
- Fix new Clippy findings (`large_futures`, `result_large_err`, deprecated `cc::Tool::env`)
- Install a pinned, SHA-256-checked `rustup-init` in the Alpine native build instead of piping `sh.rustup.rs` into `sh`, and make the `no-curl-pipe-shell` hook catch pipes split across lines
- Install the pinned mise `v2026.10.8` Linux x64/ARM64 release binary directly (the `-musl` build in Alpine containers, where the glibc one cannot relocate even with `gcompat`), with its SHA-256 verified before execution, instead of the installer and its unpinned release-index lookup ([#1338](https://github.com/Cosmian/kms/pull/1338))
- Rerun hosted runners lost during a job from `/ci-fix` instead of committing a fix, and route prompts to the matching skill automatically ([#1341](https://github.com/Cosmian/kms/pull/1341))

### 📚 Documentation

- Document PKCS#11 v3.x provider interfaces, Alpine installation with signature verification, Thales Luna and Kubernetes HSM deployments (Luna, Proteccio, Crypt2pay), GnuPG smartcard use, EST/SCEP trusted-proxy semantics, PostgreSQL `sslmode`, the Redis single-node requirement and the Azure EKM trust directions ([#1323](https://github.com/Cosmian/kms/pull/1323))
- Document NIST SP 800-227 requirements RS1–RS5 for KEMs, which of them the KMS meets or does not meet (no ESV/CMVP entropy claims for PQC key generation), in the random-number-generation page ([#1253](https://github.com/Cosmian/kms/pull/1253)); add ADRs for the HSM delegation and PKCS#11 v3.0 scope decisions, the PQC `KmsRng` seeding decision and the randomness exceptions
- Add Thales Luna and Proteccio benchmark reports, the Luna quick reference, and HSM algorithm support matrix columns for Thales Luna and GCP Cloud HSM, all listed in the documentation navigation
- List every supported model, including Azure Cloud HSM and GCP Cloud HSM, in the `--hsm-model` help and `resources/kms.toml`, and document the `[audit.postgres]` `url` and `instance_id` keys in the configuration template
- Document the SPIRE KMIP integration for the `KeyManager` plugin only: remove the `UpstreamAuthority` plugin guide and the `test:spire-kmip-upstream-authority` task ([#1335](https://github.com/Cosmian/kms/pull/1335))

## Features

- **ReKeyKeyPair operation**: Implemented KMIP `ReKeyKeyPair` (§6.1.47) for all asymmetric key types — RSA, EC (P-256/P-384/P-521/secp256k1), Ed25519, X25519, ML-KEM (768/1024), ML-DSA (65/87), and SLH-DSA. Generates a new key pair preserving the algorithm and parameters of the existing one, transfers Name and links via `ReplacementObjectLink`/`ReplacedObjectLink`, and applies `Offset`-based activation. Shared lifecycle logic extracted to `rekey_common.rs`.
- **ReKeyKeyPair KMIP 1.4 support**: Implemented the V14↔V21 conversion for `ReKeyKeyPair` — previously commented out. KMIP 1.4 clients can now use `ReKeyKeyPair` with `PrivateKeyUniqueIdentifier` (required String) and `CommonTemplateAttribute` containers. Response converts back to V14 format with plain String identifiers.

## Bug Fixes

- **ReKey operation**: Fixed KMIP `ReKey` to create a new replacement key with a new UID instead of replacing key material in-place. Per KMIP 2.1 §6.1.46, the existing key is linked to the new key via `ReplacementObjectLink`/`ReplacedObjectLink` and the Name attribute is transferred; the existing key's **State is NOT changed** — the spec does not mandate deactivation. Callers wishing to retire the old key must issue an explicit `Revoke` afterwards.
- **ReKey spec correction**: Removed hallucinated deactivation of the existing key. KMIP 2.1 §6.1.46 Table 304 lists State only for the *replacement* key ("Set based on attribute values, such as dates"); the existing key's State is unaffected by ReKey. This matches observed VAST Data production behaviour where VAST explicitly calls `Revoke` + `Destroy` on the old key after rotation.
- **ReKey log/test wording**: Fixed log message and test comments that incorrectly stated "old key deactivated" — old key remains Active after ReKey per spec.
- **ReKey test cleanup**: VAST ReKey test now properly cleans up both the original and replacement keys (revoke + destroy each).
- **Activate lifecycle errors on destroyed/compromised objects**: `Activate` on a `Destroyed` or `Compromised` key now returns the correct KMIP `Wrong_Key_Lifecycle_State` error instead of `Object_Not_Found`. The object retrieval filter was extended to allow `Activate` through for these states so `activate.rs` can emit the proper lifecycle rejection.
- **Test isolation: unique SQLite paths per process**: `load_test_config_from_toml` and the HSM bootstrap helpers now embed `std::process::id()` in their temp-directory names. Without this, two test binaries launched in parallel by `cargo test --workspace` could collide on the same path when their per-process atomic counters both start at 0 within the same clock tick, causing `database is locked` failures.

## Security

- **DDOS mitigation on `/hsm/status`**: The `GET /hsm/status` endpoint now requires explicit authentication (JWT, client certificate, or API token). Requests that only have the fallback default username are rejected with 401.
- **Activate authorization** (COSMIAN-2026-018): The Activate operation now uses `KmipOperation::Activate` for permission checks instead of `GetAttributes`. Previously, any user with any permission on an object could activate it.
- **ReKey authorization** (COSMIAN-2026-017): Added ownership/permission check before modifying the existing key during ReKey. Previously, a caller who knew another user's key UID could create a replacement key and remove the original key's Name without authorization. Same fix applied to `ReKeyKeyPair`.
- **CVE-2026-39373 / GHSA-fjrm-76x2-c4q4**: Upgrade `jwcrypto` from 1.5.6 to 1.5.7 in `.github/scripts/test/requirements-jose.txt`. Fixes JWE ZIP decompression bomb — 1.5.6 validated compressed input size (≤250 KB) but not the decompressed output size, allowing a crafted token to exhaust server memory.
- **DDOS mitigation on `/hsm/status`**: The `GET /hsm/status` endpoint now requires explicit authentication (JWT, client certificate, or API token). Requests that only have the fallback default username are rejected with 401.
- **ReKey authorization** (COSMIAN-2026-017): Added ownership/permission check before modifying the existing key during ReKey. Previously, a caller who knew another user's key UID could create a replacement key and remove the original key's Name without authorization. Same fix applied to `ReKeyKeyPair`.
- **ReKey/ReKeyKeyPair privileged-user enforcement**: `ReKey` and `ReKeyKeyPair` now enforce the `privileged_users` Create-permission check. Since both operations create new cryptographic objects, unprivileged users are blocked when `privileged_users` is configured — consistent with `Create`, `CreateKeyPair`, `Import`, and `Register`.

## Testing

- **VAST Data integration test vector**: Updated to 16 steps (was 15) — added explicit `Revoke` of old key before `Destroy` since old key remains Active after ReKey. Sequence: DiscoverVersions → Create → AddAttribute (Name, ObjectGroup) → Activate → Locate → Get → GetAttributes → ReKey → Locate → Get → GetAttributes → Revoke old → Destroy old → Revoke new → Destroy new.
- **ReKey Locate By Name**: Updated to 9 steps — asserts old key State=Active (not Deactivated) after ReKey, adds explicit Revoke(old) before Destroy(old).
- **ReKey Deactivated Fails**: Updated to 7 steps — adds explicit Revoke(old) to transition it to Deactivated before verifying that a second ReKey on a non-Active key fails.
- **ReKey With Links**: Updated to 8 steps — adds Revoke(old) before Destroy(old) since old key remains Active after ReKey.
- **Privilege escalation: ReKey without permission**: New access control test vector — non-owner with Get-only grant cannot ReKey another user's key.
- **Privilege escalation: Activate without permission**: New access control test vector — non-owner with Encrypt-only grant cannot Activate another user's PreActive key.
- **Negative: Activate on destroyed key**: New test vector (`deactivate_pre_active`) — Create → Activate → Revoke → Destroy → Activate expects `Wrong_Key_Lifecycle_State`.
- **ReKeyKeyPair full test coverage**: 24 new test vectors exercising ReKeyKeyPair for RSA (2048/4096), EC (P-256/P-384/P-521), ML-KEM (768/1024), ML-DSA (65/87), SLH-DSA-SHA2-128f, Ed25519, X25519, and secp256k1. Includes double-rekey chain, deactivated-fails, change-algo-fails, locate-by-name, name-removed-from-old, old-key-still-active, no-public-link-fails, with-links, with-offset, RSA encrypt/decrypt round-trip, and EC sign/verify round-trip scenarios.
- **ReKey old key still decrypts**: Test vector verifying the old symmetric key remains functional (can still encrypt) after ReKey.
- **KMIP 1.4 protocol compliance**: 3 new test vectors exercising ReKey and ReKeyKeyPair through the KMIP 1.4 protocol path (both JSON and binary wire formats), verifying V14↔V21 struct conversion including `TemplateAttribute`↔`Attributes` and required-String↔`Option<UniqueIdentifier>` field mappings.
- **Privileged-user bypass: ReKey blocked**: New test (`pb05_non_privileged_user_cannot_rekey`) verifies that non-privileged users are denied ReKey even when they hold the Rekey permission on the key, because ReKey creates a new object.

## Documentation

- **VAST Data integration doc**: Updated workflow description and sequence diagram — old key remains Active after ReKey; VAST explicitly calls Revoke + Destroy on both old and new keys. Removed incorrect claim that ReKey deactivates the existing key.

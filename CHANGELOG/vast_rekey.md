## Bug Fixes

- **ReKey operation**: Fixed KMIP `ReKey` to create a new replacement key with a new UID instead of replacing key material in-place. Per KMIP 2.1 §6.1.46, the existing key is linked to the new key via `ReplacementObjectLink`/`ReplacedObjectLink` and the Name attribute is transferred; the existing key's **State is NOT changed** — the spec does not mandate deactivation. Callers wishing to retire the old key must issue an explicit `Revoke` afterwards.
- **ReKey spec correction**: Removed hallucinated deactivation of the existing key. KMIP 2.1 §6.1.46 Table 304 lists State only for the *replacement* key ("Set based on attribute values, such as dates"); the existing key's State is unaffected by ReKey. This matches observed VAST Data production behaviour where VAST explicitly calls `Revoke` + `Destroy` on the old key after rotation.
- **ReKey log/test wording**: Fixed log message and test comments that incorrectly stated "old key deactivated" — old key remains Active after ReKey per spec.
- **ReKey test cleanup**: VAST ReKey test now properly cleans up both the original and replacement keys (revoke + destroy each).

## Security

- **DDOS mitigation on `/hsm/status`**: The `GET /hsm/status` endpoint now requires explicit authentication (JWT, client certificate, or API token). Requests that only have the fallback default username are rejected with 401.
- **ReKey authorization** (COSMIAN-2026-017): Added ownership/permission check before modifying the existing key during ReKey. Previously, a caller who knew another user's key UID could create a replacement key and remove the original key's Name without authorization. Same fix applied to `ReKeyKeyPair`.
- **Activate authorization** (COSMIAN-2026-018): The Activate operation now uses `KmipOperation::Activate` for permission checks instead of `GetAttributes`. Previously, any user with any permission on an object could activate it.
- **CVE-2026-39373 / GHSA-fjrm-76x2-c4q4**: Upgrade `jwcrypto` from 1.5.6 to 1.5.7 in `.github/scripts/test/requirements-jose.txt`. Fixes JWE ZIP decompression bomb — 1.5.6 validated compressed input size (≤250 KB) but not the decompressed output size, allowing a crafted token to exhaust server memory.

## Testing

- **VAST Data integration test vector**: Updated to 16 steps (was 15) — added explicit `Revoke` of old key before `Destroy` since old key remains Active after ReKey. Sequence: DiscoverVersions → Create → AddAttribute (Name, ObjectGroup) → Activate → Locate → Get → GetAttributes → ReKey → Locate → Get → GetAttributes → Revoke old → Destroy old → Revoke new → Destroy new.
- **ReKey Locate By Name**: Updated to 9 steps — asserts old key State=Active (not Deactivated) after ReKey, adds explicit Revoke(old) before Destroy(old).
- **ReKey Deactivated Fails**: Updated to 7 steps — adds explicit Revoke(old) to transition it to Deactivated before verifying that a second ReKey on a non-Active key fails.
- **ReKey With Links**: Updated to 8 steps — adds Revoke(old) before Destroy(old) since old key remains Active after ReKey.
- **Privilege escalation: ReKey without permission**: New access control test vector — non-owner with Get-only grant cannot ReKey another user's key.
- **Privilege escalation: Activate without permission**: New access control test vector — non-owner with Encrypt-only grant cannot Activate another user's PreActive key.

## Documentation

- **VAST Data integration doc**: Updated workflow description and sequence diagram — old key remains Active after ReKey; VAST explicitly calls Revoke + Destroy on both old and new keys. Removed incorrect claim that ReKey deactivates the existing key.

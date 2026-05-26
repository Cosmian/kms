## Bug Fixes

- **ReKey operation**: Fixed KMIP `ReKey` to create a new replacement key with a new UID instead of replacing key material in-place. Per KMIP 2.1 §6.1.46, the existing key is linked to the new key via `ReplacementObjectLink`/`ReplacedObjectLink` and the Name attribute is transferred; the existing key's **State is NOT changed** — the spec does not mandate deactivation. Callers wishing to retire the old key must issue an explicit `Revoke` afterwards.
- **ReKey spec correction**: Removed hallucinated deactivation of the existing key. KMIP 2.1 §6.1.46 Table 304 lists State only for the *replacement* key ("Set based on attribute values, such as dates"); the existing key's State is unaffected by ReKey. This matches observed VAST Data production behaviour where VAST explicitly calls `Revoke` + `Destroy` on the old key after rotation.

## Testing

- **VAST Data integration test vector**: Updated to 16 steps (was 15) — added explicit `Revoke` of old key before `Destroy` since old key remains Active after ReKey. Sequence: DiscoverVersions → Create → AddAttribute (Name, ObjectGroup) → Activate → Locate → Get → GetAttributes → ReKey → Locate → Get → GetAttributes → Revoke old → Destroy old → Revoke new → Destroy new.
- **ReKey Locate By Name**: Updated to 9 steps — asserts old key State=Active (not Deactivated) after ReKey, adds explicit Revoke(old) before Destroy(old).
- **ReKey Deactivated Fails**: Updated to 7 steps — adds explicit Revoke(old) to transition it to Deactivated before verifying that a second ReKey on a non-Active key fails.
- **ReKey With Links**: Updated to 8 steps — adds Revoke(old) before Destroy(old) since old key remains Active after ReKey.

## Documentation

- **VAST Data integration doc**: Updated workflow description and sequence diagram — old key remains Active after ReKey; VAST explicitly calls Revoke + Destroy on both old and new keys. Removed incorrect claim that ReKey deactivates the existing key.

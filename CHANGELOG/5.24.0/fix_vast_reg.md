## Bug Fixes

### VAST Data Integration

- **Root cause**: Fix `GetAttributes` response silently dropping all vendor attributes (including `OperationPolicyName`) when a KMIP 1.4 client sends a default/all-attributes request (without explicit attribute name list). The `shape_kmip1_get_attributes_response` filter in `message.rs` was retaining only `vendor_identification == "x"` (which matches nothing real), effectively stripping `KMIP1:__Operation Policy Name__` from responses. Now preserves all user-facing vendor attributes and only removes the internal Cosmian tag.
- Fix `OperationPolicyName` attribute being silently dropped by `AddAttribute` — the attribute is now stored as a VendorAttribute (consistent with `Create` template behavior) and returned via `GetAttributes` to KMIP 1.4 clients
- Allow KMIP 1.x compatibility attributes (`vendor_identification="KMIP1"`) to be overwritten via `AddAttribute` when they already exist from the `Create` template, instead of rejecting with "Vendor Attribute already exists"

## Testing

- Add `test_vast_opn_returned_in_default_get_attributes`: verifies OPN is returned in a default (no explicit attribute list) `GetAttributes` response — directly tests the `message.rs` filter fix
- Add `test_vast_opn_add_attribute_persistence`: verifies `AddAttribute(OperationPolicyName)` is stored and returned by `GetAttributes`
- Add `test_vast_opn_survives_rekey`: verifies OPN is transferred to the replacement key after `ReKey`
- Add `test_vast_multi_key_locate_after_rekey`: verifies `Locate` returns the correct (new) UID after `ReKey` in a multi-key encryption group path
- Update VAST Data test vector from 16 to 17 steps: adds `AddAttribute(OperationPolicyName)` step and `GetAttributes` after `ReKey` asserting OPN preservation

## Documentation

- Update VAST Data integration docs: clarify OPN is stored (not dropped), add troubleshooting entry for "Rotate key fails" symptom, update verified date to June 2026

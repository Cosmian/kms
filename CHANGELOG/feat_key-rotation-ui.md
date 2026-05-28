## Features

- **CLI**: Add `set-rotation-policy` and `get-rotation-policy` subcommands under `ckms sym keys`
- **WASM**: Add `rekey_ttlv_request`, `parse_rekey_ttlv_response`, `set_rotate_interval_ttlv_request`, `set_rotate_offset_ttlv_request`, `set_rotate_name_ttlv_request`, and `parse_rotation_policy_response` bindings
- **UI**: Add Re-Key, Set Rotation Policy, and Get Rotation Policy pages under Symmetric Keys
- **UI**: Add Notifications bell component with unread count badge and drawer

## Bug Fixes

- **Server**: `GetAttributes` now returns rotation-policy attributes (`rotate_interval`, `rotate_offset`, `rotate_name`, `rotate_date`, `rotate_generation`, `rotate_latest`) which were previously ignored because the `Tag` enum lacks dedicated variants

## Testing

- Add Playwright E2E tests for key rotation flow (set/get policy, re-key, navigation, notifications bell)

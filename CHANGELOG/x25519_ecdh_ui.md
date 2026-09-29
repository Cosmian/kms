## Features

### Client / WASM
- Add a WASM export, `derive_key_asymmetric_ttlv_request` (with matching `parse_derive_key_asymmetric_ttlv_response`), building on `DeriveKey::new_asymmetric` for the Web UI and other WASM consumers.

### Web UI
- Add an "X25519 ECDH" derivation method to the Derive Key page, with private-key and peer-public-key selectors (reusing the existing key-picker/locate component), forcing the fixed 256-bit `SecretData` output contract enforced server-side.
- Add matching `en`/`zh-CN` i18n strings for the new form fields and introductory copy.

### CLI (`ckms`)
- Add `ckms derive-key --x25519 --private-key-id <ID> --peer-public-key-id <ID>` to close the CLI↔UI parity gap for the asymmetric X25519 ECDH derivation form, giving the Web UI capability a `ckms` counterpart. Mutually exclusive with `--key-id`/`--password`; `--salt` becomes optional (ignored for X25519).

## Testing

### Web UI
- Extend `derive-key-flow.spec.ts` with Playwright e2e coverage for the X25519 ECDH form (default derivation and custom output-ID variants), reusing the EC key-pair creation helper against the `X25519` curve.

### CLI (`ckms`)
- Add `test_derive_key_x25519` integration test covering the happy path (with `--derived-key-id`) and the required-argument error path for the new `--x25519` flag.

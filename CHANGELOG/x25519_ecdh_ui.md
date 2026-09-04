## Features

### Client / WASM
- Add a WASM export, `derive_key_asymmetric_ttlv_request` (with matching `parse_derive_key_asymmetric_ttlv_response`), building on `DeriveKey::new_asymmetric` for the Web UI and other WASM consumers.

### Web UI
- Add an "X25519 ECDH" derivation method to the Derive Key page, with private-key and peer-public-key selectors (reusing the existing key-picker/locate component), forcing the fixed 256-bit `SecretData` output contract enforced server-side.
- Add matching `en`/`zh-CN` i18n strings for the new form fields and introductory copy.

## Testing

### Web UI
- Extend `derive-key-flow.spec.ts` with Playwright e2e coverage for the X25519 ECDH form (default derivation and custom output-ID variants), reusing the EC key-pair creation helper against the `X25519` curve.

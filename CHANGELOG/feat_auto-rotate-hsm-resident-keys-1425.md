## Security

- **COSMIAN-2026-057**: Decrypt by a bare keyset name refuses modes without wrong-key detection (CBC, ECB, CTR, XTS, ChaCha20, FPE and RSA PKCS#1 v1.5) with `Feature_Not_Supported`, including stored parameters. Address the generation explicitly (`name@N`) for these modes. Bare HSM keyset decryption defaults to AES-GCM or RSA-OAEP-SHA256, never falling back to CBC or PKCS#1 v1.5.
- **COSMIAN-2026-058**: retired HSM generations are treated as `Deactivated` for Encrypt, Sign and MAC, with `Wrong_Key_Lifecycle_State`; Decrypt and verification still accept every generation. Protection eligibility uses a live, fail-closed head lookup; label/date writes invalidate cached metadata.
- **COSMIAN-2026-059**: HSM keys addressed by their UID now obey the configured KMIP algorithm policy, including keys never enrolled in a keyset.
- **COSMIAN-2026-060**: HSM re-key checks the `Rekey` permission before the object type and hides keys from callers without any grant.

## Features

### HSM

- Auto-rotation now rotates HSM-resident keys (#1425): due AES keys through `C_GenerateKey` and RSA/EC pairs through `C_GenerateKeyPair`, once per due date. The replacement keeps the interval and the old label is retired. The scheduler acts as the HSM admin and rotates only an enrolled keyset head with valid `CKA_START_DATE` / `CKA_END_DATE`; foreign PKCS#11 validity dates alone never trigger a rotation. A positive `SetAttribute RotateInterval` enrolls an unmarked key before the scheduler can use it. Renewal warnings apply to HSM keys.
- `ReKeyKeyPair` works on HSM private keys; the public key UID is the new private key UID + `_pk`. `Offset`, `Attributes` and Protection Storage Masks return `Feature_Not_Supported`.
- A never-enrolled HSM key is enrolled under its full base UID when a positive rotation interval is set or at its first manual re-key.
- Encrypt, Sign, MAC, Decrypt, Signature Verify and MAC Verify on an HSM keyset address (bare UID, `@latest`, `@first`, `@0`, `@N`) apply cryptography on the HSM, not in the KMS. On a FIPS build, AES-GCM Encrypt by keyset name therefore fails on an HSM that cannot generate the GCM IV (SoftHSM2, Kryoptic): encrypt with an HSM that generates the IV, or on a non-FIPS build.

## Bug Fixes

### HSM

- A non-extractable RSA key is served as a private/public key stub instead of a symmetric-key stub.
- `SetAttribute RotateInterval > 0` on an HSM public key is rejected (set it on the private key); `SetAttribute RotateAutomatic` on an HSM key is rejected with `Feature_Not_Supported` (use `RotateInterval 0` to disarm) instead of being accepted and ignored; rotation attributes in an HSM `Create` / `CreateKeyPair` are rejected instead of silently dropped.
- `ReKey` / `ReKeyKeyPair` on `name@first` / `name@0` of an HSM keyset whose generation 0 is retired is rejected instead of silently rotating the head.
- HSM `ReKey` / `ReKeyKeyPair`: a missing key returns `Item_Not_Found` (was `Invalid_Field`), a wrong object type returns `Invalid_Object_Type` (was `Feature_Not_Supported`). A missing explicitly addressed generation never redirects to the head.
- An HSM key at generation `i32::MAX` fails re-key with an error instead of aborting the server.
- `SetAttribute RotateInterval 0` (disarming an HSM rotation schedule) failed with `CKR_GENERAL_ERROR` on tokens that refuse an all-zero `CK_DATE`, such as the Utimaco simulator: an unset `CKA_START_DATE` / `CKA_END_DATE` is now written as an empty attribute first, then as a zeroed `CK_DATE` for tokens that refuse the empty form.

### Key rotation

- Signature Verify and MAC Verify by a bare keyset name try every generation until one verifies; they used to stop at the newest key's `Invalid` verdict.

## Documentation

- Split the HSM key rotation documentation into how-to, reference and explanation pages: keyset addressing per operation, retired generations, auto-rotation due rule and error reasons.

## Testing

- HSM keyset rotation runs against real PKCS#11 tokens: the server `test_hsm_all` (SoftHSM2, Kryoptic) and the Utimaco simulator task cover re-key of AES keys and key pairs, retirement of old generations, processing with every generation and, on tokens that store `CKA_START_DATE` / `CKA_END_DATE`, the auto-rotation scheduler. The shared PKCS#11 loader test, run by every HSM loader including the hardware Proteccio and Crypt2Pay jobs, checks that keyset labels keep object ids and lookups for AES keys and both halves of a key pair, and, where the token stores key dates, that dates can be set, elapse and be cleared.

## Features

### HSM

- Auto-rotation now rotates HSM-resident keys (#1425): due AES keys through `C_GenerateKey` and RSA/EC key pairs through `C_GenerateKeyPair`, once per due date. The replacement keeps the interval (`CKA_START_DATE` = rotation day, `CKA_END_DATE` = + interval) and the old key is retired in `CKA_LABEL`. The scheduler acts as the HSM admin. Renewal warnings now fire for HSM keys.
- `ReKeyKeyPair` works on HSM private keys; the public key UID is the new private key UID + `_pk`. `Offset`, `Attributes` and Protection Storage Masks return `Feature_Not_Supported`.
- An HSM key that never joined a keyset is enrolled under its full base UID at its first re-key (manual or automatic).
- Encrypt/Sign and Decrypt/Verify on an HSM keyset address (bare UID, `@latest`, `@first`, `@0`) now run on the HSM instead of exporting the key into the KMS; `@latest`, `@first` and `@0` are accepted as documented.

## Bug Fixes

### HSM

- `find_due_for_rotation` returns the HSM admin as owner and only the keyset head, so retired generations with a past `CKA_END_DATE` are not rotated again.
- A non-extractable RSA key is served as a private/public key stub instead of a symmetric-key stub.
- `SetAttribute RotateInterval > 0` on an HSM public key is rejected (set it on the private key); rotation attributes in an HSM `Create` / `CreateKeyPair` are rejected instead of silently dropped.
- Encrypt, Sign and MAC by HSM keyset name now run on the HSM instead of exporting the key and running in software; on a FIPS build, AES-GCM Encrypt by keyset name fails on an HSM that cannot generate the GCM IV.

## Documentation

- Document HSM auto-rotation, key-pair re-key and keyset addressing in `key_rotation/hsm.md`.

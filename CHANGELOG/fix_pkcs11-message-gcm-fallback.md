## Bug Fixes

### HSM
- Retry classic PKCS#11 AES-GCM when message-based encryption fails, before rejecting an HSM KEK at startup.
- Accept a caller-supplied 12-byte AES-GCM IV for HSM encryption only where the build and profile already allow a non-HSM-generated classic IV (non-FIPS with `supports_caller_iv`, or the FIPS development-token exception); reject empty, wrong-length, all-zero and unsupported-profile IVs before any driver call. `HsmStore` no longer rejects these requests itself, so KMIP and CLI callers reach that policy.
- Stop AES-GCM fallback when a message operation cannot be finalized, finalize message decryption before reporting its error, validate driver-reported output lengths, reject all-zero message-generated IVs, and keep GCM plaintext buffers zeroized on error paths.
- Stop tracing Crypt2Pay credentials in host preparation, keep its VPN/config files private, pass shell re-entry secrets through the environment instead of `nix-shell` command arguments, and install the vendor PKCS#11 libraries with explicit `0755` modes so the test user can still load them.

## Refactor

### HSM
- Separate session encryption/decryption dispatch from GCM, CBC, and OAEP parameter handling; preserve IV ownership, ciphertext framing, FIPS policy, and message-decryption errors without adding retries.

## Testing

### HSM
- Cover the complete GCM capability/IV-policy matrix, message fallback and precedence, stored-IV decryption, authentication failures, framing boundaries, and key-wrap misrouting; verify software-token variants and non-FIPS Proteccio/Crypt2Pay round trips and KMS startup.
- Add `mise run test:hsm-other` (CI matrix entry `other` in the `hsm` job, FIPS and non-FIPS, picked up by the existing `test:hsm-<type>` step): a PKCS#11 shim over SoftHSM2 boots the KMS with an HSM-backed KEK for both a v2 library (classic only) and a v3 library (message API attempted, then classic fallback), refusing caller AES-GCM IVs in FIPS and accepting them in non-FIPS.

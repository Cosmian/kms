## Bug Fixes

### HSM
- Retry classic PKCS#11 AES-GCM when message-based encryption fails, before rejecting an HSM KEK at startup.
- Accept a caller-supplied 12-byte AES-GCM IV for HSM encryption only where the build and profile already allow a non-HSM-generated classic IV (non-FIPS with `supports_caller_iv`, or the FIPS development-token exception); reject wrong-length, all-zero and unsupported-profile IVs before any driver call (an empty IV is treated as no IV). `HsmStore` no longer rejects these requests itself, so KMIP and CLI callers reach that policy.
- Decrypt AES-GCM through the classic API when a PKCS#11 v3 library's message-decrypt init answers `CKR_FUNCTION_NOT_SUPPORTED`/mechanism-unsupported (a v3 library whose message functions are unsupported stubs), so keys wrapped by an HSM key can be unwrapped; other init failures and authentication failures are still reported, never retried.
- Name every standard `CKR_*` return code in HSM errors (for example `CKR_KEY_HANDLE_INVALID`, previously reported as `CKR_UNKNOWN`), replace the misleading "data to encrypt is likely too big" message of a failing `C_Encrypt` length query, and explain in the key-wrap errors that some HSMs cannot wrap imported keys.
- Fix `ckms pkcs11 capabilities` reading a PKCS#11 v2.x function table returned by `C_GetInterface` as the longer v3.0 table, which read past its end and could end the command without output; a library without a v3.x table now reports every v3.0 function as not implemented.
- Remember per slot that a library refused the PKCS#11 v3 message API for AES-GCM as unsupported, so later encryptions and decryptions use classic AES-GCM directly instead of retrying the message API on every call.
- Stop AES-GCM fallback when a message operation cannot be finalized, finalize message decryption before reporting its error, validate driver-reported output lengths, reject all-zero message-generated IVs, and keep GCM plaintext buffers zeroized on error paths.
- Stop tracing Crypt2Pay credentials in host preparation, keep its VPN/config files private, pass shell re-entry secrets through the environment instead of `nix-shell` command arguments, and install the vendor PKCS#11 libraries with explicit `0755` modes so the test user can still load them.

## Refactor

### HSM
- Separate session encryption/decryption dispatch from GCM, CBC, and OAEP parameter handling; preserve IV ownership, ciphertext framing, FIPS policy, and message-decryption errors without adding retries.

## Testing

### HSM
- Cover the complete GCM capability/IV-policy matrix, message fallback and precedence, stored-IV decryption, authentication failures, framing boundaries, and key-wrap misrouting; verify software-token variants and non-FIPS Proteccio/Crypt2Pay round trips and KMS startup.
- Add `.mise/scripts/test/pkcs11_gcm_iv_probe.py` (and a C twin), a standalone probe that replays the KMS AES-GCM IV calls against any PKCS#11 library (HSM-generated, caller-chosen and NULL IV) and lists its exported v3.0 message symbols; `test:hsm:other` checks it against the FIPS and non-FIPS shims.
- Add `mise run test:hsm:nix-helpers` (nix-shell re-entry must not leak credentials into process arguments), run by the `hsm` CI job.
- Add `mise run test:hsm:other` (run by the `test:hsm` group in the `hsm` CI job, FIPS and non-FIPS): a PKCS#11 shim over SoftHSM2 boots the KMS with an HSM-backed KEK for a v2 library (classic only) and two v3 libraries whose message API refuses the operation (`CKR_MECHANISM_INVALID`, or `CKR_FUNCTION_NOT_SUPPORTED` stubs; message API attempted, then classic fallback), refusing caller AES-GCM IVs in FIPS and accepting them in non-FIPS.

## Documentation

### HSM
- Add a matrix of who generates the AES-GCM IV by KMS build, PKCS#11 library and HSM FIPS mode, with the startup errors to expect (`documentation/docs/hsm_support/hsm_operations.md`).

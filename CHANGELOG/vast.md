## Bug Fixes

- **KMIP 1.x / VAST integration**: Fix `Invalid Request: Failed to parse RequestMessage: unsupported KMIP 1 operation: ReKey` when VAST (or any KMIP 1.4 client) sends a `ReKey` request. Add `OperationEnumeration::ReKey` to the KMIP 1.4 message deserializer, implement `From<ReKey>` → KMIP 2.1 and `TryFrom<ReKeyResponse>` ← KMIP 2.1 conversion, and wire the `ReKey` operation into the KMIP 1.4 → 2.1 `Operation` conversion path. ([#845](https://github.com/Cosmian/kms/issues/845))
- **KMIP 1.x / VAST integration**: Fix `Invalid_Message` returned for `DeriveKey`, `ReCertify`, and `Check` KMIP 1.4 operations. Add match arms in the KMIP 1.4 message deserializer for all three operations; implement `From<DeriveKey>`/`TryFrom<DeriveKeyResponse>` and `From<Check>`/`TryFrom<CheckResponse>` bridges between KMIP 1.4 and KMIP 2.1; add `From<DerivationMethod>` and `From<DerivationParameters>` helper conversions; derive `Default` on `kmip_1_4::DerivationParameters` and `kmip_2_1::DerivationParameters`. ([#845](https://github.com/Cosmian/kms/issues/845))
- **Key wrapping / VAST integration**: Fix `cryptography.hazmat.primitives.keywrap.InvalidUnwrap` when VAST performs its KEK/DEK wrapping workflow. The KMS defaulted to `BlockCipherMode::AESKeyWrapPadding` (RFC 5649) when no `CryptographicParameters` were supplied in a `Get` with `KeyWrappingSpecification`, but pykmip-based clients such as VAST Data use `aes_key_unwrap` which expects standard RFC 3394 output. Default is now `AESKeyWrap` (RFC 3394), matching the KMIP spec; `AESKeyWrapPadding` (RFC 5649) is used only when explicitly requested. ([#845](https://github.com/Cosmian/kms/issues/845))

## Testing

- **KMIP 1.x / VAST integration**: Add non-regression test suite `crate/server/src/tests/ttlv_tests/integrations/vast.rs` with five tests covering `ReKey`, `Check`, `DeriveKey`, `ReCertify`, and the KEK/DEK RFC 3394 wrapping round-trip (`test_vast_get_dek_wrapped_by_kek`) to prevent future regressions. ([#845](https://github.com/Cosmian/kms/issues/845))

Closes #845

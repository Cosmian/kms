## Security

- `DeriveKey` requires the Create permission, like the other operations that create objects; Crypto Officers are unaffected (COSMIAN-2026-071, [#1492](https://github.com/Cosmian/kms/issues/1492))
- The JOSE and SPIRE transit routes apply the `kmip.policy_id` request policy to every KMIP request they send (`Create`, `CreateKeyPair`, `Import`, `Encrypt`, `Decrypt`, `Sign`, `SignatureVerify`, `MAC`), with the same message as the KMIP endpoint; a SPIRE policy denial is a client error, not HTTP 500 (COSMIAN-2026-071)
- Wrap and unwrap return `does not exist or is not accessible` (`Permission_Denied`) for a missing key and for any key the caller may not use, whatever its type, state or usage mask; owners still get the specific error (COSMIAN-2026-071)

## Bug Fixes

### KMIP

- Batch `Undo` keeps the usage-limit budget consumed by an undone item (its output was already returned); other changes to Usage Limits are still undone

---

Closes #1492

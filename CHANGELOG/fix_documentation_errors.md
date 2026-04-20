# Fix Documentation Errors Found by Automated HTTP Testing

## Bug Fixes

### Documentation

Automated HTTP testing against a live KMS server (`verify_docs.py`) revealed the following
documentation errors across several KMIP and anonymization example pages:

- **anonymization.md — `word-pattern-mask` response**: The `\+[\d\s\-]+` regex consumes the
  trailing space before "or", so the correct result is `Call me at [PHONE]or [PHONE]` (not
  `[PHONE] or [PHONE]` as previously shown).

- **`_create.md` / `_get.md` — key state after Create**: Examples implying `Active` state
  immediately after `Create` are misleading. Without an `ActivationDate` attribute, keys are
  created in `PreActive` state and require an explicit `Activate` call to become usable.

- **`_get.md` — `Get` lifecycle description**: The implementation note incorrectly stated
  `Get` is restricted to `Active` objects only. `Get` is also allowed for `Pre-Active` and
  `Compromised` objects; only `Deactivated`, `Destroyed`, and `Destroyed Compromised` keys
  require `Export`.

- **`_get.md` — `Object` response wrapper tag**: All five response examples used `"tag": "Object"`
  to wrap the key block. The server returns the KMIP object-type-specific tag (`SymmetricKey`,
  `PrivateKey`, `Certificate`, etc.) instead of the generic `Object`.

- **`_revoke.md` — `RevocationReason` format**: The request example showed
  `"type": "TextString"` for `RevocationReason`. KMIP 2.1 requires a `Structure` containing
  `RevocationReasonCode` as an `Enumeration` (e.g. `KeyCompromise`).

- **`_revoke.md` — `Get` after revoke**: The text stated "Get will return an error" after any
  revocation. This is only true for `Deactivated` state. Revoking with reason `KeyCompromise`
  places the key in `Compromised` state, where `Get` is still allowed.

- **`_hash.md` — section title mismatch**: The "Simple hash" section heading said "SHA256"
  but the JSON request body used `SHA3512`.

- **`_hash.md` — Response 3 (Final) wrong hash value**: The documented final streaming hash
  (`511BDAFD…`, 63 bytes) was incorrect — the server returns `51A2F7FC…` (64 bytes / 128 hex
  chars). The Request 3 `CorrelationValue` was also wrong.

- **`_mac.md` — `Data` → `MACData` response tag**: All MAC response examples used `"tag": "Data"`
  for the output. The server returns `"tag": "MACData"`.

- **`_mac.md` — simple MAC value is a plain hash**: The documented simple MAC response value
  was identical to the SHA3-512 plain hash of the same data — a keyed HMAC cannot match an
  un-keyed hash of the same input. This was a copy-paste error; replaced with a representative
  placeholder.

- **`_mac.md` — streaming MAC Response 2 returns `MACData` not `CorrelationValue`**: The server
  finalizes MAC computation eagerly on each call, returning `MACData` even for middle-step
  requests with `FinalIndicator: false`. Updated example and added an implementation note.

- **`_signature.md` — `InitIndicator` and `FinalIndicator` both `true`**: Both Sign and
  SignatureVerify request examples set `InitIndicator: true` alongside `FinalIndicator: true`.
  The server rejects this combination. For a single-step operation, use `InitIndicator: false`
  with `FinalIndicator: true`.

- **`_signature.md` — Sign response placeholder size**: The `SignatureData` placeholder was
  32 bytes (64 hex chars). RSA-2048 signatures are 256 bytes (512 hex chars); updated
  placeholder accordingly.

# HSM delegation review fixes

## Security

- Reject SHA-1 RSA signatures in FIPS mode on the HSM-delegated pre-hashed path too: a
  20-byte `digested_data` was signed as a SHA-1 PKCS#1 v1.5 `DigestInfo` through raw
  `CKM_RSA_PKCS`, bypassing the FIPS gate that only blocked `CKM_SHA1_RSA_PKCS`

## Bug Fixes

### HSM

- Only infer the RSA PKCS#1 v1.5 hash from the input length when the input is a digest
  (`digested_data`); a raw message with no explicit hash always signs with SHA-256 instead
  of silently switching to SHA-1/SHA-384/SHA-512 for 20/48/64-byte messages
- Reject a `CryptographicAlgorithm` that does not match the key family (e.g. `ECDSA` on an
  RSA key) with a clear KMIP error instead of an opaque PKCS#11 mechanism error
- Report a malformed DER ECDSA signature as invalid in HSM `SignatureVerify` instead of
  returning an operation error
- Pool only read-write PKCS#11 sessions (`SlotManager::checkout_session` no longer takes an
  ignored `read_write` flag)

### DB

- Keyset re-key eligibility and HSM latest-generation selection bypass the `RotateNameCache`,
  so they are never decided on stale keyset state (e.g. a rotation done by another KMS node)
- `RotateNameCache` is invalidated by keyset name for all owners and generation filters, and
  by member UID on update, state change (revoke/destroy), delete and HSM re-label; empty
  results are no longer cached

### PKCS#11

- A signature cached by a `C_Sign` length query is only reused for the same data; a
  follow-up call over different data is signed again instead of returning the earlier
  signature

## Documentation

- Document the `RotateNameCache` invalidation and multi-node consistency model, and the
  virtual-memory cost of the server's 16 MiB `RUST_MIN_STACK` default

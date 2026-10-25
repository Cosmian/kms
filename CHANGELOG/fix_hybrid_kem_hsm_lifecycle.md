# HSM-wrapped hybrid KEM key lifecycle

## Bug Fixes

- Hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768` / `X448MLKEM1024`) now work when the server `key_encryption_key` is stored in an HSM: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`.
    - Wrap: `ByteString`-only `Raw`, `ConfigurableKEM*` and `CoverCrypt*` asymmetric keys are wrapped as raw bytes instead of going through OpenSSL (Create, Import, ReKeyKeyPair, Export with a `KeyWrappingSpecification` using `NoEncoding`).
    - Unwrap: `ConfigurableKEM*` keys are decoded on unwrap (Encrypt/Decrypt after a restart, `default_unwrap_type`, Export/Import with `NotWrapped`).
    - Export: a PQC/hybrid KEM key can be exported with its own stored `KeyFormatType`.
    - TTLV: `ConfigurableKEM*` key material can be deserialized from TTLV, so TTLV-wrapped keys (`ckms keys export --wrap-key-id ... -f json-ttlv`, then import) can be unwrapped and used.
- Unwrapping with a KMS wrapping key now works when that wrapping key is itself wrapped (e.g. by the HSM KEK): it is unwrapped first and its stored usage mask is checked, as already done when wrapping.
- `ConfigurableKEM` hybrid keys (ML-KEM + P-256/X25519) follow least privilege and the KMIP usage-mask rules:
    - A requested `CryptographicUsageMask` is kept as is instead of being OR-ed with `Unrestricted`. Without one, the private key gets `Decrypt` and the public key `Encrypt`; `ckms pqc keys create` no longer requests `Unrestricted`. Existing keys keep their mask.
    - Per-key `PrivateKeyAttributes`/`PublicKeyAttributes` inherit the `CommonAttributes` (tags, curve, ML-KEM variant) instead of replacing them, which also applies to `ReKeyKeyPair`.
- KMIP `Encrypt` with a `ConfigurableKEM` public key keeps its response contract: `Data` is the serialized `(shared secret, encapsulation)` tuple and `IVCounterNonce` is empty; only the encapsulation component is decapsulated. This is now covered by regression tests, in software and with an HSM KEK. ML-KEM and native hybrid KEMs keep returning the secret in `Data` and the encapsulation in `IVCounterNonce`.
- KEM `Encrypt` (ML-KEM, native hybrid, `ConfigurableKEM`) rejects non-empty `Data` instead of silently ignoring it.
- Algorithm policy: a `ConfigurableKEM` key is checked on every use, not only at creation, against both its ML-KEM variant and its curve, read from the serialized key rather than from its KMIP attributes, so an imported key with relabelled or stripped attributes cannot bypass the policy; `X25519MLKEM768` and `X448MLKEM1024` are in the policy scope and in the `DEFAULT` allowlist (non-FIPS), where they were previously always denied.
- `ckms bench`: the configurable KEM decapsulation benchmark now decapsulates the encapsulation component of the packed result instead of the whole tuple.

## Testing

- Add a SoftHSM2-backed hybrid KEM lifecycle test (`tests::hsm::hybrid_kem_dek`), TTLV-wrapped import tests (export wrapped by a software AES key, and client-side wrap by the HSM KEK), a wrap/unwrap unit test (`NoEncoding` and TTLV) for `ByteString`-only KEM keys, and a TTLV round-trip test for `ConfigurableKEM*` key values.
- Add `tests::configurable_kem_tests` (usage masks, encapsulation round trip, plaintext and `Sign` refusal, `Locate`, `ReKeyKeyPair`, revocation, policy on use including relabelled and stripped imports) and make `ckms pqc` KEM tests compare the decapsulated secret with the encapsulated one.

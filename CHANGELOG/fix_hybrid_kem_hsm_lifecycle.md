# HSM-wrapped hybrid KEM key lifecycle

## Bug Fixes

- Hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768` / `X448MLKEM1024`) now work when the server `key_encryption_key` is stored in an HSM: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`.
    - Wrap: `ByteString`-only `Raw`, `ConfigurableKEM*` and `CoverCrypt*` asymmetric keys are wrapped as raw bytes instead of going through OpenSSL (Create, Import, ReKeyKeyPair, Export with a `KeyWrappingSpecification`).
    - Unwrap: `ConfigurableKEM*` keys are decoded on unwrap (Encrypt/Decrypt after a restart, `default_unwrap_type`, Export/Import with `NotWrapped`).
    - Export: a PQC/hybrid KEM key can be exported with its own stored `KeyFormatType`.

## Testing

- Add a SoftHSM2-backed hybrid KEM lifecycle test (`tests::hsm::hybrid_kem_dek`) and a wrap/unwrap unit test for `ByteString`-only KEM keys.

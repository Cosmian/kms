# HSM-wrapped hybrid KEM key lifecycle

## Bug Fixes

- Hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768` / `X448MLKEM1024`) now work when the server `key_encryption_key` is stored in an HSM: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`.
    - Wrap: `ByteString`-only `Raw`, `ConfigurableKEM*` and `CoverCrypt*` asymmetric keys are wrapped as raw bytes instead of going through OpenSSL (Create, Import, Export with a `KeyWrappingSpecification`).
    - Unwrap: `ConfigurableKEM*` keys are decoded on unwrap (Encrypt/Decrypt after a restart, `default_unwrap_type`, Export/Import with `NotWrapped`).
    - Export: a PQC/hybrid KEM key can be exported with its own stored `KeyFormatType`.
    - TTLV: `ConfigurableKEM*` key material can be deserialized from TTLV, so TTLV-wrapped keys (`ckms keys export --wrap-key-id ... -f json-ttlv`, then import) can be unwrapped and used.
    - Backport of #1268: import and export skip the OpenSSL round-trip for `ConfigurableKEM` and native hybrid KEM keys.
- Unwrapping with a KMS wrapping key now works when that wrapping key is itself wrapped (e.g. by the HSM KEK): it is unwrapped first and its stored usage mask is checked, as already done when wrapping.

## Testing

- Add a SoftHSM2-backed hybrid KEM lifecycle test (`tests::hsm::hybrid_kem_dek`), TTLV-wrapped import tests (export wrapped by a software AES key, and client-side wrap by the HSM KEK), a wrap/unwrap unit test (`NoEncoding` and TTLV) for `ByteString`-only KEM keys, and a TTLV round-trip test for `ConfigurableKEM*` key values.
- Fix the stale `test_toml` snapshot (`rate_limit_per_second`, `otlp_allow_insecure`) in `crate/server/src/main.rs`.

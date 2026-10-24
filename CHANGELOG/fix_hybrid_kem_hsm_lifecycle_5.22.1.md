# HSM-wrapped hybrid KEM key lifecycle

## Bug Fixes

- Hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768` / `X448MLKEM1024`) now work when the server `key_encryption_key` is stored in an HSM: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`.
    - Wrap: `ByteString`-only `Raw`, `ConfigurableKEM*` and `CoverCrypt*` asymmetric keys are wrapped as raw bytes instead of going through OpenSSL (Create, Import, Export with a `KeyWrappingSpecification`).
    - Unwrap: `ConfigurableKEM*` keys are decoded on unwrap (Encrypt/Decrypt after a restart, `default_unwrap_type`, Export/Import with `NotWrapped`).
    - Export: a PQC/hybrid KEM key can be exported with its own stored `KeyFormatType`.
    - TTLV: `ConfigurableKEM*` key material can be deserialized from TTLV, so TTLV-wrapped keys (`ckms keys export --wrap-key-id ... -f json-ttlv`, then import) can be unwrapped and used.
    - Backport of #1268: import and export skip the OpenSSL round-trip for `ConfigurableKEM` and native hybrid KEM keys.
- Unwrapping with a KMS wrapping key now works when that wrapping key is itself wrapped (e.g. by the HSM KEK): it is unwrapped first and its stored usage mask is checked, as already done when wrapping.
- `ConfigurableKEM` hybrid keys (ML-KEM + P-256/X25519) follow least privilege and the KMIP usage-mask rules:
    - A requested `CryptographicUsageMask` is kept as is instead of being OR-ed with `Unrestricted`. Without one, the private key gets `Decrypt` and the public key `Encrypt`; `ckms pqc keys create` no longer requests `Unrestricted`. Existing keys keep their mask.
    - Per-key `PrivateKeyAttributes`/`PublicKeyAttributes` inherit the `CommonAttributes` (tags, curve, ML-KEM variant) instead of replacing them.
- KMIP `Encrypt` with a `ConfigurableKEM` public key returns the shared secret in `Data` and the encapsulation in `IVCounterNonce`, like ML-KEM and native hybrid KEMs; it used to pack both into `Data`, so the Web UI encapsulation page downloaded an unusable file. KMIP clients parsing the old packed format must be updated (`ckms` and the Web UI already read the new one).
- KEM `Encrypt` (ML-KEM, native hybrid, `ConfigurableKEM`) rejects non-empty `Data` instead of silently ignoring it.
- Algorithm policy: a `ConfigurableKEM` key is checked on every use, not only at creation, against both its ML-KEM variant and its curve; `X25519MLKEM768` and `X448MLKEM1024` are in the policy scope and in the `DEFAULT` allowlist (non-FIPS), where they were previously always denied.
- `ckms bench`: the configurable KEM decapsulation benchmark now decapsulates the actual encapsulation.

## Testing

- Add a SoftHSM2-backed hybrid KEM lifecycle test (`tests::hsm::hybrid_kem_dek`), TTLV-wrapped import tests (export wrapped by a software AES key, and client-side wrap by the HSM KEK), a wrap/unwrap unit test (`NoEncoding` and TTLV) for `ByteString`-only KEM keys, and a TTLV round-trip test for `ConfigurableKEM*` key values.
- Add `tests::configurable_kem_tests` (usage masks, encapsulation round trip, plaintext and `Sign` refusal, `Locate`, revocation, policy on use) and make `ckms pqc` KEM tests compare the decapsulated secret with the encapsulated one.
- Fix the stale `test_toml` snapshot (`rate_limit_per_second`, `otlp_allow_insecure`) in `crate/server/src/main.rs`.

## Dependencies

- Bump the workspace version to 5.22.1 and pin the internal path dependencies with `=5.22.1`, so that `cargo publish --dry-run` verifies the local 5.22.1 crates instead of newer 5.2x releases already on crates.io (a caret requirement matched them, and `cosmian_kms_crypto` 5.25.0 does not compile against `openssl` 0.10.79).
- Fix the RUSTSEC advisories published since 5.22.0: `h2` (RUSTSEC-2026-0258, `actix-web` 4.17), `tokio` (RUSTSEC-2026-0386), `lru` 0.18 (RUSTSEC-2026-0253), `tokio-postgres`/`postgres-protocol` (RUSTSEC-2026-0178/0179/0180, with `aes-kw` 0.3.1), `quick-xml` 0.42 (RUSTSEC-2026-0194/0195) and `mysql_async` 0.37 without the `derive` feature (RUSTSEC-2026-0173).
- Ignore RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, no 0.5.x patch) in `deny.toml` and `.cargo/audit.toml`, with its reason.

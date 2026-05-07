## Features

### CNG KSP

- Fix `test_sign_with_rsa_key`: RSA key pairs now set `activation_date` in `CreateKeyPair`
  `common_attributes` so they are created in `Active` state (keys without an activation date
  were created in `PreActive` state and rejected by the KMS sign operation).
- Fix `test_list_cng_keys`: `GetAttributes` in `list_cng_keys` now explicitly requests the
  vendor tag attribute (`cosmian:tag`) so that `extract_cng_name_from_tags` can resolve the
  CNG key name (the default `attribute_reference: None` excludes the tag vendor attribute).
- Fix feature propagation: add `test_kms_server/non-fips` to the `non-fips` feature of the
  `cosmian_kms_cng_ksp` crate so that `cosmian_kms_server_database` is compiled with the
  correct `non-fips` features when running single-crate tests.
- Add `revoke_key` backend function and update all test cleanup to revoke keys before
  destroying them (KMIP requires Active keys to be revoked before destruction).
- Add `cosmian_kms_cng_ksp_verify` standalone tool that loads and exercises all CNG KSP
  backend functions (RSA/EC key creation, signing, encryption, key listing, export, and
  lifecycle management).
- Implement `verify_signature` backend function using the KMIP `SignatureVerify` operation,
  enabling RSA PKCS1v15, RSA-PSS, and ECDSA signature verification through the KMS.
- Fix `digital_signature_algorithm` in `sign_hash` and `verify_signature` to explicitly set
  the algorithm (e.g. `SHA256WithRSAEncryption` for PKCS1v15, `RSASSAPSS` for PSS) instead
  of leaving it `None`, which caused the server to default to PSS for all RSA signatures.
- Parse `pv_padding_info` in `sign_hash`, `verify_signature`, `encrypt`, and `decrypt` NCrypt
  functions to honor the hash algorithm and salt length from CNG padding info structs
  (`BCRYPT_PKCS1_PADDING_INFO`, `BCRYPT_PSS_PADDING_INFO`, `BCRYPT_OAEP_PADDING_INFO`).
- Implement `EnumAlgorithms` to return supported algorithms (RSA, ECDSA P-256/P-384/P-521,
  ECDH P-256/P-384/P-521) with operation class filtering.
- Update `delete_key` to revoke both private and public keys before destroying them.
- Add EC P-384 and P-521 key pair creation and signing tests.
- Add RSA-PSS signing, RSA/ECDSA signature verification, and RSA OAEP encrypt/decrypt tests.
- Fix `encrypt` using private key UID instead of public key UID — added `pub_uid()` accessor
  to `CngKeyCtx` and updated the encrypt function in `provider.rs` to use it.
- Rewrite `cosmian_kms_cng_ksp_verify` to dynamically load the CNG KSP DLL and call exported
  NCrypt functions through the `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`, instead of linking
  directly to the backend module. This verifies the DLL as an external consumer would.

## Documentation

- Replace ASCII text diagrams with Mermaid diagrams in `windows_cng_ksp.md` integration docs.

## CI

- Add `test_cng_ksp.ps1` end-to-end integration test script that builds the CNG KSP DLL,
  starts a local KMS server, registers the KSP, runs the DLL surface verification tool,
  Rust lib tests, and ckms CLI CNG commands.
- Add `test-cng-ksp` job to `test_windows.yml` CI workflow to run the CNG KSP integration
  tests on every PR and push.

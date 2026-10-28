## Features

### HSM

- Add `key_encryption_key_wrapping_algorithm` (`aes-gcm`, `aes-key-wrap`, `aes-key-wrap-padding`, `rsa-oaep`; env `KMS_KEY_ENCRYPTION_KEY_WRAPPING_ALGORITHM`) to choose how keys are wrapped at rest by `key_encryption_key`. Unset keeps AES-GCM for an HSM AES key, RSA-OAEP (SHA-256) for an HSM RSA key and AES-KWP for a software AES key; a software RSA key requires `rsa-oaep`.
- HSM wrapping keys support AES-KW (NIST SP 800-38F, RFC 3394) and AES-KWP (RFC 5649) and honour the wrapping mode requested on Export/Get; wrapped objects record the mode actually used. Objects wrapped by earlier versions still unwrap.
- At startup, the server checks that an HSM AES key encryption key can wrap with its configured mode. For AES-KW/KWP it sets `CKA_WRAP`/`CKA_UNWRAP` once on keys created by earlier versions, only on a slot that offers AES key wrap, and restores them when that does not fix the wrapping; otherwise it stops with an actionable error.

## Bug Fixes

### Crypto

- Unwrap AES-GCM-wrapped keys with 128- and 192-bit key encryption keys; unwrapping always assumed AES-256.
- Wrapping or encrypting with an explicit RSA algorithm on an HSM private-key UID now uses the matching public key, as the default algorithm already did.

### HSM

- FIPS builds use the PKCS#11 v3.0 message API or an HSM-generated AES-GCM IV for production HSMs (FIPS 140-3 IG C.H); an HSM providing neither fails with a message pointing to `key_encryption_key_wrapping_algorithm = "aes-key-wrap-padding"` (other GCM failures keep their own cause). Only the SoftHSM2 and Kryoptic development tokens retain caller-supplied IVs. The Crypt2pay simulator's FIPS suite (`test_crypt2pay_simulator_all`, outside the hardware `test_hsm_crypt2pay` filter) verifies rejection when no IV is generated, without weakening the production Crypt2pay policy; the PKCS#11 benchmark probes AES-GCM once and skips it on such an HSM. `hsm_model = "other"` is now treated as a FIPS-validated module.

### CLI / UI

- Remove the `--authenticated-additional-data` export option and the matching Web UI fields: the value was silently ignored since KMS v5.

## Testing

- Server tests build in-process KMS instances only through `test_kms()` / `test_kms_with_config()`, enforced by the `no-direct-kms-instantiate` pre-commit hook; `test_kms_server` singletons share one startup helper.

## CI

- `/ci-fix` recognises lost hosted runners and reruns them instead of committing; prompts matching `.github/copilot-instructions.md` § Automatic skill routing load the matching skill automatically in OMP sessions, ignoring fenced/inline code, quoted or diff lines and negated clauses ("do not edit …").

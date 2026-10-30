## Features

### KMIP
- KMIP 2.1 Ping (§6.1.36): empty request, empty response payload; advertised by Query and allowed for Operators.

## Bug Fixes

### KMIP
- Locate returns Located Items whenever every store returned all matches and no Offset Items was given, also with Maximum Items set.
- Create Split Key keeps a requested future Activation Date (shares stay Pre-Active); Add Attribute works on Split Key shares.
- Validate decodes its `Certificate` list as Certificate structures (Certificate Type + Certificate Value, KMIP 2.1 Table 340) instead of bare byte strings, so certificates sent over TTLV are no longer ignored. The Rust type `Validate.certificate` is now `Option<Vec<Certificate>>`.
- MAC and MAC Verify infer the HMAC algorithm from the key's Cryptographic Algorithm attribute when neither the request nor the key block gives one (Table 259).
- Hash supports SHA-224.
- Export and Get accept a Key Format Type together with a Key Wrapping Specification (private and public keys): the key is converted to the requested format, then wrapped (§6.1.19).
- Wrapping a byte-string private or public key with No Encoding keeps the key's own format (PKCS#1, SEC1, …) instead of re-encoding it as PKCS#8 / SPKI, so unwrap restores the format recorded in the key block.
- PKCS#12 import and export take the container password from the Active Secret Data designated by the PKCS#12 Password Link (`Bad Password` otherwise, §6.1.19). An identifier that designates no accessible object is still read as the literal password.

## Testing

- `mise run test:kmipkit` (non-FIPS, needs Docker): runs the live tests of the external [KMIPKit](https://github.com/NeverWe1come/KMIPKit) KMIP 2.1 client (pinned commit) against a local server over binary TTLV + mTLS (fast gate: `cosmian_kms_*` and `lifecycle::` tests; `--full` runs every family, ~35 min, local only). Wired into `test_all.yml` as `kmipkit` (non-FIPS only).

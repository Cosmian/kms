## Testing

- Rewrite JOSE interoperability test suite to use JOSE REST key creation exclusively (`POST /v1/crypto/keys`) — eliminates all KMIP Create/Import for key provisioning
- Add full bidirectional interop coverage with Python `jwcrypto`: Direction A (KMS generates → KMS operates → jwcrypto validates), Direction B (jwcrypto generates → REST import → both operate), Direction C (KMS generates → export → jwcrypto operates → KMS validates)
- Add `generate-jwk` subcommand to `jose_interop_helper.py` for jwcrypto-originated key generation (RSA, EC, OKP, oct)
- Add 8 new Direction B tests (E40–E47): EC P-256/P-384/P-521, RSA, oct encryption, HMAC, Ed25519 key import from jwcrypto-generated JWKs

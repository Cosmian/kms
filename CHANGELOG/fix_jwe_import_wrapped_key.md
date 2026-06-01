## Features

- Add `POST /v1/crypto/keys/unwrap` endpoint for RSA-OAEP CEK unwrapping without key exposure
    - Decrypts the wrapped CEK using the private key referenced in the JWE protected header
    - Imports the symmetric key as an Active KMIP object in the KMS database
    - Returns the key identifier (`kid`), key type, algorithm, and allowed operations
    - Supports `RSA-OAEP` and `RSA-OAEP-256` algorithms with `A128GCM`, `A192GCM`, `A256GCM`

## Testing

- Add 6 integration tests for the unwrap endpoint (round-trip, RSA-OAEP-256, error cases)
- Add 8 JOSE test vectors: 4 round-trip vectors (`unwrap_rsa_oaep_*.json`) and 4 error vectors (`error_unwrap_*.json`)

## Documentation

- Update `documentation/docs/integrations/jose/jwe_decryption.md` with the new key unwrap flow
- Update `documentation/docs/integrations/jose/rest_crypto_api.md` with `POST /v1/crypto/keys/unwrap` endpoint
- Regroup JOSE docs under `documentation/docs/integrations/jose/`
- Register `rest_crypto_api.md` in `documentation/mkdocs.yml` nav

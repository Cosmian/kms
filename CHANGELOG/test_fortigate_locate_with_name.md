## Features

- Support JWK key import in `POST /v1/crypto/keys` endpoint: symmetric (oct), EC (P-256, P-384, P-521), RSA, and OKP (Ed25519, non-FIPS)
- Allow `SignatureVerify` operation on private keys (enables verify for imported keys without a paired public key)
- Allow `RSA-OAEP encrypt` with imported RSA private keys (extract public component when no linked public key exists)
- Accept HMAC keys longer than the minimum required size (per RFC 7518 §3.2)

## Testing

- Add 15 JOSE non-regression vectors for JWK import: `import_oct_mac_hs256`, `import_oct_encrypt_a256gcm`, `import_ec_sign_es256`, `import_ec_sign_es384`, `import_rsa_sign_rs256`, `import_rsa_encrypt_oaep256`, `import_okp_sign_eddsa`, plus 8 error vectors
- Add 3 non-regression test vectors for FortiGate KMIP Locate name filtering:
    - `fortigate_locate_many_similar_names`: 8 keys with confusingly similar names, verifies strict isolation (40 steps)
    - `fortigate_locate_multi_tunnel`: 6 keys across 3 tunnel configs, verifies no cross-tunnel contamination (30 steps)
    - `fortigate_locate_no_match`: proves no partial/substring matching (substring, superstring, non-existent names all return 0 results)

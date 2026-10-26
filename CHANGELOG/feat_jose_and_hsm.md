# JOSE RSA-OAEP with HSM keys and external public keys

## Breaking Changes

### Server

- `GET /.well-known/jwks.json` now derives the `use` and `alg` of RSA keys from the public key usage mask:
  `Verify` only publishes `use=sig` with `alg=RS256/384/512`, `Encrypt`/`WrapKey` only publishes `use=enc` without
  `alg`, and keys carrying both (or neither, such as HSM public keys) publish neither. Keys without a usage mask are
  unchanged. Clients that assumed every RSA JWK is `use=sig`/`RS*` must select keys by `kid`.

## Features

### Server

- `POST /v1/crypto/decrypt` with `RSA-OAEP` / `RSA-OAEP-256` unwraps the CEK through the HSM crypto oracle when
  `kid` designates an HSM key pair (public `kid` resolved through `PrivateKeyLink` or the `_pk` suffix), so the
  private key never leaves the HSM. SoftHSM2 2.6.1 cannot perform RSA-OAEP decryption with explicit parameters;
  use another HSM (e.g. Kryoptic).
- `POST /v1/crypto/keys` imports a public-only RSA key (`n` and `e` without `d`, `key_ops` among `encrypt`,
  `wrapKey`, `verify`) and accepts a caller-chosen `kid` on every import (`kid` on key generation is rejected).
- `POST /v1/crypto/encrypt` accepts `cek_kid` (RSA-OAEP / RSA-OAEP-256 only): a KMS AES key, active and
  extractable, with Export permission, used as the CEK of a complete JWE.

## Testing

- Add `mise run test:jose-hsm` (JWKS, RSA-OAEP-256 decrypt through a Kryoptic HSM, `cek_kid` encryption).

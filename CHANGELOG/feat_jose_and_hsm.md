# JOSE RSA-OAEP with HSM keys and external public keys

## Breaking Changes

### Server

- `GET /.well-known/jwks.json` now derives the `use` and `alg` of RSA keys from the public key usage mask:
  `Verify` only publishes `use=sig` with `alg=RS256/384/512`, `Encrypt`/`WrapKey` only publishes `use=enc` without
  `alg`, and keys carrying both (such as HSM RSA public keys) or neither publish neither. Keys without a usage mask are
  unchanged. Clients that assumed every RSA JWK is `use=sig`/`RS*` must select keys by `kid`.
- `POST /v1/crypto/keys` with RSA `n` and `e` but no `d` now imports a public key instead of generating a key
  pair, and a `kid` on a generation request is rejected with HTTP 400.

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

- Add `mise run test:jose-hsm` (JWKS, RSA-OAEP-256 decrypt through a Kryoptic HSM, `cek_kid` encryption);
  `mise run test:jose` now runs it too.
- `test_hsm_all` also runs `export_key_bytes`, `non_extractable_key_bytes` and `jose_decrypt` (the latter
  skipped on SoftHSM2).
- Add `test_hsm_crypt2pay_exportable_aes_key` to real-Crypt2Pay CI: export an AES-256 key and use its bytes to decrypt HSM-produced AES-GCM ciphertext. The hardware task runs the `test_hsm_crypt2pay` prefix serially, including the aggregate suite and export regression; the simulator task remains aggregate-only. Finish with cleanup of reserved `kms-test-*` objects, including leftovers from earlier runs, while preserving non-test objects. Reuse the existing C2P key-directory watcher workaround for hardware tests.

## Bug Fixes

- Export/Get of a sensitive HSM key is refused even with a key-wrapping specification: the KMS cannot read
  such a key and has nothing to wrap.

## Build

- `shell.nix`: only add the glibc include path on Linux so `nix-shell` evaluates on macOS.

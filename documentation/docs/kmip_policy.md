# KMIP algorithm policy (server-side)

The `cosmian_kms_server` crate can enforce a KMIP algorithm policy at request entry points (and on retrieved keys).

The policy selector is `kmip.policy_id`.

Accepted values (case-insensitive):

- `DEFAULT`: enforce the built-in conservative allowlists.
- `CUSTOM`: enforce the allowlists you provide under `[kmip.allowlists]` (use with caution).

## Enabling the default policy

If `kmip.policy_id` is unset, the KMIP policy layer is disabled.

To explicitly select the built-in default policy, set `kmip.policy_id = "DEFAULT"` in `kms.toml` (or pass it on the command line):

```toml
[kmip]
policy_id = "DEFAULT"
```

CLI:

```sh
cosmian_kms --kmip-policy-id DEFAULT
```

## Policies to use with caution

- `CUSTOM`: lets you override allowlists under `[kmip.allowlists]`. Misconfiguration can unintentionally allow weak choices or, conversely, deny most operations (e.g., if you set an empty list `[]`).

## What the `DEFAULT` policy enforces

The `DEFAULT` policy is a conservative (ANSSI/NIST/FIPS-aligned) allowlist.
It constrains KMIP requests by validating their declared cryptographic parameters and, when applicable, the characteristics of the referenced keys.

In particular, it allowlists:

- Cryptographic algorithms: `AES`, `RSA`, `ECDSA`, `ECDH`, `EC`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`
- Hash functions: `SHA256`, `SHA384`, `SHA512`, `SHA3256`, `SHA3384`, `SHA3512`
- Signature algorithms: `SHA256WithRSAEncryption`, `SHA384WithRSAEncryption`, `SHA512WithRSAEncryption`, `RSASSAPSS`, `ECDSAWithSHA256`, `ECDSAWithSHA384`, `ECDSAWithSHA512`
- Curves: `P256`, `P384`, `P521`, `CURVE25519`, `CURVE448`
- Block cipher modes: `GCM`, `CCM`, `XTS`, `NISTKeyWrap`, `AESKeyWrapPadding`, `GCMSIV`
- Padding methods: `OAEP`, `PSS`, `PKCS5`
- MGF hashes: `SHA256`, `SHA384`, `SHA512`
- Mask generators: `MGF1`

It also enforces key-size constraints:

- RSA key sizes: `3072`, `4096` (in addition to baseline structural constraints)
- AES key sizes: `128`, `192`, `256`

### Scheme-to-policy mapping

This table links the [Algorithms](./algorithms.md) to the minimal `kms.toml` allowlist values needed to keep each scheme reachable when `kmip.policy_id = "DEFAULT"`.

| Documentation scheme name | KMIP operation(s) | KMIP `CryptographicAlgorithm` | Minimal `kms.toml` allowlist values |
| ------------------------- | ----------------- | ----------------------------- | ---------------------------------- |
| AES-KWP (RFC 5649) | `Import` / `Export` (wrap/unwrap) | `AES` | `algorithms=["AES"]`<br>`block_cipher_modes=["AESKeyWrapPadding"]`<br>`aes_key_sizes=[256]` (or `[128,192,256]`) |
| NIST KW (RFC 3394) | `Import` / `Export` (wrap/unwrap) | `AES` | `algorithms=["AES"]`<br>`block_cipher_modes=["NISTKeyWrap"]`<br>`aes_key_sizes=[256]` (or `[128,192,256]`) |
| CKM_RSA_PKCS_OAEP | `Encrypt` / `Decrypt` (and RSA-wrap paths using OAEP) | `RSA` | `algorithms=["RSA"]`<br>`padding_methods=["OAEP"]`<br>`hashes=["SHA256","SHA384","SHA512"]`<br>`mask_generators=["MGF1"]`<br>`mgf_hashes=["SHA256","SHA384","SHA512"]`<br>`rsa_key_sizes=[2048,3072,4096]` |
| CKM_RSA_AES_KEY_WRAP | `Import` / `Export` (wrap/unwrap) | `RSA` | `algorithms=["RSA"]`<br>`padding_methods=["None"]`<br>`hashes=["SHA256","SHA384","SHA512"]`<br>`rsa_key_sizes=[2048,3072,4096]` |
| CKM_RSA_PKCS (PKCS#1 v1.5) | `Encrypt` / `Decrypt` | `RSA` | `algorithms=["RSA"]`<br>`padding_methods=["PKCS1v15"]`<br>`rsa_key_sizes=[2048,3072,4096]` |
| ECIES (NIST curves) | `Encrypt` / `Decrypt` | (key-type driven) | `curves=["P256","P384","P521"]`<br>(and if restricting key creation/import: `algorithms=["EC","ECDH","ECDSA"]`) |
| Salsa Sealed Box | `Encrypt` / `Decrypt` | (key-type driven) | `curves=["CURVE25519","CURVEED25519"]`<br>(and if restricting key creation/import: `algorithms=["EC","ECDH","ECDSA","Ed25519"]`) |
| AES GCM | `Encrypt` / `Decrypt` | `AES` | `algorithms=["AES"]`<br>`block_cipher_modes=["GCM"]`<br>`aes_key_sizes=[256]` (or `[128,192,256]`) |
| AES XTS | `Encrypt` / `Decrypt` | `AES` | `algorithms=["AES"]`<br>`block_cipher_modes=["XTS"]`<br>`aes_key_sizes=[512]` (or `[256,512]` depending on client encoding) |
| AES GCM-SIV | `Encrypt` / `Decrypt` | `AES` | `algorithms=["AES"]`<br>`block_cipher_modes=["GCMSIV"]`<br>`aes_key_sizes=[256]` (or `[128,192,256]`) |
| ChaCha20-Poly1305 | `Encrypt` / `Decrypt` | `ChaCha20Poly1305` | `algorithms=["ChaCha20Poly1305"]` |
| RSASSA-PSS | `Sign` / `SignatureVerify` | `RSA` | `algorithms=["RSA"]`<br>`signature_algorithms=["RSASSAPSS"]`<br>`hashes=["SHA256","SHA384","SHA512"]`<br>`mask_generators=["MGF1"]`<br>`mgf_hashes=["SHA256","SHA384","SHA512"]`<br>`rsa_key_sizes=[2048,3072,4096]` |
| ECDSA (with SHA-2) | `Sign` / `SignatureVerify` | `ECDSA` | `algorithms=["ECDSA","EC"]`<br>`signature_algorithms=["ECDSAWithSHA256","ECDSAWithSHA384","ECDSAWithSHA512"]`<br>`curves=["P256","P384","P521"]` |
| EdDSA | `Sign` / `SignatureVerify` | `Ed25519` / `Ed448` | `algorithms=["Ed25519","Ed448"]`<br>`curves=["CURVEED25519","CURVEED448"]` |

# KMIP algorithm policy (server-side)

The `cosmian_kms_server` crate can enforce a KMIP algorithm policy at request entry points (and on retrieved keys).

The policy selector is `kmip.policy_id`.

You can also set it via:

- CLI: `--kmip-policy-id` (case-insensitive)
- Env var: `KMS_POLICY_ID`

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

Env var:

```sh
export KMS_POLICY_ID=DEFAULT
```

## Policies to use with caution

- `CUSTOM`: enforces the allowlists under `[kmip.allowlists]`. Misconfiguration can unintentionally allow weak choices or, conversely, deny most operations (e.g., if you set an empty list `[]`).

Notes:

- When `kmip.policy_id = "DEFAULT"`, any `[kmip.allowlists]` values in the configuration file are ignored (the server uses the built-in defaults).
- When `kmip.policy_id = "CUSTOM"` and an allowlist key is omitted, that parameter is not restricted by an allowlist.

## What the `DEFAULT` policy enforces

The `DEFAULT` policy is a conservative (ANSSI/NIST/FIPS-aligned) allowlist.
It constrains KMIP requests by validating their declared cryptographic parameters and, when applicable, the characteristics of the referenced keys.

In particular, it allowlists:

- Cryptographic algorithms (all builds): `AES`, `RSA`, `ECDSA`, `ECDH`, `EC`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`
- Cryptographic algorithms (non-FIPS builds only): `ChaCha20Poly1305`, `Ed25519`, `SHAKE128`, `SHAKE256`, `ConfigurableKEM`, `MLKEM_512`, `MLKEM_768`, `MLKEM_1024`
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

Baseline constraints (independent from the allowlists):

- RSA keys smaller than 2048 bits are always rejected when the policy layer is enabled.

## Custom allowlists (`CUSTOM`)

When `kmip.policy_id = "CUSTOM"`, the policy layer uses the allowlists under `[kmip.allowlists]`.

All allowlists follow these semantics:

- omitted key: no allowlist restriction for that parameter
- empty list `[]`: deny everything for that parameter
- non-empty list: allow only listed values

Allowlists are config-file only (there are no per-allowlist CLI flags).

### Allowlist keys

`[kmip.allowlists]` supports:

- `algorithms`: KMIP `CryptographicAlgorithm` (e.g. `"AES"`, `"RSA"`)
- `hashes`: KMIP `HashingAlgorithm` (e.g. `"SHA256"`)
- `signature_algorithms`: KMIP `DigitalSignatureAlgorithm` (e.g. `"RSASSAPSS"`)
- `curves`: KMIP `RecommendedCurve` (e.g. `"P256"`, `"CURVE25519"`)
- `block_cipher_modes`: KMIP `BlockCipherMode` (e.g. `"GCM"`)
- `padding_methods`: KMIP `PaddingMethod` (e.g. `"OAEP"`, `"PSS"`, `"PKCS1v15"`, `"PKCS5"`)
- `rsa_key_sizes`: RSA key sizes in bits (strings): `"2048"`, `"3072"`, `"4096"`
- `aes_key_sizes`: AES key sizes in bits (strings): `"128"`, `"192"`, `"256"`, and optionally `"512"` for some AES-XTS client encodings
- `mgf_hashes`: KMIP `HashingAlgorithm` for MGF1 (e.g. `"SHA256"`)
- `mask_generators`: KMIP `MaskGenerator` (e.g. `"MGF1"`)

Values are matched case-insensitively against the KMIP enum display names.

### Example: AES-GCM only

```toml
[kmip]
policy_id = "CUSTOM"

[kmip.allowlists]
algorithms = ["AES"]
block_cipher_modes = ["GCM"]
aes_key_sizes = ["256"]
```

### Example: RSA-OAEP with RSA-3072+

```toml
[kmip]
policy_id = "CUSTOM"

[kmip.allowlists]
algorithms = ["RSA"]
padding_methods = ["OAEP"]
hashes = ["SHA256", "SHA384", "SHA512"]
mask_generators = ["MGF1"]
mgf_hashes = ["SHA256", "SHA384", "SHA512"]
rsa_key_sizes = ["3072", "4096"]
```

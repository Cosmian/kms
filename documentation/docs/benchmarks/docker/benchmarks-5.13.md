# Benchmarks — KMS 5.13 (Docker)

Image: `ghcr.io/cosmian/kms:5.13`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.L129m1Mi72 bench --mode all --format markdown --save-baseline v5.13 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `327.90 µs` | `265.83 µs` | `311.33 µs` | `443.16 µs` |
| **`10 requests`** | `585.13 µs` | `516.32 µs` | `508.94 µs` | `609.56 µs` |
| **`50 requests`** | `1.01 ms` | `1.46 ms` | `822.30 µs` | `2.14 ms` |
| **`100 requests`** | `1.94 ms` | `1.95 ms` | `2.70 ms` | `1.81 ms` |
| **`500 requests`** | `10.94 ms` | `9.75 ms` | `10.31 ms` | `9.74 ms` |
| **`1000 requests`** | `17.71 ms` | `18.25 ms` | `16.44 ms` | `20.11 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `30.03 ms` | `507.82 µs` | `81.03 ms` | `536.55 µs` | `183.31 ms` | `715.27 µs` |
| **`10 requests`** | `271.18 ms` | `2.89 ms` | `832.86 ms` | `5.44 ms` | `1.89 s` | `5.10 ms` |
| **`50 requests`** | `1.34 s` | `13.14 ms` | `4.10 s` | `15.75 ms` | `9.31 s` | `18.16 ms` |
| **`100 requests`** | `2.65 s` | `28.06 ms` | `8.18 s` | `30.07 ms` | `18.72 s` | `36.18 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `26.76 ms` | `444.88 µs` | `82.24 ms` | `683.43 µs` | `187.06 ms` | `675.22 µs` |
| **`10 requests`** | `261.22 ms` | `3.53 ms` | `812.70 ms` | `3.84 ms` | `1.86 s` | `6.12 ms` |
| **`50 requests`** | `1.33 s` | `13.47 ms` | `4.08 s` | `17.09 ms` | `9.31 s` | `18.12 ms` |
| **`100 requests`** | `2.65 s` | `27.38 ms` | `8.21 s` | `30.69 ms` | `18.60 s` | `37.26 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.73 ms` | `540.13 µs` | `83.46 ms` | `515.21 µs` | `186.90 ms` | `781.82 µs` |
| **`10 requests`** | `262.33 ms` | `2.75 ms` | `820.89 ms` | `8.02 ms` | `1.88 s` | `5.23 ms` |
| **`50 requests`** | `1.34 s` | `14.89 ms` | `4.10 s` | `15.74 ms` | `9.36 s` | `18.37 ms` |
| **`100 requests`** | `2.64 s` | `24.40 ms` | `8.15 s` | `30.55 ms` | `18.60 s` | `35.72 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `206.98 µs` | `354.97 µs` |
| **`192`** | `218.12 µs` | `310.42 µs` |
| **`256`** | `315.03 µs` | `230.56 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `151.96 µs` | `335.28 µs` |
| **`256`** | `283.31 µs` | `392.94 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `358.15 µs` | `371.49 µs` |
| **`256`** | `314.94 µs` | `397.21 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `212.50 µs` | `354.09 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `13.43 ms` | `7.38 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `351.82 µs` | `696.52 µs` |
| **`P-384`** | `1.91 ms` | `2.48 ms` |
| **`P-521`** | `5.87 ms` | `6.32 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `29.35 ms` | `528.60 µs` |
| **`3072`** | `81.83 ms` | `558.51 µs` |
| **`4096`** | `188.76 ms` | `590.61 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `29.71 ms` | `470.17 µs` |
| **`3072`** | `82.23 ms` | `452.85 µs` |
| **`4096`** | `182.66 ms` | `590.37 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.28 ms` | `391.71 µs` |
| **`3072`** | `85.58 ms` | `536.62 µs` |
| **`4096`** | `191.15 ms` | `612.84 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `363.18 µs` | `475.84 µs` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `21.63 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.55 ms` | `3.90 ms` | `3.33 ms` | `5.28 ms` | `5.77 ms` | `4.68 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `36.69 ms` | `108.64 ms` | `320.16 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.38 ms` | `3.24 ms` | `3.28 ms` | `2.57 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `288.31 µs` | `522.13 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.62 ms` | `1.86 ms` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `5.62 ms` | `4.07 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.06 ms` | `1.30 ms` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `248.49 µs` | `358.64 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `27.84 ms` | `314.08 µs` |
| **`3072`** | `84.64 ms` | `333.07 µs` |
| **`4096`** | `188.74 ms` | `418.92 µs` |

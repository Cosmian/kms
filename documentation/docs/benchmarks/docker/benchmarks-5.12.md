# Benchmarks — KMS 5.12 (Docker)

Image: `ghcr.io/cosmian/kms:5.12`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.FCIxKKiQPE bench --mode all --format markdown --save-baseline v5.12 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `194.65 µs` | `276.63 µs` | `181.96 µs` | `392.57 µs` |
| **`10 requests`** | `799.16 µs` | `509.48 µs` | `674.28 µs` | `883.53 µs` |
| **`50 requests`** | `872.11 µs` | `1.55 ms` | `861.65 µs` | `2.33 ms` |
| **`100 requests`** | `1.95 ms` | `1.65 ms` | `2.47 ms` | `2.09 ms` |
| **`500 requests`** | `8.05 ms` | `8.05 ms` | `7.98 ms` | `8.12 ms` |
| **`1000 requests`** | `16.27 ms` | `15.80 ms` | `15.44 ms` | `16.63 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `30.43 ms` | `706.31 µs` | `88.20 ms` | `652.80 µs` | `204.67 ms` | `677.39 µs` |
| **`10 requests`** | `299.77 ms` | `3.47 ms` | `907.85 ms` | `4.00 ms` | `2.12 s` | `4.16 ms` |
| **`50 requests`** | `1.49 s` | `10.45 ms` | `4.49 s` | `9.61 ms` | `10.53 s` | `12.47 ms` |
| **`100 requests`** | `2.96 s` | `17.11 ms` | `8.87 s` | `17.87 ms` | `19.96 s` | `25.30 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `30.77 ms` | `493.23 µs` | `87.92 ms` | `388.52 µs` | `209.71 ms` | `560.68 µs` |
| **`10 requests`** | `282.12 ms` | `1.57 ms` | `881.85 ms` | `2.54 ms` | `2.09 s` | `4.54 ms` |
| **`50 requests`** | `1.41 s` | `7.84 ms` | `4.42 s` | `9.72 ms` | `10.82 s` | `13.24 ms` |
| **`100 requests`** | `2.82 s` | `13.21 ms` | `8.97 s` | `18.26 ms` | `21.48 s` | `28.16 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `28.12 ms` | `267.89 µs` | `86.28 ms` | `477.84 µs` | `203.12 ms` | `506.04 µs` |
| **`10 requests`** | `286.24 ms` | `2.88 ms` | `873.17 ms` | `4.20 ms` | `1.99 s` | `2.72 ms` |
| **`50 requests`** | `1.41 s` | `7.27 ms` | `4.37 s` | `9.58 ms` | `10.36 s` | `13.09 ms` |
| **`100 requests`** | `2.85 s` | `13.78 ms` | `8.91 s` | `20.16 ms` | `20.55 s` | `24.44 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `145.07 µs` | `335.96 µs` |
| **`256`** | `459.37 µs` | `407.42 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `307.35 µs` | `402.87 µs` |
| **`256`** | `373.65 µs` | `378.69 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `223.74 µs` | `577.67 µs` |
| **`256`** | `529.19 µs` | `345.38 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `274.06 µs` | `306.81 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `524.51 µs` | `554.43 µs` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `587.37 µs` | `644.37 µs` |
| **`P-384`** | `2.46 ms` | `2.39 ms` |
| **`P-521`** | `3.02 ms` | `4.41 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `29.66 ms` | `263.55 µs` |
| **`3072`** | `90.11 ms` | `356.82 µs` |
| **`4096`** | `206.61 ms` | `466.15 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `31.35 ms` | `357.54 µs` |
| **`3072`** | `92.69 ms` | `297.06 µs` |
| **`4096`** | `207.83 ms` | `357.35 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `32.78 ms` | `401.11 µs` |
| **`3072`** | `93.56 ms` | `251.63 µs` |
| **`4096`** | `211.24 ms` | `511.77 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `424.70 µs` | `453.65 µs` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `5.77 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `4.10 ms` | `4.90 ms` | `4.25 ms` | `4.94 ms` | `6.11 ms` | `4.94 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `39.21 ms` | `158.01 ms` | `328.19 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `3.38 ms` | `3.50 ms` | `3.32 ms` | `3.20 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `503.91 µs` | `519.55 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `2.24 ms` | `1.41 ms` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `3.69 ms` | `2.81 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `916.65 µs` | `728.61 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `300.02 µs` | `262.85 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `29.65 ms` | `384.40 µs` |
| **`3072`** | `90.37 ms` | `538.00 µs` |
| **`4096`** | `202.76 ms` | `465.46 µs` |

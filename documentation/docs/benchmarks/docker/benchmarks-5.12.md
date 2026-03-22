# Benchmarks — KMS 5.12 (Docker)

Image: `ghcr.io/cosmian/kms:5.12`

Source command:

```bash
cargo run -p ckms --features non-fips -- --conf-path /tmp/tmp.uSmf7zAWBk bench --mode all --format markdown --save-baseline v5.12 --sanity
```

## Benchmark Results

### AES GCM - plaintext of 64 bytes

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `2.32 ms` | `871.85 µs` | `2.68 ms` | `2.10 ms` |

### RSA AES KEY WRAP - plaintext of 32 bytes

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `49.09 ms` | `4.65 ms` | `202.35 ms` | `5.89 ms` | `552.85 ms` | `3.94 ms` |

### RSA OAEP - plaintext of 32 bytes

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `73.14 ms` | `4.56 ms` | `180.38 ms` | `4.72 ms` | `422.85 ms` | `4.64 ms` |

### RSA PKCSv1.5 - plaintext of 32 bytes

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `81.07 ms` | `3.70 ms` | `268.41 ms` | `3.29 ms` | `507.23 ms` | `3.72 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `2.15 ms` | `590.61 µs` |
| **`256`** | `3.36 ms` | `2.65 ms` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `865.54 µs` | `2.74 ms` |
| **`256`** | `1.55 ms` | `1.84 ms` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `2.61 ms` | `2.95 ms` |
| **`256`** | `1.19 ms` | `1.16 ms` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `2.86 ms` | `931.40 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `2.65 ms` | `3.94 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `3.19 ms` | `3.46 ms` |
| **`P-384`** | `6.53 ms` | `6.95 ms` |
| **`P-521`** | `9.98 ms` | `13.74 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `79.12 ms` | `2.98 ms` |
| **`3072`** | `181.10 ms` | `2.95 ms` |
| **`4096`** | `521.26 ms` | `1.82 ms` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `58.99 ms` | `592.29 µs` |
| **`3072`** | `193.49 ms` | `1.69 ms` |
| **`4096`** | `518.83 ms` | `2.77 ms` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `60.98 ms` | `4.47 ms` |
| **`3072`** | `185.78 ms` | `3.14 ms` |
| **`4096`** | `528.44 ms` | `3.08 ms` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `3.53 ms` | `3.59 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `6.45 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `9.21 ms` | `9.70 ms` | `4.57 ms` | `7.33 ms` | `11.76 ms` | `8.41 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `183.20 ms` | `303.51 ms` | `919.28 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `9.09 ms` | `6.58 ms` | `10.12 ms` | `4.94 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `996.44 µs` | `3.00 ms` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `6.35 ms` | `4.82 ms` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `8.66 ms` | `6.53 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `2.27 ms` | `3.50 ms` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `2.01 ms` | `1.41 ms` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `77.04 ms` | `3.16 ms` |
| **`3072`** | `239.10 ms` | `4.60 ms` |
| **`4096`** | `441.06 ms` | `3.88 ms` |

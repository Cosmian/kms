# Benchmarks — KMS 5.16 (Docker)

Image: `ghcr.io/cosmian/kms:5.16`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.L129m1Mi72 bench --mode all --format markdown --save-baseline v5.16 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `117.84 µs` | `254.51 µs` | `115.49 µs` | `183.25 µs` |
| **`10 requests`** | `293.90 µs` | `377.00 µs` | `335.95 µs` | `354.76 µs` |
| **`50 requests`** | `795.42 µs` | `1.22 ms` | `958.19 µs` | `893.51 µs` |
| **`100 requests`** | `1.45 ms` | `1.66 ms` | `1.96 ms` | `2.22 ms` |
| **`500 requests`** | `6.67 ms` | `12.97 ms` | `7.58 ms` | `9.96 ms` |
| **`1000 requests`** | `13.24 ms` | `16.51 ms` | `14.07 ms` | `16.55 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `24.49 ms` | `343.67 µs` | `77.30 ms` | `423.13 µs` | `170.36 ms` | `413.17 µs` |
| **`10 requests`** | `251.49 ms` | `2.31 ms` | `765.69 ms` | `3.26 ms` | `1.74 s` | `2.88 ms` |
| **`50 requests`** | `1.21 s` | `10.32 ms` | `3.73 s` | `11.53 ms` | `8.50 s` | `16.11 ms` |
| **`100 requests`** | `2.37 s` | `17.60 ms` | `7.44 s` | `23.36 ms` | `16.87 s` | `26.29 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.74 ms` | `337.43 µs` | `75.78 ms` | `389.88 µs` | `170.25 ms` | `443.42 µs` |
| **`10 requests`** | `247.73 ms` | `2.14 ms` | `734.64 ms` | `3.00 ms` | `1.70 s` | `5.74 ms` |
| **`50 requests`** | `1.24 s` | `17.69 ms` | `3.75 s` | `11.94 ms` | `8.62 s` | `15.45 ms` |
| **`100 requests`** | `2.47 s` | `19.95 ms` | `7.57 s` | `22.79 ms` | `17.16 s` | `26.42 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `28.59 ms` | `293.85 µs` | `72.49 ms` | `375.66 µs` | `181.11 ms` | `439.12 µs` |
| **`10 requests`** | `234.30 ms` | `2.25 ms` | `722.98 ms` | `2.30 ms` | `1.69 s` | `3.07 ms` |
| **`50 requests`** | `1.16 s` | `8.80 ms` | `3.73 s` | `18.03 ms` | `8.38 s` | `19.72 ms` |
| **`100 requests`** | `2.45 s` | `17.38 ms` | `7.29 s` | `20.47 ms` | `16.86 s` | `26.66 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `123.41 µs` | `199.20 µs` |
| **`192`** | `130.87 µs` | `261.83 µs` |
| **`256`** | `173.22 µs` | `193.32 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `191.63 µs` | `192.30 µs` |
| **`256`** | `134.51 µs` | `207.15 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `113.26 µs` | `225.92 µs` |
| **`256`** | `89.77 µs` | `224.42 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `161.06 µs` | `234.56 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `11.92 ms` | `5.93 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `202.75 µs` | `349.11 µs` |
| **`P-384`** | `1.42 ms` | `1.51 ms` |
| **`P-521`** | `2.76 ms` | `4.60 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.32 ms` | `239.52 µs` |
| **`3072`** | `73.58 ms` | `331.61 µs` |
| **`4096`** | `167.53 ms` | `360.55 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.96 ms` | `285.93 µs` |
| **`3072`** | `78.35 ms` | `280.01 µs` |
| **`4096`** | `170.56 ms` | `317.95 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.79 ms` | `270.81 µs` |
| **`3072`** | `79.29 ms` | `284.48 µs` |
| **`4096`** | `178.41 ms` | `326.32 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `188.97 µs` | `271.03 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `333.46 µs` | `433.98 µs` |
| **`ML-KEM-512/P-256`** | `277.72 µs` | `551.71 µs` |
| **`ML-KEM-512/X25519`** | `421.79 µs` | `3.84 ms` |
| **`ML-KEM-768`** | `342.45 µs` | `492.24 µs` |
| **`ML-KEM-768/P-256`** | `298.76 µs` | `652.14 µs` |
| **`ML-KEM-768/X25519`** | `483.87 µs` | `4.04 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `24.18 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.02 ms` | `3.48 ms` | `3.83 ms` | `3.70 ms` | `7.07 ms` | `3.77 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.97 ms` | `4.24 ms` | `6.19 ms` | `2.57 ms` | `3.84 ms` | `7.25 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `34.25 ms` | `110.91 ms` | `341.91 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.88 ms` | `2.65 ms` | `2.77 ms` | `2.08 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `606.98 µs` | `211.99 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.66 ms` | `625.38 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `4.57 ms` | `1.26 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `625.76 µs` | `458.88 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `232.22 µs` | `222.49 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `506.43 µs` | `331.76 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `26.99 ms` | `203.70 µs` |
| **`3072`** | `74.51 ms` | `283.32 µs` |
| **`4096`** | `169.06 ms` | `372.51 µs` |

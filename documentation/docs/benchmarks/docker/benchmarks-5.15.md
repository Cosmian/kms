# Benchmarks — KMS 5.15 (Docker)

Image: `ghcr.io/cosmian/kms:5.15`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.L129m1Mi72 bench --mode all --format markdown --save-baseline v5.15 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `115.71 µs` | `186.11 µs` | `179.86 µs` | `400.14 µs` |
| **`10 requests`** | `280.64 µs` | `497.50 µs` | `355.48 µs` | `440.84 µs` |
| **`50 requests`** | `1.02 ms` | `904.49 µs` | `920.15 µs` | `1.13 ms` |
| **`100 requests`** | `1.62 ms` | `1.52 ms` | `1.74 ms` | `2.05 ms` |
| **`500 requests`** | `6.72 ms` | `8.82 ms` | `7.96 ms` | `7.28 ms` |
| **`1000 requests`** | `15.56 ms` | `15.93 ms` | `13.97 ms` | `14.38 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `29.66 ms` | `313.86 µs` | `73.17 ms` | `370.05 µs` | `180.22 ms` | `421.81 µs` |
| **`10 requests`** | `238.88 ms` | `2.06 ms` | `737.59 ms` | `2.49 ms` | `1.74 s` | `3.51 ms` |
| **`50 requests`** | `1.20 s` | `8.58 ms` | `3.76 s` | `11.00 ms` | `8.57 s` | `13.39 ms` |
| **`100 requests`** | `2.44 s` | `17.71 ms` | `7.47 s` | `21.11 ms` | `17.07 s` | `28.13 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.92 ms` | `394.32 µs` | `73.55 ms` | `428.40 µs` | `167.39 ms` | `417.24 µs` |
| **`10 requests`** | `239.63 ms` | `2.27 ms` | `774.30 ms` | `2.51 ms` | `1.79 s` | `3.35 ms` |
| **`50 requests`** | `1.26 s` | `10.48 ms` | `3.70 s` | `11.69 ms` | `8.51 s` | `19.21 ms` |
| **`100 requests`** | `2.40 s` | `18.96 ms` | `7.56 s` | `23.52 ms` | `17.14 s` | `27.57 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `24.43 ms` | `369.49 µs` | `72.88 ms` | `403.30 µs` | `166.45 ms` | `469.72 µs` |
| **`10 requests`** | `250.73 ms` | `2.06 ms` | `726.63 ms` | `3.62 ms` | `1.70 s` | `3.93 ms` |
| **`50 requests`** | `1.23 s` | `9.07 ms` | `3.72 s` | `17.43 ms` | `8.65 s` | `14.34 ms` |
| **`100 requests`** | `2.46 s` | `17.34 ms` | `7.52 s` | `23.11 ms` | `17.10 s` | `28.02 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `173.70 µs` | `216.30 µs` |
| **`192`** | `127.88 µs` | `184.04 µs` |
| **`256`** | `117.28 µs` | `239.57 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `137.06 µs` | `195.70 µs` |
| **`256`** | `145.58 µs` | `169.95 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `120.64 µs` | `201.01 µs` |
| **`256`** | `199.26 µs` | `173.30 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `118.23 µs` | `153.14 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `11.78 ms` | `5.27 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `310.83 µs` | `400.94 µs` |
| **`P-384`** | `1.37 ms` | `1.43 ms` |
| **`P-521`** | `2.85 ms` | `2.59 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `29.79 ms` | `236.90 µs` |
| **`3072`** | `78.03 ms` | `340.30 µs` |
| **`4096`** | `173.95 ms` | `350.44 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.34 ms` | `242.72 µs` |
| **`3072`** | `74.88 ms` | `272.11 µs` |
| **`4096`** | `179.49 ms` | `352.29 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `25.77 ms` | `352.57 µs` |
| **`3072`** | `75.49 ms` | `264.85 µs` |
| **`4096`** | `171.07 ms` | `328.73 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `270.14 µs` | `248.40 µs` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `18.41 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.07 ms` | `3.61 ms` | `3.00 ms` | `4.97 ms` | `3.86 ms` | `4.48 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `42.81 ms` | `96.50 ms` | `380.29 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.92 ms` | `2.86 ms` | `2.95 ms` | `2.62 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `586.07 µs` | `220.53 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.15 ms` | `711.56 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `2.63 ms` | `1.43 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `508.91 µs` | `384.11 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `154.25 µs` | `208.24 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `462.39 µs` | `282.99 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `25.91 ms` | `144.40 µs` |
| **`3072`** | `88.67 ms` | `435.89 µs` |
| **`4096`** | `180.38 ms` | `243.42 µs` |

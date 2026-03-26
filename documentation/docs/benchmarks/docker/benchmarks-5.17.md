# Benchmarks — KMS 5.17 (Docker)

Image: `ghcr.io/cosmian/kms:5.17`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.L129m1Mi72 bench --mode all --format markdown --save-baseline v5.17 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `99.21 µs` | `177.40 µs` | `194.51 µs` | `216.66 µs` |
| **`10 requests`** | `279.20 µs` | `364.73 µs` | `266.78 µs` | `350.95 µs` |
| **`50 requests`** | `768.22 µs` | `831.58 µs` | `852.55 µs` | `989.74 µs` |
| **`100 requests`** | `1.45 ms` | `2.74 ms` | `1.97 ms` | `2.69 ms` |
| **`500 requests`** | `6.80 ms` | `9.29 ms` | `7.09 ms` | `11.81 ms` |
| **`1000 requests`** | `16.22 ms` | `14.90 ms` | `13.46 ms` | `14.06 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `25.14 ms` | `365.41 µs` | `72.53 ms` | `361.73 µs` | `173.84 ms` | `378.97 µs` |
| **`10 requests`** | `235.88 ms` | `1.70 ms` | `717.50 ms` | `2.01 ms` | `1.68 s` | `2.54 ms` |
| **`50 requests`** | `1.17 s` | `10.22 ms` | `3.71 s` | `10.69 ms` | `8.38 s` | `16.93 ms` |
| **`100 requests`** | `2.43 s` | `14.35 ms` | `7.27 s` | `17.71 ms` | `16.76 s` | `22.59 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.05 ms` | `320.98 µs` | `75.47 ms` | `368.14 µs` | `163.61 ms` | `336.01 µs` |
| **`10 requests`** | `257.76 ms` | `2.72 ms` | `722.53 ms` | `2.25 ms` | `1.74 s` | `2.46 ms` |
| **`50 requests`** | `1.20 s` | `16.17 ms` | `3.70 s` | `20.94 ms` | `8.33 s` | `12.66 ms` |
| **`100 requests`** | `2.39 s` | `15.16 ms` | `7.29 s` | `18.24 ms` | `16.71 s` | `22.67 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `23.86 ms` | `374.76 µs` | `72.09 ms` | `291.72 µs` | `173.60 ms` | `347.36 µs` |
| **`10 requests`** | `233.60 ms` | `1.67 ms` | `723.12 ms` | `2.68 ms` | `1.64 s` | `2.45 ms` |
| **`50 requests`** | `1.16 s` | `7.83 ms` | `3.68 s` | `9.16 ms` | `8.45 s` | `11.50 ms` |
| **`100 requests`** | `2.39 s` | `15.09 ms` | `7.32 s` | `18.54 ms` | `16.71 s` | `21.97 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `190.42 µs` | `154.29 µs` |
| **`192`** | `166.12 µs` | `167.26 µs` |
| **`256`** | `117.18 µs` | `209.18 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `121.91 µs` | `147.30 µs` |
| **`256`** | `129.52 µs` | `189.27 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `112.03 µs` | `159.72 µs` |
| **`256`** | `128.19 µs` | `165.90 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `121.78 µs` | `183.69 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `11.83 ms` | `6.28 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `243.35 µs` | `332.26 µs` |
| **`P-384`** | `1.46 ms` | `1.49 ms` |
| **`P-521`** | `2.47 ms` | `2.53 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.77 ms` | `337.36 µs` |
| **`3072`** | `76.73 ms` | `275.44 µs` |
| **`4096`** | `164.06 ms` | `315.73 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `25.95 ms` | `226.03 µs` |
| **`3072`** | `73.41 ms` | `295.70 µs` |
| **`4096`** | `166.91 ms` | `304.82 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.04 ms` | `226.71 µs` |
| **`3072`** | `72.62 ms` | `223.31 µs` |
| **`4096`** | `164.72 ms` | `291.29 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `230.68 µs` | `268.56 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `348.67 µs` | `338.12 µs` |
| **`ML-KEM-512/P-256`** | `322.13 µs` | `500.97 µs` |
| **`ML-KEM-512/X25519`** | `289.39 µs` | `4.11 ms` |
| **`ML-KEM-768`** | `326.35 µs` | `469.37 µs` |
| **`ML-KEM-768/P-256`** | `442.25 µs` | `584.45 µs` |
| **`ML-KEM-768/X25519`** | `444.00 µs` | `3.94 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `24.39 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `2.93 ms` | `3.51 ms` | `3.07 ms` | `3.37 ms` | `4.70 ms` | `3.73 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `2.98 ms` | `3.06 ms` | `7.52 ms` | `3.35 ms` | `3.81 ms` | `4.35 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `35.06 ms` | `124.54 ms` | `249.12 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.80 ms` | `2.49 ms` | `2.55 ms` | `2.47 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `542.37 µs` | `215.41 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.55 ms` | `798.19 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `4.47 ms` | `1.34 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `639.42 µs` | `382.76 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `190.54 µs` | `189.22 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `477.14 µs` | `285.48 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `24.69 ms` | `254.21 µs` |
| **`3072`** | `78.78 ms` | `189.72 µs` |
| **`4096`** | `182.29 ms` | `331.68 µs` |

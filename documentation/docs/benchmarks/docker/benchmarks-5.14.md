# Benchmarks — KMS 5.14 (Docker)

Image: `ghcr.io/cosmian/kms:5.14`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.L129m1Mi72 bench --mode all --format markdown --save-baseline v5.14 --speed quick
```

## Benchmark Results

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `230.20 µs` | `402.47 µs` | `274.93 µs` | `292.56 µs` |
| **`10 requests`** | `328.41 µs` | `690.00 µs` | `328.10 µs` | `530.34 µs` |
| **`50 requests`** | `1.13 ms` | `1.68 ms` | `966.75 µs` | `1.80 ms` |
| **`100 requests`** | `2.14 ms` | `2.22 ms` | `1.85 ms` | `2.63 ms` |
| **`500 requests`** | `7.77 ms` | `9.92 ms` | `8.54 ms` | `9.28 ms` |
| **`1000 requests`** | `15.74 ms` | `17.27 ms` | `15.38 ms` | `16.74 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.23 ms` | `431.57 µs` | `82.77 ms` | `534.46 µs` | `188.01 ms` | `639.59 µs` |
| **`10 requests`** | `272.36 ms` | `3.10 ms` | `833.52 ms` | `3.24 ms` | `1.90 s` | `4.22 ms` |
| **`50 requests`** | `1.33 s` | `13.17 ms` | `4.10 s` | `15.96 ms` | `9.49 s` | `18.69 ms` |
| **`100 requests`** | `2.67 s` | `26.16 ms` | `8.26 s` | `31.15 ms` | `18.95 s` | `35.45 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `28.16 ms` | `450.27 µs` | `82.56 ms` | `674.36 µs` | `186.12 ms` | `649.06 µs` |
| **`10 requests`** | `264.92 ms` | `2.83 ms` | `818.67 ms` | `3.52 ms` | `1.89 s` | `6.02 ms` |
| **`50 requests`** | `1.35 s` | `12.48 ms` | `4.07 s` | `16.30 ms` | `9.29 s` | `17.78 ms` |
| **`100 requests`** | `2.64 s` | `26.07 ms` | `8.10 s` | `31.43 ms` | `18.64 s` | `36.22 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `27.80 ms` | `533.60 µs` | `83.98 ms` | `482.91 µs` | `167.61 ms` | `594.70 µs` |
| **`10 requests`** | `271.79 ms` | `4.97 ms` | `804.63 ms` | `4.56 ms` | `1.76 s` | `3.74 ms` |
| **`50 requests`** | `1.34 s` | `13.07 ms` | `3.86 s` | `14.48 ms` | `8.57 s` | `16.46 ms` |
| **`100 requests`** | `2.67 s` | `26.21 ms` | `7.45 s` | `28.68 ms` | `17.14 s` | `34.58 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `279.04 µs` | `558.02 µs` |
| **`192`** | `144.98 µs` | `403.51 µs` |
| **`256`** | `370.67 µs` | `316.66 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `122.71 µs` | `444.40 µs` |
| **`256`** | `197.67 µs` | `269.09 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `154.81 µs` | `224.52 µs` |
| **`256`** | `217.23 µs` | `517.07 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `170.67 µs` | `275.59 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `13.87 ms` | `6.74 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `288.53 µs` | `471.62 µs` |
| **`P-384`** | `2.10 ms` | `2.41 ms` |
| **`P-521`** | `2.41 ms` | `11.22 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.02 ms` | `461.23 µs` |
| **`3072`** | `82.39 ms` | `496.47 µs` |
| **`4096`** | `184.98 ms` | `566.42 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `28.84 ms` | `357.63 µs` |
| **`3072`** | `81.80 ms` | `629.08 µs` |
| **`4096`** | `187.58 ms` | `550.88 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.61 ms` | `744.40 µs` |
| **`3072`** | `83.63 ms` | `344.38 µs` |
| **`4096`** | `185.74 ms` | `638.93 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `329.98 µs` | `374.26 µs` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `21.05 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.84 ms` | `2.63 ms` | `3.91 ms` | `5.08 ms` | `7.25 ms` | `5.67 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `34.75 ms` | `121.80 ms` | `363.61 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `3.11 ms` | `3.29 ms` | `3.19 ms` | `3.39 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `814.25 µs` | `503.34 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.79 ms` | `1.97 ms` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `6.65 ms` | `4.32 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `852.82 µs` | `869.61 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `384.09 µs` | `398.55 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `712.16 µs` | `302.08 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `29.02 ms` | `295.71 µs` |
| **`3072`** | `81.30 ms` | `349.42 µs` |
| **`4096`** | `183.42 ms` | `488.22 µs` |

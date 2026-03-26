# Benchmarks — KMS 5.17.0 (Docker)

Image: `ghcr.io/cosmian/kms:5.17.0`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- --conf-path /tmp/tmp.4zFlfbmo6n bench --mode all --format markdown --quick
```

## Benchmark Results

### AES GCM - plaintext of 64 bytes

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `103.09 µs` | `145.76 µs` | `104.45 µs` | `152.23 µs` |
| **`10 requests`** | `239.45 µs` | `279.17 µs` | `273.33 µs` | `303.33 µs` |
| **`100 requests`** | `1.64 ms` | `1.57 ms` | `2.14 ms` | `1.60 ms` |
| **`1000 requests`** | `13.42 ms` | `13.91 ms` | `13.93 ms` | `15.33 ms` |
| **`50 requests`** | `814.70 µs` | `836.66 µs` | `733.67 µs` | `926.94 µs` |
| **`500 requests`** | `6.73 ms` | `7.32 ms` | `6.52 ms` | `12.56 ms` |

### RSA AES KEY WRAP - plaintext of 32 bytes

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `23.46 ms` | `241.70 µs` | `73.86 ms` | `296.27 µs` | `161.80 ms` | `360.35 µs` |
| **`10 requests`** | `230.59 ms` | `1.83 ms` | `717.41 ms` | `2.10 ms` | `1.63 s` | `2.30 ms` |
| **`100 requests`** | `2.40 s` | `14.76 ms` | `7.26 s` | `20.94 ms` | `18.16 s` | `22.25 ms` |
| **`50 requests`** | `1.16 s` | `7.76 ms` | `3.62 s` | `12.91 ms` | `8.47 s` | `11.07 ms` |

### RSA OAEP - plaintext of 32 bytes

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `25.20 ms` | `260.04 µs` | `75.39 ms` | `368.58 µs` | `161.86 ms` | `331.61 µs` |
| **`10 requests`** | `243.65 ms` | `1.71 ms` | `761.32 ms` | `2.20 ms` | `1.63 s` | `2.44 ms` |
| **`100 requests`** | `2.32 s` | `16.02 ms` | `7.29 s` | `18.47 ms` | `16.70 s` | `22.69 ms` |
| **`50 requests`** | `1.18 s` | `11.71 ms` | `3.58 s` | `9.26 ms` | `8.36 s` | `12.53 ms` |

### RSA PKCSv1.5 - plaintext of 32 bytes

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `36.82 ms` | `414.64 µs` | `70.63 ms` | `358.84 µs` | `181.43 ms` | `407.12 µs` |
| **`10 requests`** | `304.28 ms` | `3.31 ms` | `721.58 ms` | `2.95 ms` | `1.70 s` | `3.27 ms` |
| **`100 requests`** | `2.35 s` | `14.91 ms` | `7.35 s` | `21.69 ms` | `16.83 s` | `22.86 ms` |
| **`50 requests`** | `1.23 s` | `10.13 ms` | `3.73 s` | `12.99 ms` | `8.30 s` | `12.46 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `174.16 µs` | `177.38 µs` |
| **`192`** | `188.38 µs` | `156.87 µs` |
| **`256`** | `112.63 µs` | `133.24 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `112.34 µs` | `147.92 µs` |
| **`256`** | `106.02 µs` | `127.46 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `83.45 µs` | `138.77 µs` |
| **`256`** | `79.84 µs` | `145.36 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `132.47 µs` | `155.17 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `13.03 ms` | `5.22 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `193.39 µs` | `299.76 µs` |
| **`P-384`** | `1.44 ms` | `1.21 ms` |
| **`P-521`** | `2.44 ms` | `2.59 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `25.62 ms` | `196.13 µs` |
| **`3072`** | `76.46 ms` | `232.10 µs` |
| **`4096`** | `179.36 ms` | `322.92 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `23.58 ms` | `198.21 µs` |
| **`3072`** | `83.92 ms` | `226.44 µs` |
| **`4096`** | `178.76 ms` | `251.69 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `23.74 ms` | `191.28 µs` |
| **`3072`** | `72.33 ms` | `253.61 µs` |
| **`4096`** | `161.45 ms` | `267.87 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `213.72 µs` | `282.60 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `200.34 µs` | `385.76 µs` |
| **`ML-KEM-512/P-256`** | `506.04 µs` | `473.59 µs` |
| **`ML-KEM-512/X25519`** | `230.95 µs` | `5.08 ms` |
| **`ML-KEM-768`** | `323.30 µs` | `417.32 µs` |
| **`ML-KEM-768/P-256`** | `310.09 µs` | `686.70 µs` |
| **`ML-KEM-768/X25519`** | `408.25 µs` | `3.94 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `24.25 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `2.87 ms` | `3.49 ms` | `2.89 ms` | `4.47 ms` | `3.31 ms` | `3.72 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.15 ms` | `3.78 ms` | `4.32 ms` | `3.17 ms` | `4.27 ms` | `3.75 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `23.60 ms` | `88.37 ms` | `189.14 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.07 ms` | `2.50 ms` | `2.54 ms` | `2.60 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `615.82 µs` | `192.71 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.16 ms` | `520.38 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `3.47 ms` | `1.16 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `483.00 µs` | `454.65 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `208.60 µs` | `195.01 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `422.15 µs` | `270.02 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `26.29 ms` | `178.28 µs` |
| **`3072`** | `76.58 ms` | `250.77 µs` |
| **`4096`** | `165.67 ms` | `210.47 µs` |

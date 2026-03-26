# Benchmark diff — KMS 5.12.0 vs 5.17.0

Baseline image: `ghcr.io/cosmian/kms:5.12.0`
Compare image:  `ghcr.io/cosmian/kms:5.17.0`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- bench --mode all --format json --quick --version-label v<VERSION>
cat v5.12.0.json v5.17.0.json | criterion-table
```

## Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [AES GCM - plaintext of 64 bytes](#aes-gcm---plaintext-of-64-bytes)
    - [RSA AES KEY WRAP - plaintext of 32 bytes](#rsa-aes-key-wrap---plaintext-of-32-bytes)
    - [RSA OAEP - plaintext of 32 bytes](#rsa-oaep---plaintext-of-32-bytes)
    - [RSA PKCSv1.5 - plaintext of 32 bytes](#rsa-pkcsv15---plaintext-of-32-bytes)
    - [encrypt_aes-gcm-siv](#encrypt_aes-gcm-siv)
    - [encrypt_aes-gcm](#encrypt_aes-gcm)
    - [encrypt_aes-xts](#encrypt_aes-xts)
    - [encrypt_chacha20-poly1305](#encrypt_chacha20-poly1305)
    - [encrypt_covercrypt](#encrypt_covercrypt)
    - [encrypt_ecies](#encrypt_ecies)
    - [encrypt_rsa-aes-kwp](#encrypt_rsa-aes-kwp)
    - [encrypt_rsa-oaep](#encrypt_rsa-oaep)
    - [encrypt_rsa-pkcs1v15](#encrypt_rsa-pkcs1v15)
    - [encrypt_salsa-sealed-box](#encrypt_salsa-sealed-box)
    - [key-creation_covercrypt](#key-creation_covercrypt)
    - [key-creation_ec](#key-creation_ec)
    - [key-creation_rsa](#key-creation_rsa)
    - [key-creation_symmetric](#key-creation_symmetric)
    - [sign-verify_ecdsa-p256](#sign-verify_ecdsa-p256)
    - [sign-verify_ecdsa-p384](#sign-verify_ecdsa-p384)
    - [sign-verify_ecdsa-p521](#sign-verify_ecdsa-p521)
    - [sign-verify_ecdsa-secp256k1](#sign-verify_ecdsa-secp256k1)
    - [sign-verify_eddsa-ed25519](#sign-verify_eddsa-ed25519)
    - [sign-verify_rsa-pss](#sign-verify_rsa-pss)
    - [kem_configurable](#kem_configurable)
    - [key-creation_kem](#key-creation_kem)
    - [sign-verify_eddsa-ed448](#sign-verify_eddsa-ed448)

## Benchmark Results

### AES GCM - plaintext of 64 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`128-bit key decrypt - 1 request`**     | `237.84 us` (✅ **1.00x**) | `104.19 us` (🚀 **2.28x faster**)  |
| **`128-bit key decrypt - 10 requests`**   | `337.88 us` (✅ **1.00x**) | `231.07 us` (✅ **1.46x faster**)  |
| **`128-bit key decrypt - 100 requests`**  | `2.77 ms` (✅ **1.00x**)   | `1.59 ms` (✅ **1.75x faster**)    |
| **`128-bit key decrypt - 1000 requests`** | `11.98 ms` (✅ **1.00x**)  | `13.55 ms` (❌ *1.13x slower*)     |
| **`128-bit key decrypt - 50 requests`**   | `945.00 us` (✅ **1.00x**) | `919.25 us` (✅ **1.03x faster**)  |
| **`128-bit key decrypt - 500 requests`**  | `6.25 ms` (✅ **1.00x**)   | `11.13 ms` (❌ *1.78x slower*)     |
| **`128-bit key encrypt - 1 request`**     | `163.07 us` (✅ **1.00x**) | `170.12 us` (✅ **1.04x slower**)  |
| **`128-bit key encrypt - 10 requests`**   | `653.66 us` (✅ **1.00x**) | `509.72 us` (✅ **1.28x faster**)  |
| **`128-bit key encrypt - 100 requests`**  | `1.58 ms` (✅ **1.00x**)   | `2.79 ms` (❌ *1.77x slower*)      |
| **`128-bit key encrypt - 1000 requests`** | `13.89 ms` (✅ **1.00x**)  | `14.17 ms` (✅ **1.02x slower**)   |
| **`128-bit key encrypt - 50 requests`**   | `765.39 us` (✅ **1.00x**) | `1.24 ms` (❌ *1.62x slower*)      |
| **`128-bit key encrypt - 500 requests`**  | `9.59 ms` (✅ **1.00x**)   | `7.37 ms` (✅ **1.30x faster**)    |
| **`256-bit key decrypt - 1 request`**     | `233.66 us` (✅ **1.00x**) | `222.90 us` (✅ **1.05x faster**)  |
| **`256-bit key decrypt - 10 requests`**   | `258.56 us` (✅ **1.00x**) | `243.27 us` (✅ **1.06x faster**)  |
| **`256-bit key decrypt - 100 requests`**  | `1.62 ms` (✅ **1.00x**)   | `1.79 ms` (✅ **1.10x slower**)    |
| **`256-bit key decrypt - 1000 requests`** | `12.91 ms` (✅ **1.00x**)  | `13.94 ms` (✅ **1.08x slower**)   |
| **`256-bit key decrypt - 50 requests`**   | `1.00 ms` (✅ **1.00x**)   | `1.23 ms` (❌ *1.23x slower*)      |
| **`256-bit key decrypt - 500 requests`**  | `6.31 ms` (✅ **1.00x**)   | `7.16 ms` (❌ *1.13x slower*)      |
| **`256-bit key encrypt - 1 request`**     | `323.92 us` (✅ **1.00x**) | `263.45 us` (✅ **1.23x faster**)  |
| **`256-bit key encrypt - 10 requests`**   | `288.98 us` (✅ **1.00x**) | `465.21 us` (❌ *1.61x slower*)    |
| **`256-bit key encrypt - 100 requests`**  | `2.48 ms` (✅ **1.00x**)   | `1.73 ms` (✅ **1.43x faster**)    |
| **`256-bit key encrypt - 1000 requests`** | `14.57 ms` (✅ **1.00x**)  | `14.88 ms` (✅ **1.02x slower**)   |
| **`256-bit key encrypt - 50 requests`**   | `1.07 ms` (✅ **1.00x**)   | `2.00 ms` (❌ *1.87x slower*)      |
| **`256-bit key encrypt - 500 requests`**  | `9.83 ms` (✅ **1.00x**)   | `13.37 ms` (❌ *1.36x slower*)     |

### RSA AES KEY WRAP - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `27.36 ms` (✅ **1.00x**)  | `24.97 ms` (✅ **1.10x faster**)   |
| **`2048-bit key decrypt - 10 requests`**  | `244.49 ms` (✅ **1.00x**) | `243.41 ms` (✅ **1.00x faster**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.50 s` (✅ **1.00x**)    | `2.54 s` (✅ **1.02x slower**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.26 s` (✅ **1.00x**)    | `1.26 s` (✅ **1.01x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `330.66 us` (✅ **1.00x**) | `244.28 us` (✅ **1.35x faster**)  |
| **`2048-bit key encrypt - 10 requests`**  | `2.14 ms` (✅ **1.00x**)   | `2.36 ms` (✅ **1.10x slower**)    |
| **`2048-bit key encrypt - 100 requests`** | `12.10 ms` (✅ **1.00x**)  | `15.11 ms` (❌ *1.25x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `6.83 ms` (✅ **1.00x**)   | `14.09 ms` (❌ *2.06x slower*)     |
| **`3072-bit key decrypt - 1 request`**    | `79.42 ms` (✅ **1.00x**)  | `77.56 ms` (✅ **1.02x faster**)   |
| **`3072-bit key decrypt - 10 requests`**  | `766.84 ms` (✅ **1.00x**) | `755.13 ms` (✅ **1.02x faster**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.69 s` (✅ **1.00x**)    | `7.63 s` (✅ **1.01x faster**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.90 s` (✅ **1.00x**)    | `3.86 s` (✅ **1.01x faster**)     |
| **`3072-bit key encrypt - 1 request`**    | `322.22 us` (✅ **1.00x**) | `375.03 us` (❌ *1.16x slower*)    |
| **`3072-bit key encrypt - 10 requests`**  | `1.68 ms` (✅ **1.00x**)   | `2.04 ms` (❌ *1.21x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `15.43 ms` (✅ **1.00x**)  | `18.80 ms` (❌ *1.22x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `8.03 ms` (✅ **1.00x**)   | `9.22 ms` (❌ *1.15x slower*)      |
| **`4096-bit key decrypt - 1 request`**    | `180.42 ms` (✅ **1.00x**) | `172.23 ms` (✅ **1.05x faster**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.77 s` (✅ **1.00x**)    | `1.79 s` (✅ **1.01x slower**)     |
| **`4096-bit key decrypt - 100 requests`** | `17.63 s` (✅ **1.00x**)   | `17.55 s` (✅ **1.00x faster**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.77 s` (✅ **1.00x**)    | `8.78 s` (✅ **1.00x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `367.03 us` (✅ **1.00x**) | `419.79 us` (❌ *1.14x slower*)    |
| **`4096-bit key encrypt - 10 requests`**  | `3.01 ms` (✅ **1.00x**)   | `3.60 ms` (❌ *1.20x slower*)      |
| **`4096-bit key encrypt - 100 requests`** | `20.50 ms` (✅ **1.00x**)  | `23.19 ms` (❌ *1.13x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `9.96 ms` (✅ **1.00x**)   | `15.45 ms` (❌ *1.55x slower*)     |

### RSA OAEP - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.28 ms` (✅ **1.00x**)  | `27.26 ms` (✅ **1.04x slower**)   |
| **`2048-bit key decrypt - 10 requests`**  | `256.86 ms` (✅ **1.00x**) | `244.45 ms` (✅ **1.05x faster**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.48 s` (✅ **1.00x**)    | `2.45 s` (✅ **1.01x faster**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.26 s` (✅ **1.00x**)    | `1.28 s` (✅ **1.02x slower**)     |
| **`2048-bit key encrypt - 1 request`**    | `280.01 us` (✅ **1.00x**) | `470.12 us` (❌ *1.68x slower*)    |
| **`2048-bit key encrypt - 10 requests`**  | `1.40 ms` (✅ **1.00x**)   | `2.44 ms` (❌ *1.74x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `11.97 ms` (✅ **1.00x**)  | `20.57 ms` (❌ *1.72x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `6.31 ms` (✅ **1.00x**)   | `14.12 ms` (❌ *2.24x slower*)     |
| **`3072-bit key decrypt - 1 request`**    | `77.46 ms` (✅ **1.00x**)  | `79.39 ms` (✅ **1.02x slower**)   |
| **`3072-bit key decrypt - 10 requests`**  | `791.01 ms` (✅ **1.00x**) | `774.99 ms` (✅ **1.02x faster**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.75 s` (✅ **1.00x**)    | `7.71 s` (✅ **1.01x faster**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.82 s` (✅ **1.00x**)    | `3.83 s` (✅ **1.00x slower**)     |
| **`3072-bit key encrypt - 1 request`**    | `347.70 us` (✅ **1.00x**) | `371.24 us` (✅ **1.07x slower**)  |
| **`3072-bit key encrypt - 10 requests`**  | `3.32 ms` (✅ **1.00x**)   | `2.49 ms` (✅ **1.33x faster**)    |
| **`3072-bit key encrypt - 100 requests`** | `15.73 ms` (✅ **1.00x**)  | `18.77 ms` (❌ *1.19x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `7.91 ms` (✅ **1.00x**)   | `12.99 ms` (❌ *1.64x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `175.93 ms` (✅ **1.00x**) | `182.24 ms` (✅ **1.04x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.75 s` (✅ **1.00x**)    | `1.73 s` (✅ **1.01x faster**)     |
| **`4096-bit key decrypt - 100 requests`** | `17.58 s` (✅ **1.00x**)   | `17.54 s` (✅ **1.00x faster**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.84 s` (✅ **1.00x**)    | `8.83 s` (✅ **1.00x faster**)     |
| **`4096-bit key encrypt - 1 request`**    | `383.80 us` (✅ **1.00x**) | `366.50 us` (✅ **1.05x faster**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.84 ms` (✅ **1.00x**)   | `2.47 ms` (✅ **1.15x faster**)    |
| **`4096-bit key encrypt - 100 requests`** | `19.53 ms` (✅ **1.00x**)  | `23.17 ms` (❌ *1.19x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `14.61 ms` (✅ **1.00x**)  | `13.28 ms` (✅ **1.10x faster**)   |

### RSA PKCSv1.5 - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `27.61 ms` (✅ **1.00x**)  | `25.25 ms` (✅ **1.09x faster**)   |
| **`2048-bit key decrypt - 10 requests`**  | `248.68 ms` (✅ **1.00x**) | `259.29 ms` (✅ **1.04x slower**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.53 s` (✅ **1.00x**)    | `2.49 s` (✅ **1.02x faster**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.25 s` (✅ **1.00x**)    | `1.23 s` (✅ **1.02x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `423.06 us` (✅ **1.00x**) | `269.40 us` (✅ **1.57x faster**)  |
| **`2048-bit key encrypt - 10 requests`**  | `1.33 ms` (✅ **1.00x**)   | `2.14 ms` (❌ *1.60x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `11.86 ms` (✅ **1.00x**)  | `16.37 ms` (❌ *1.38x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `8.65 ms` (✅ **1.00x**)   | `13.43 ms` (❌ *1.55x slower*)     |
| **`3072-bit key decrypt - 1 request`**    | `75.23 ms` (✅ **1.00x**)  | `79.67 ms` (✅ **1.06x slower**)   |
| **`3072-bit key decrypt - 10 requests`**  | `757.68 ms` (✅ **1.00x**) | `793.96 ms` (✅ **1.05x slower**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.72 s` (✅ **1.00x**)    | `7.67 s` (✅ **1.01x faster**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.86 s` (✅ **1.00x**)    | `3.75 s` (✅ **1.03x faster**)     |
| **`3072-bit key encrypt - 1 request`**    | `463.77 us` (✅ **1.00x**) | `368.34 us` (✅ **1.26x faster**)  |
| **`3072-bit key encrypt - 10 requests`**  | `1.73 ms` (✅ **1.00x**)   | `2.87 ms` (❌ *1.66x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `18.26 ms` (✅ **1.00x**)  | `22.71 ms` (❌ *1.24x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `7.80 ms` (✅ **1.00x**)   | `14.26 ms` (❌ *1.83x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `178.66 ms` (✅ **1.00x**) | `176.11 ms` (✅ **1.01x faster**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.79 s` (✅ **1.00x**)    | `1.74 s` (✅ **1.03x faster**)     |
| **`4096-bit key decrypt - 100 requests`** | `17.59 s` (✅ **1.00x**)   | `17.62 s` (✅ **1.00x slower**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.76 s` (✅ **1.00x**)    | `8.82 s` (✅ **1.01x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `365.99 us` (✅ **1.00x**) | `304.12 us` (✅ **1.20x faster**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.24 ms` (✅ **1.00x**)   | `2.31 ms` (✅ **1.03x slower**)    |
| **`4096-bit key encrypt - 100 requests`** | `19.62 ms` (✅ **1.00x**)  | `22.48 ms` (❌ *1.15x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `10.52 ms` (✅ **1.00x**)  | `26.91 ms` (❌ *2.56x slower*)     |

### encrypt_aes-gcm-siv

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `262.21 us` (✅ **1.00x**) | `255.63 us` (✅ **1.03x faster**)  |
| **`decrypt - 256`** | `113.58 us` (✅ **1.00x**) | `110.85 us` (✅ **1.02x faster**)  |
| **`encrypt - 128`** | `179.83 us` (✅ **1.00x**) | `273.66 us` (❌ *1.52x slower*)    |
| **`encrypt - 256`** | `365.10 us` (✅ **1.00x**) | `349.12 us` (✅ **1.05x faster**)  |

### encrypt_aes-gcm

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `359.98 us` (✅ **1.00x**) | `152.82 us` (🚀 **2.36x faster**)  |
| **`decrypt - 256`** | `173.18 us` (✅ **1.00x**) | `133.42 us` (✅ **1.30x faster**)  |
| **`encrypt - 128`** | `139.53 us` (✅ **1.00x**) | `436.51 us` (❌ *3.13x slower*)    |
| **`encrypt - 256`** | `156.91 us` (✅ **1.00x**) | `259.87 us` (❌ *1.66x slower*)    |
| **`decrypt - 192`** | `N/A`                     | `243.23 us` (✅ **1.00x**)         |
| **`encrypt - 192`** | `N/A`                     | `163.38 us` (✅ **1.00x**)         |

### encrypt_aes-xts

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `227.99 us` (✅ **1.00x**) | `107.83 us` (🚀 **2.11x faster**)  |
| **`decrypt - 256`** | `287.09 us` (✅ **1.00x**) | `174.91 us` (✅ **1.64x faster**)  |
| **`encrypt - 128`** | `319.57 us` (✅ **1.00x**) | `155.85 us` (🚀 **2.05x faster**)  |
| **`encrypt - 256`** | `209.30 us` (✅ **1.00x**) | `163.22 us` (✅ **1.28x faster**)  |

### encrypt_chacha20-poly1305

|                   | `v5.12.0`                 | `v5.17.0`                         |
|:------------------|:--------------------------|:--------------------------------- |
| **`decrypt_256`** | `374.95 us` (✅ **1.00x**) | `258.18 us` (✅ **1.45x faster**)  |
| **`encrypt_256`** | `163.19 us` (✅ **1.00x**) | `184.32 us` (❌ *1.13x slower*)    |

### encrypt_covercrypt

|               | `v5.12.0`                 | `v5.17.0`                         |
|:--------------|:--------------------------|:--------------------------------- |
| **`decrypt`** | `364.29 us` (✅ **1.00x**) | `12.47 ms` (❌ *34.22x slower*)    |
| **`encrypt`** | `281.31 us` (✅ **1.00x**) | `9.94 ms` (❌ *35.32x slower*)     |

### encrypt_ecies

|                       | `v5.12.0`                 | `v5.17.0`                         |
|:----------------------|:--------------------------|:--------------------------------- |
| **`decrypt - P-256`** | `269.42 us` (✅ **1.00x**) | `224.43 us` (✅ **1.20x faster**)  |
| **`decrypt - P-384`** | `2.14 ms` (✅ **1.00x**)   | `1.53 ms` (✅ **1.40x faster**)    |
| **`decrypt - P-521`** | `4.12 ms` (✅ **1.00x**)   | `2.45 ms` (✅ **1.68x faster**)    |
| **`encrypt - P-256`** | `322.39 us` (✅ **1.00x**) | `318.39 us` (✅ **1.01x faster**)  |
| **`encrypt - P-384`** | `1.87 ms` (✅ **1.00x**)   | `1.65 ms` (✅ **1.14x faster**)    |
| **`encrypt - P-521`** | `4.88 ms` (✅ **1.00x**)   | `2.98 ms` (✅ **1.64x faster**)    |

### encrypt_rsa-aes-kwp

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `23.55 ms` (✅ **1.00x**)  | `26.86 ms` (❌ *1.14x slower*)     |
| **`decrypt - 3072`** | `71.76 ms` (✅ **1.00x**)  | `77.13 ms` (✅ **1.07x slower**)   |
| **`decrypt - 4096`** | `166.42 ms` (✅ **1.00x**) | `175.44 ms` (✅ **1.05x slower**)  |
| **`encrypt - 2048`** | `246.32 us` (✅ **1.00x**) | `211.83 us` (✅ **1.16x faster**)  |
| **`encrypt - 3072`** | `337.95 us` (✅ **1.00x**) | `265.34 us` (✅ **1.27x faster**)  |
| **`encrypt - 4096`** | `485.68 us` (✅ **1.00x**) | `275.22 us` (✅ **1.76x faster**)  |

### encrypt_rsa-oaep

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `24.24 ms` (✅ **1.00x**)  | `25.00 ms` (✅ **1.03x slower**)   |
| **`decrypt - 3072`** | `72.72 ms` (✅ **1.00x**)  | `75.51 ms` (✅ **1.04x slower**)   |
| **`decrypt - 4096`** | `163.72 ms` (✅ **1.00x**) | `163.10 ms` (✅ **1.00x faster**)  |
| **`encrypt - 2048`** | `203.37 us` (✅ **1.00x**) | `270.93 us` (❌ *1.33x slower*)    |
| **`encrypt - 3072`** | `227.66 us` (✅ **1.00x**) | `219.94 us` (✅ **1.04x faster**)  |
| **`encrypt - 4096`** | `384.68 us` (✅ **1.00x**) | `521.02 us` (❌ *1.35x slower*)    |

### encrypt_rsa-pkcs1v15

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `24.81 ms` (✅ **1.00x**)  | `24.95 ms` (✅ **1.01x slower**)   |
| **`decrypt - 3072`** | `75.16 ms` (✅ **1.00x**)  | `80.77 ms` (✅ **1.07x slower**)   |
| **`decrypt - 4096`** | `162.56 ms` (✅ **1.00x**) | `178.68 ms` (✅ **1.10x slower**)  |
| **`encrypt - 2048`** | `146.42 us` (✅ **1.00x**) | `226.22 us` (❌ *1.55x slower*)    |
| **`encrypt - 3072`** | `261.22 us` (✅ **1.00x**) | `333.87 us` (❌ *1.28x slower*)    |
| **`encrypt - 4096`** | `226.60 us` (✅ **1.00x**) | `327.74 us` (❌ *1.45x slower*)    |

### encrypt_salsa-sealed-box

|               | `v5.12.0`                 | `v5.17.0`                         |
|:--------------|:--------------------------|:--------------------------------- |
| **`decrypt`** | `313.85 us` (✅ **1.00x**) | `219.48 us` (✅ **1.43x faster**)  |
| **`encrypt`** | `211.91 us` (✅ **1.00x**) | `457.24 us` (❌ *2.16x slower*)    |

### key-creation_covercrypt

|                      | `v5.12.0`               | `v5.17.0`                        |
|:---------------------|:------------------------|:-------------------------------- |
| **`master-keypair`** | `5.61 ms` (✅ **1.00x**) | `25.07 ms` (❌ *4.47x slower*)    |

### key-creation_ec

|                 | `v5.12.0`               | `v5.17.0`                       |
|:----------------|:------------------------|:------------------------------- |
| **`ed25519`**   | `3.24 ms` (✅ **1.00x**) | `3.37 ms` (✅ **1.04x slower**)  |
| **`ed448`**     | `4.74 ms` (✅ **1.00x**) | `3.45 ms` (✅ **1.37x faster**)  |
| **`p256`**      | `3.89 ms` (✅ **1.00x**) | `3.55 ms` (✅ **1.09x faster**)  |
| **`p384`**      | `4.73 ms` (✅ **1.00x**) | `6.05 ms` (❌ *1.28x slower*)    |
| **`p521`**      | `8.66 ms` (✅ **1.00x**) | `4.75 ms` (🚀 **1.82x faster**)  |
| **`secp256k1`** | `4.65 ms` (✅ **1.00x**) | `3.86 ms` (✅ **1.20x faster**)  |

### key-creation_rsa

|                | `v5.12.0`                 | `v5.17.0`                         |
|:---------------|:--------------------------|:--------------------------------- |
| **`rsa-2048`** | `36.85 ms` (✅ **1.00x**)  | `33.87 ms` (✅ **1.09x faster**)   |
| **`rsa-3072`** | `156.37 ms` (✅ **1.00x**) | `100.71 ms` (✅ **1.55x faster**)  |
| **`rsa-4096`** | `313.72 ms` (✅ **1.00x**) | `316.38 ms` (✅ **1.01x slower**)  |

### key-creation_symmetric

|                    | `v5.12.0`               | `v5.17.0`                       |
|:-------------------|:------------------------|:------------------------------- |
| **`aes-128`**      | `9.44 ms` (✅ **1.00x**) | `2.85 ms` (🚀 **3.32x faster**)  |
| **`aes-192`**      | `6.13 ms` (✅ **1.00x**) | `3.10 ms` (🚀 **1.98x faster**)  |
| **`aes-256`**      | `3.30 ms` (✅ **1.00x**) | `3.02 ms` (✅ **1.09x faster**)  |
| **`chacha20-256`** | `3.13 ms` (✅ **1.00x**) | `2.78 ms` (✅ **1.13x faster**)  |

### sign-verify_ecdsa-p256

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `283.50 us` (✅ **1.00x**) | `570.31 us` (❌ *2.01x slower*)    |
| **`verify`** | `353.40 us` (✅ **1.00x**) | `225.33 us` (✅ **1.57x faster**)  |

### sign-verify_ecdsa-p384

|              | `v5.12.0`               | `v5.17.0`                         |
|:-------------|:------------------------|:--------------------------------- |
| **`sign`**   | `1.44 ms` (✅ **1.00x**) | `1.32 ms` (✅ **1.10x faster**)    |
| **`verify`** | `1.33 ms` (✅ **1.00x**) | `583.35 us` (🚀 **2.28x faster**)  |

### sign-verify_ecdsa-p521

|              | `v5.12.0`               | `v5.17.0`                       |
|:-------------|:------------------------|:------------------------------- |
| **`sign`**   | `3.33 ms` (✅ **1.00x**) | `2.26 ms` (✅ **1.47x faster**)  |
| **`verify`** | `2.29 ms` (✅ **1.00x**) | `1.14 ms` (🚀 **2.01x faster**)  |

### sign-verify_ecdsa-secp256k1

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `697.40 us` (✅ **1.00x**) | `459.61 us` (✅ **1.52x faster**)  |
| **`verify`** | `773.25 us` (✅ **1.00x**) | `388.96 us` (🚀 **1.99x faster**)  |

### sign-verify_eddsa-ed25519

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `339.06 us` (✅ **1.00x**) | `262.10 us` (✅ **1.29x faster**)  |
| **`verify`** | `216.50 us` (✅ **1.00x**) | `217.25 us` (✅ **1.00x slower**)  |

### sign-verify_rsa-pss

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`sign - 2048`**   | `29.46 ms` (✅ **1.00x**)  | `26.61 ms` (✅ **1.11x faster**)   |
| **`sign - 3072`**   | `77.33 ms` (✅ **1.00x**)  | `77.05 ms` (✅ **1.00x faster**)   |
| **`sign - 4096`**   | `169.56 ms` (✅ **1.00x**) | `178.65 ms` (✅ **1.05x slower**)  |
| **`verify - 2048`** | `390.03 us` (✅ **1.00x**) | `161.64 us` (🚀 **2.41x faster**)  |
| **`verify - 3072`** | `532.39 us` (✅ **1.00x**) | `217.29 us` (🚀 **2.45x faster**)  |
| **`verify - 4096`** | `647.66 us` (✅ **1.00x**) | `328.55 us` (🚀 **1.97x faster**)  |

### kem_configurable

|                                       | `v5.17.0`                  |
|:--------------------------------------|:-------------------------- |
| **`decapsulate - ML-KEM-512`**        | `368.65 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-512_P-256`**  | `756.29 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-512_X25519`** | `250.12 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768`**        | `300.92 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768_P-256`**  | `733.30 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768_X25519`** | `319.67 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512`**        | `476.00 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512_P-256`**  | `617.99 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512_X25519`** | `3.63 ms` (✅ **1.00x**)    |
| **`encapsulate - ML-KEM-768`**        | `449.25 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-768_P-256`**  | `556.10 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-768_X25519`** | `3.65 ms` (✅ **1.00x**)    |

### key-creation_kem

|                         | `v5.17.0`                |
|:------------------------|:------------------------ |
| **`ML-KEM-512`**        | `3.29 ms` (✅ **1.00x**)  |
| **`ML-KEM-512_P-256`**  | `3.82 ms` (✅ **1.00x**)  |
| **`ML-KEM-512_X25519`** | `6.21 ms` (✅ **1.00x**)  |
| **`ML-KEM-768`**        | `4.16 ms` (✅ **1.00x**)  |
| **`ML-KEM-768_P-256`**  | `4.07 ms` (✅ **1.00x**)  |
| **`ML-KEM-768_X25519`** | `6.49 ms` (✅ **1.00x**)  |

### sign-verify_eddsa-ed448

|              | `v5.17.0`                  |
|:-------------|:-------------------------- |
| **`sign`**   | `455.30 us` (✅ **1.00x**)  |
| **`verify`** | `323.50 us` (✅ **1.00x**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

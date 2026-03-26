# Benchmark diff — KMS 5.17 vs 5.18

Baseline image: `ghcr.io/cosmian/kms:5.17`
Compare image:  `ghcr.io/cosmian/kms:5.18`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- bench --mode all --format json --speed quick --version-label v<VERSION>
cat v5.17.json v5.18.json | criterion-table
```

## Benchmarks

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [batch_aes-gcm](#batch_aes-gcm)
    - [batch_rsa-aes-kwp](#batch_rsa-aes-kwp)
    - [batch_rsa-oaep](#batch_rsa-oaep)
    - [batch_rsa-pkcs1v15](#batch_rsa-pkcs1v15)
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
    - [kem_configurable](#kem_configurable)
    - [key-creation_covercrypt](#key-creation_covercrypt)
    - [key-creation_ec](#key-creation_ec)
    - [key-creation_kem](#key-creation_kem)
    - [key-creation_rsa](#key-creation_rsa)
    - [key-creation_symmetric](#key-creation_symmetric)
    - [sign-verify_ecdsa-p256](#sign-verify_ecdsa-p256)
    - [sign-verify_ecdsa-p384](#sign-verify_ecdsa-p384)
    - [sign-verify_ecdsa-p521](#sign-verify_ecdsa-p521)
    - [sign-verify_ecdsa-secp256k1](#sign-verify_ecdsa-secp256k1)
    - [sign-verify_eddsa-ed25519](#sign-verify_eddsa-ed25519)
    - [sign-verify_eddsa-ed448](#sign-verify_eddsa-ed448)
    - [sign-verify_rsa-pss](#sign-verify_rsa-pss)
    - [kem_pqc](#kem_pqc)
    - [key-creation_pqc](#key-creation_pqc)
    - [sign-verify_ml-dsa](#sign-verify_ml-dsa)
    - [sign-verify_slh-dsa](#sign-verify_slh-dsa)

## Benchmark Results

### batch_aes-gcm

|                                           | `v5.17`                   | `v5.18`                           |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`128-bit key decrypt - 1 request`**     | `280.85 us` (✅ **1.00x**) | `182.21 us` (✅ **1.54x faster**)  |
| **`128-bit key decrypt - 10 requests`**   | `304.85 us` (✅ **1.00x**) | `480.57 us` (❌ *1.58x slower*)    |
| **`128-bit key decrypt - 100 requests`**  | `1.98 ms` (✅ **1.00x**)   | `1.98 ms` (✅ **1.00x faster**)    |
| **`128-bit key decrypt - 1000 requests`** | `14.77 ms` (✅ **1.00x**)  | `15.45 ms` (✅ **1.05x slower**)   |
| **`128-bit key decrypt - 50 requests`**   | `964.22 us` (✅ **1.00x**) | `1.12 ms` (❌ *1.16x slower*)      |
| **`128-bit key decrypt - 500 requests`**  | `7.67 ms` (✅ **1.00x**)   | `7.93 ms` (✅ **1.03x slower**)    |
| **`128-bit key encrypt - 1 request`**     | `168.37 us` (✅ **1.00x**) | `329.47 us` (❌ *1.96x slower*)    |
| **`128-bit key encrypt - 10 requests`**   | `412.78 us` (✅ **1.00x**) | `458.64 us` (✅ **1.11x slower**)  |
| **`128-bit key encrypt - 100 requests`**  | `1.71 ms` (✅ **1.00x**)   | `2.01 ms` (❌ *1.17x slower*)      |
| **`128-bit key encrypt - 1000 requests`** | `16.41 ms` (✅ **1.00x**)  | `15.74 ms` (✅ **1.04x faster**)   |
| **`128-bit key encrypt - 50 requests`**   | `950.77 us` (✅ **1.00x**) | `1.22 ms` (❌ *1.28x slower*)      |
| **`128-bit key encrypt - 500 requests`**  | `7.57 ms` (✅ **1.00x**)   | `7.81 ms` (✅ **1.03x slower**)    |
| **`256-bit key decrypt - 1 request`**     | `127.26 us` (✅ **1.00x**) | `217.20 us` (❌ *1.71x slower*)    |
| **`256-bit key decrypt - 10 requests`**   | `278.62 us` (✅ **1.00x**) | `323.20 us` (❌ *1.16x slower*)    |
| **`256-bit key decrypt - 100 requests`**  | `1.53 ms` (✅ **1.00x**)   | `1.83 ms` (❌ *1.20x slower*)      |
| **`256-bit key decrypt - 1000 requests`** | `16.41 ms` (✅ **1.00x**)  | `15.44 ms` (✅ **1.06x faster**)   |
| **`256-bit key decrypt - 50 requests`**   | `873.17 us` (✅ **1.00x**) | `1.14 ms` (❌ *1.31x slower*)      |
| **`256-bit key decrypt - 500 requests`**  | `6.89 ms` (✅ **1.00x**)   | `9.03 ms` (❌ *1.31x slower*)      |
| **`256-bit key encrypt - 1 request`**     | `290.33 us` (✅ **1.00x**) | `346.70 us` (❌ *1.19x slower*)    |
| **`256-bit key encrypt - 10 requests`**   | `293.05 us` (✅ **1.00x**) | `442.33 us` (❌ *1.51x slower*)    |
| **`256-bit key encrypt - 100 requests`**  | `2.18 ms` (✅ **1.00x**)   | `1.78 ms` (✅ **1.23x faster**)    |
| **`256-bit key encrypt - 1000 requests`** | `17.69 ms` (✅ **1.00x**)  | `17.53 ms` (✅ **1.01x faster**)   |
| **`256-bit key encrypt - 50 requests`**   | `889.03 us` (✅ **1.00x**) | `1.48 ms` (❌ *1.66x slower*)      |
| **`256-bit key encrypt - 500 requests`**  | `11.06 ms` (✅ **1.00x**)  | `8.02 ms` (✅ **1.38x faster**)    |

### batch_rsa-aes-kwp

|                                           | `v5.17`                   | `v5.18`                           |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `24.65 ms` (✅ **1.00x**)  | `27.61 ms` (❌ *1.12x slower*)     |
| **`2048-bit key decrypt - 10 requests`**  | `237.30 ms` (✅ **1.00x**) | `256.67 ms` (✅ **1.08x slower**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.42 s` (✅ **1.00x**)    | `2.43 s` (✅ **1.00x slower**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.19 s` (✅ **1.00x**)    | `1.20 s` (✅ **1.00x slower**)     |
| **`2048-bit key encrypt - 1 request`**    | `355.99 us` (✅ **1.00x**) | `305.30 us` (✅ **1.17x faster**)  |
| **`2048-bit key encrypt - 10 requests`**  | `1.80 ms` (✅ **1.00x**)   | `2.28 ms` (❌ *1.27x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `15.29 ms` (✅ **1.00x**)  | `16.61 ms` (✅ **1.09x slower**)   |
| **`2048-bit key encrypt - 50 requests`**  | `7.54 ms` (✅ **1.00x**)   | `9.62 ms` (❌ *1.28x slower*)      |
| **`3072-bit key decrypt - 1 request`**    | `73.27 ms` (✅ **1.00x**)  | `82.45 ms` (❌ *1.13x slower*)     |
| **`3072-bit key decrypt - 10 requests`**  | `724.85 ms` (✅ **1.00x**) | `739.54 ms` (✅ **1.02x slower**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.40 s` (✅ **1.00x**)    | `7.38 s` (✅ **1.00x faster**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.70 s` (✅ **1.00x**)    | `3.73 s` (✅ **1.01x slower**)     |
| **`3072-bit key encrypt - 1 request`**    | `308.13 us` (✅ **1.00x**) | `549.66 us` (❌ *1.78x slower*)    |
| **`3072-bit key encrypt - 10 requests`**  | `2.57 ms` (✅ **1.00x**)   | `2.33 ms` (✅ **1.10x faster**)    |
| **`3072-bit key encrypt - 100 requests`** | `19.32 ms` (✅ **1.00x**)  | `19.50 ms` (✅ **1.01x slower**)   |
| **`3072-bit key encrypt - 50 requests`**  | `9.78 ms` (✅ **1.00x**)   | `10.68 ms` (✅ **1.09x slower**)   |
| **`4096-bit key decrypt - 1 request`**    | `176.28 ms` (✅ **1.00x**) | `177.19 ms` (✅ **1.01x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.65 s` (✅ **1.00x**)    | `1.79 s` (✅ **1.08x slower**)     |
| **`4096-bit key decrypt - 100 requests`** | `16.96 s` (✅ **1.00x**)   | `16.97 s` (✅ **1.00x slower**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.50 s` (✅ **1.00x**)    | `8.46 s` (✅ **1.00x faster**)     |
| **`4096-bit key encrypt - 1 request`**    | `418.81 us` (✅ **1.00x**) | `365.14 us` (✅ **1.15x faster**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.50 ms` (✅ **1.00x**)   | `4.17 ms` (❌ *1.67x slower*)      |
| **`4096-bit key encrypt - 100 requests`** | `24.04 ms` (✅ **1.00x**)  | `26.90 ms` (❌ *1.12x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `11.71 ms` (✅ **1.00x**)  | `20.00 ms` (❌ *1.71x slower*)     |

### batch_rsa-oaep

|                                           | `v5.17`                   | `v5.18`                           |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.78 ms` (✅ **1.00x**)  | `26.47 ms` (✅ **1.01x faster**)   |
| **`2048-bit key decrypt - 10 requests`**  | `241.90 ms` (✅ **1.00x**) | `248.52 ms` (✅ **1.03x slower**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.48 s` (✅ **1.00x**)    | `2.39 s` (✅ **1.04x faster**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.18 s` (✅ **1.00x**)    | `1.29 s` (✅ **1.09x slower**)     |
| **`2048-bit key encrypt - 1 request`**    | `317.94 us` (✅ **1.00x**) | `483.42 us` (❌ *1.52x slower*)    |
| **`2048-bit key encrypt - 10 requests`**  | `2.01 ms` (✅ **1.00x**)   | `2.29 ms` (❌ *1.14x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `17.11 ms` (✅ **1.00x**)  | `15.44 ms` (✅ **1.11x faster**)   |
| **`2048-bit key encrypt - 50 requests`**  | `9.38 ms` (✅ **1.00x**)   | `16.20 ms` (❌ *1.73x slower*)     |
| **`3072-bit key decrypt - 1 request`**    | `74.50 ms` (✅ **1.00x**)  | `78.85 ms` (✅ **1.06x slower**)   |
| **`3072-bit key decrypt - 10 requests`**  | `726.53 ms` (✅ **1.00x**) | `783.33 ms` (✅ **1.08x slower**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.35 s` (✅ **1.00x**)    | `7.42 s` (✅ **1.01x slower**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.73 s` (✅ **1.00x**)    | `3.66 s` (✅ **1.02x faster**)     |
| **`3072-bit key encrypt - 1 request`**    | `429.54 us` (✅ **1.00x**) | `580.86 us` (❌ *1.35x slower*)    |
| **`3072-bit key encrypt - 10 requests`**  | `2.10 ms` (✅ **1.00x**)   | `2.26 ms` (✅ **1.08x slower**)    |
| **`3072-bit key encrypt - 100 requests`** | `19.36 ms` (✅ **1.00x**)  | `22.22 ms` (❌ *1.15x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `9.81 ms` (✅ **1.00x**)   | `11.37 ms` (❌ *1.16x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `188.04 ms` (✅ **1.00x**) | `179.31 ms` (✅ **1.05x faster**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.70 s` (✅ **1.00x**)    | `1.69 s` (✅ **1.01x faster**)     |
| **`4096-bit key decrypt - 100 requests`** | `17.08 s` (✅ **1.00x**)   | `17.04 s` (✅ **1.00x faster**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.47 s` (✅ **1.00x**)    | `8.48 s` (✅ **1.00x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `566.28 us` (✅ **1.00x**) | `399.92 us` (✅ **1.42x faster**)  |
| **`4096-bit key encrypt - 10 requests`**  | `3.97 ms` (✅ **1.00x**)   | `3.54 ms` (✅ **1.12x faster**)    |
| **`4096-bit key encrypt - 100 requests`** | `23.10 ms` (✅ **1.00x**)  | `23.77 ms` (✅ **1.03x slower**)   |
| **`4096-bit key encrypt - 50 requests`**  | `11.61 ms` (✅ **1.00x**)  | `19.34 ms` (❌ *1.67x slower*)     |

### batch_rsa-pkcs1v15

|                                           | `v5.17`                   | `v5.18`                           |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.38 ms` (✅ **1.00x**)  | `28.96 ms` (✅ **1.10x slower**)   |
| **`2048-bit key decrypt - 10 requests`**  | `246.77 ms` (✅ **1.00x**) | `251.57 ms` (✅ **1.02x slower**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.39 s` (✅ **1.00x**)    | `2.45 s` (✅ **1.02x slower**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.29 s` (✅ **1.00x**)    | `1.21 s` (✅ **1.07x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `318.80 us` (✅ **1.00x**) | `515.13 us` (❌ *1.62x slower*)    |
| **`2048-bit key encrypt - 10 requests`**  | `2.54 ms` (✅ **1.00x**)   | `4.02 ms` (❌ *1.58x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `16.90 ms` (✅ **1.00x**)  | `16.14 ms` (✅ **1.05x faster**)   |
| **`2048-bit key encrypt - 50 requests`**  | `10.50 ms` (✅ **1.00x**)  | `16.39 ms` (❌ *1.56x slower*)     |
| **`3072-bit key decrypt - 1 request`**    | `79.12 ms` (✅ **1.00x**)  | `78.44 ms` (✅ **1.01x faster**)   |
| **`3072-bit key decrypt - 10 requests`**  | `773.30 ms` (✅ **1.00x**) | `737.22 ms` (✅ **1.05x faster**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.40 s` (✅ **1.00x**)    | `7.42 s` (✅ **1.00x slower**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.63 s` (✅ **1.00x**)    | `3.74 s` (✅ **1.03x slower**)     |
| **`3072-bit key encrypt - 1 request`**    | `374.57 us` (✅ **1.00x**) | `410.29 us` (✅ **1.10x slower**)  |
| **`3072-bit key encrypt - 10 requests`**  | `2.53 ms` (✅ **1.00x**)   | `3.53 ms` (❌ *1.40x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `25.16 ms` (✅ **1.00x**)  | `22.81 ms` (✅ **1.10x faster**)   |
| **`3072-bit key encrypt - 50 requests`**  | `13.69 ms` (✅ **1.00x**)  | `12.38 ms` (✅ **1.11x faster**)   |
| **`4096-bit key decrypt - 1 request`**    | `174.24 ms` (✅ **1.00x**) | `186.69 ms` (✅ **1.07x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.69 s` (✅ **1.00x**)    | `1.67 s` (✅ **1.01x faster**)     |
| **`4096-bit key decrypt - 100 requests`** | `16.91 s` (✅ **1.00x**)   | `16.94 s` (✅ **1.00x slower**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.47 s` (✅ **1.00x**)    | `8.54 s` (✅ **1.01x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `498.82 us` (✅ **1.00x**) | `322.86 us` (✅ **1.55x faster**)  |
| **`4096-bit key encrypt - 10 requests`**  | `3.69 ms` (✅ **1.00x**)   | `5.16 ms` (❌ *1.40x slower*)      |
| **`4096-bit key encrypt - 100 requests`** | `22.93 ms` (✅ **1.00x**)  | `25.13 ms` (✅ **1.10x slower**)   |
| **`4096-bit key encrypt - 50 requests`**  | `16.34 ms` (✅ **1.00x**)  | `16.33 ms` (✅ **1.00x faster**)   |

### encrypt_aes-gcm-siv

|                     | `v5.17`                   | `v5.18`                           |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `133.79 us` (✅ **1.00x**) | `175.31 us` (❌ *1.31x slower*)    |
| **`decrypt - 256`** | `139.96 us` (✅ **1.00x**) | `162.28 us` (❌ *1.16x slower*)    |
| **`encrypt - 128`** | `209.23 us` (✅ **1.00x**) | `143.64 us` (✅ **1.46x faster**)  |
| **`encrypt - 256`** | `213.71 us` (✅ **1.00x**) | `241.00 us` (❌ *1.13x slower*)    |

### encrypt_aes-gcm

|                     | `v5.17`                   | `v5.18`                           |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `268.91 us` (✅ **1.00x**) | `188.35 us` (✅ **1.43x faster**)  |
| **`decrypt - 192`** | `199.82 us` (✅ **1.00x**) | `141.21 us` (✅ **1.41x faster**)  |
| **`decrypt - 256`** | `114.94 us` (✅ **1.00x**) | `150.72 us` (❌ *1.31x slower*)    |
| **`encrypt - 128`** | `207.46 us` (✅ **1.00x**) | `186.74 us` (✅ **1.11x faster**)  |
| **`encrypt - 192`** | `165.77 us` (✅ **1.00x**) | `149.21 us` (✅ **1.11x faster**)  |
| **`encrypt - 256`** | `179.20 us` (✅ **1.00x**) | `201.96 us` (❌ *1.13x slower*)    |

### encrypt_aes-xts

|                     | `v5.17`                   | `v5.18`                           |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `135.47 us` (✅ **1.00x**) | `317.08 us` (❌ *2.34x slower*)    |
| **`decrypt - 256`** | `173.25 us` (✅ **1.00x**) | `173.41 us` (✅ **1.00x slower**)  |
| **`encrypt - 128`** | `198.60 us` (✅ **1.00x**) | `157.61 us` (✅ **1.26x faster**)  |
| **`encrypt - 256`** | `224.76 us` (✅ **1.00x**) | `281.91 us` (❌ *1.25x slower*)    |

### encrypt_chacha20-poly1305

|                   | `v5.17`                   | `v5.18`                           |
|:------------------|:--------------------------|:--------------------------------- |
| **`decrypt_256`** | `251.71 us` (✅ **1.00x**) | `203.64 us` (✅ **1.24x faster**)  |
| **`encrypt_256`** | `240.11 us` (✅ **1.00x**) | `224.21 us` (✅ **1.07x faster**)  |

### encrypt_covercrypt

|               | `v5.17`                  | `v5.18`                          |
|:--------------|:-------------------------|:-------------------------------- |
| **`decrypt`** | `12.28 ms` (✅ **1.00x**) | `12.84 ms` (✅ **1.05x slower**)  |
| **`encrypt`** | `8.02 ms` (✅ **1.00x**)  | `7.69 ms` (✅ **1.04x faster**)   |

### encrypt_ecies

|                       | `v5.17`                   | `v5.18`                           |
|:----------------------|:--------------------------|:--------------------------------- |
| **`decrypt - P-256`** | `262.11 us` (✅ **1.00x**) | `297.52 us` (❌ *1.14x slower*)    |
| **`decrypt - P-384`** | `1.24 ms` (✅ **1.00x**)   | `1.77 ms` (❌ *1.42x slower*)      |
| **`decrypt - P-521`** | `2.60 ms` (✅ **1.00x**)   | `6.45 ms` (❌ *2.48x slower*)      |
| **`encrypt - P-256`** | `315.90 us` (✅ **1.00x**) | `376.09 us` (❌ *1.19x slower*)    |
| **`encrypt - P-384`** | `1.37 ms` (✅ **1.00x**)   | `2.37 ms` (❌ *1.73x slower*)      |
| **`encrypt - P-521`** | `3.69 ms` (✅ **1.00x**)   | `2.56 ms` (✅ **1.44x faster**)    |

### encrypt_rsa-aes-kwp

|                      | `v5.17`                   | `v5.18`                           |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `26.26 ms` (✅ **1.00x**)  | `26.50 ms` (✅ **1.01x slower**)   |
| **`decrypt - 3072`** | `73.66 ms` (✅ **1.00x**)  | `76.59 ms` (✅ **1.04x slower**)   |
| **`decrypt - 4096`** | `165.60 ms` (✅ **1.00x**) | `174.00 ms` (✅ **1.05x slower**)  |
| **`encrypt - 2048`** | `226.14 us` (✅ **1.00x**) | `272.43 us` (❌ *1.20x slower*)    |
| **`encrypt - 3072`** | `316.58 us` (✅ **1.00x**) | `271.17 us` (✅ **1.17x faster**)  |
| **`encrypt - 4096`** | `275.13 us` (✅ **1.00x**) | `386.12 us` (❌ *1.40x slower*)    |

### encrypt_rsa-oaep

|                      | `v5.17`                   | `v5.18`                           |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `24.40 ms` (✅ **1.00x**)  | `26.74 ms` (✅ **1.10x slower**)   |
| **`decrypt - 3072`** | `77.20 ms` (✅ **1.00x**)  | `79.61 ms` (✅ **1.03x slower**)   |
| **`decrypt - 4096`** | `180.09 ms` (✅ **1.00x**) | `175.64 ms` (✅ **1.03x faster**)  |
| **`encrypt - 2048`** | `231.78 us` (✅ **1.00x**) | `305.83 us` (❌ *1.32x slower*)    |
| **`encrypt - 3072`** | `243.81 us` (✅ **1.00x**) | `411.03 us` (❌ *1.69x slower*)    |
| **`encrypt - 4096`** | `377.77 us` (✅ **1.00x**) | `357.12 us` (✅ **1.06x faster**)  |

### encrypt_rsa-pkcs1v15

|                      | `v5.17`                   | `v5.18`                           |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `26.02 ms` (✅ **1.00x**)  | `29.69 ms` (❌ *1.14x slower*)     |
| **`decrypt - 3072`** | `83.95 ms` (✅ **1.00x**)  | `81.25 ms` (✅ **1.03x faster**)   |
| **`decrypt - 4096`** | `174.90 ms` (✅ **1.00x**) | `174.25 ms` (✅ **1.00x faster**)  |
| **`encrypt - 2048`** | `196.87 us` (✅ **1.00x**) | `262.46 us` (❌ *1.33x slower*)    |
| **`encrypt - 3072`** | `283.24 us` (✅ **1.00x**) | `347.02 us` (❌ *1.23x slower*)    |
| **`encrypt - 4096`** | `357.15 us` (✅ **1.00x**) | `395.54 us` (✅ **1.11x slower**)  |

### encrypt_salsa-sealed-box

|               | `v5.17`                   | `v5.18`                           |
|:--------------|:--------------------------|:--------------------------------- |
| **`decrypt`** | `228.72 us` (✅ **1.00x**) | `305.62 us` (❌ *1.34x slower*)    |
| **`encrypt`** | `277.72 us` (✅ **1.00x**) | `243.99 us` (✅ **1.14x faster**)  |

### kem_configurable

|                                       | `v5.17`                   | `v5.18`                           |
|:--------------------------------------|:--------------------------|:--------------------------------- |
| **`decapsulate - ML-KEM-512`**        | `285.73 us` (✅ **1.00x**) | `294.48 us` (✅ **1.03x slower**)  |
| **`decapsulate - ML-KEM-512_P-256`**  | `371.92 us` (✅ **1.00x**) | `515.57 us` (❌ *1.39x slower*)    |
| **`decapsulate - ML-KEM-512_X25519`** | `382.80 us` (✅ **1.00x**) | `409.50 us` (✅ **1.07x slower**)  |
| **`decapsulate - ML-KEM-768`**        | `534.24 us` (✅ **1.00x**) | `602.38 us` (❌ *1.13x slower*)    |
| **`decapsulate - ML-KEM-768_P-256`**  | `501.55 us` (✅ **1.00x**) | `817.64 us` (❌ *1.63x slower*)    |
| **`decapsulate - ML-KEM-768_X25519`** | `630.07 us` (✅ **1.00x**) | `449.60 us` (✅ **1.40x faster**)  |
| **`encapsulate - ML-KEM-512`**        | `499.49 us` (✅ **1.00x**) | `564.68 us` (❌ *1.13x slower*)    |
| **`encapsulate - ML-KEM-512_P-256`**  | `585.74 us` (✅ **1.00x**) | `622.33 us` (✅ **1.06x slower**)  |
| **`encapsulate - ML-KEM-512_X25519`** | `3.71 ms` (✅ **1.00x**)   | `4.10 ms` (✅ **1.11x slower**)    |
| **`encapsulate - ML-KEM-768`**        | `487.57 us` (✅ **1.00x**) | `550.71 us` (❌ *1.13x slower*)    |
| **`encapsulate - ML-KEM-768_P-256`**  | `724.07 us` (✅ **1.00x**) | `614.41 us` (✅ **1.18x faster**)  |
| **`encapsulate - ML-KEM-768_X25519`** | `4.01 ms` (✅ **1.00x**)   | `3.94 ms` (✅ **1.02x faster**)    |

### key-creation_covercrypt

|                      | `v5.17`                  | `v5.18`                          |
|:---------------------|:-------------------------|:-------------------------------- |
| **`master-keypair`** | `24.85 ms` (✅ **1.00x**) | `27.76 ms` (❌ *1.12x slower*)    |

### key-creation_ec

|                 | `v5.17`                 | `v5.18`                         |
|:----------------|:------------------------|:------------------------------- |
| **`ed25519`**   | `3.26 ms` (✅ **1.00x**) | `3.23 ms` (✅ **1.01x faster**)  |
| **`ed448`**     | `3.49 ms` (✅ **1.00x**) | `3.97 ms` (❌ *1.14x slower*)    |
| **`p256`**      | `2.84 ms` (✅ **1.00x**) | `2.55 ms` (✅ **1.12x faster**)  |
| **`p384`**      | `4.12 ms` (✅ **1.00x**) | `5.81 ms` (❌ *1.41x slower*)    |
| **`p521`**      | `6.07 ms` (✅ **1.00x**) | `6.01 ms` (✅ **1.01x faster**)  |
| **`secp256k1`** | `3.55 ms` (✅ **1.00x**) | `4.11 ms` (❌ *1.16x slower*)    |

### key-creation_kem

|                         | `v5.17`                 | `v5.18`                         |
|:------------------------|:------------------------|:------------------------------- |
| **`ML-KEM-512`**        | `2.93 ms` (✅ **1.00x**) | `3.45 ms` (❌ *1.18x slower*)    |
| **`ML-KEM-512_P-256`**  | `3.49 ms` (✅ **1.00x**) | `3.99 ms` (❌ *1.15x slower*)    |
| **`ML-KEM-512_X25519`** | `5.39 ms` (✅ **1.00x**) | `4.06 ms` (✅ **1.33x faster**)  |
| **`ML-KEM-768`**        | `3.36 ms` (✅ **1.00x**) | `2.55 ms` (✅ **1.32x faster**)  |
| **`ML-KEM-768_P-256`**  | `3.61 ms` (✅ **1.00x**) | `3.94 ms` (✅ **1.09x slower**)  |
| **`ML-KEM-768_X25519`** | `5.72 ms` (✅ **1.00x**) | `5.40 ms` (✅ **1.06x faster**)  |

### key-creation_rsa

|                | `v5.17`                   | `v5.18`                           |
|:---------------|:--------------------------|:--------------------------------- |
| **`rsa-2048`** | `30.65 ms` (✅ **1.00x**)  | `31.68 ms` (✅ **1.03x slower**)   |
| **`rsa-3072`** | `102.80 ms` (✅ **1.00x**) | `92.41 ms` (✅ **1.11x faster**)   |
| **`rsa-4096`** | `300.81 ms` (✅ **1.00x**) | `339.87 ms` (❌ *1.13x slower*)    |

### key-creation_symmetric

|                    | `v5.17`                 | `v5.18`                         |
|:-------------------|:------------------------|:------------------------------- |
| **`aes-128`**      | `2.32 ms` (✅ **1.00x**) | `2.62 ms` (❌ *1.13x slower*)    |
| **`aes-192`**      | `2.79 ms` (✅ **1.00x**) | `2.70 ms` (✅ **1.03x faster**)  |
| **`aes-256`**      | `2.48 ms` (✅ **1.00x**) | `2.58 ms` (✅ **1.04x slower**)  |
| **`chacha20-256`** | `2.70 ms` (✅ **1.00x**) | `2.78 ms` (✅ **1.03x slower**)  |

### sign-verify_ecdsa-p256

|              | `v5.17`                   | `v5.18`                           |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `657.77 us` (✅ **1.00x**) | `787.52 us` (❌ *1.20x slower*)    |
| **`verify`** | `299.79 us` (✅ **1.00x**) | `398.50 us` (❌ *1.33x slower*)    |

### sign-verify_ecdsa-p384

|              | `v5.17`                   | `v5.18`                           |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `1.23 ms` (✅ **1.00x**)   | `1.75 ms` (❌ *1.42x slower*)      |
| **`verify`** | `601.63 us` (✅ **1.00x**) | `685.30 us` (❌ *1.14x slower*)    |

### sign-verify_ecdsa-p521

|              | `v5.17`                 | `v5.18`                         |
|:-------------|:------------------------|:------------------------------- |
| **`sign`**   | `2.70 ms` (✅ **1.00x**) | `3.56 ms` (❌ *1.32x slower*)    |
| **`verify`** | `1.30 ms` (✅ **1.00x**) | `1.70 ms` (❌ *1.31x slower*)    |

### sign-verify_ecdsa-secp256k1

|              | `v5.17`                   | `v5.18`                           |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `517.63 us` (✅ **1.00x**) | `832.52 us` (❌ *1.61x slower*)    |
| **`verify`** | `402.12 us` (✅ **1.00x**) | `456.05 us` (❌ *1.13x slower*)    |

### sign-verify_eddsa-ed25519

|              | `v5.17`                   | `v5.18`                           |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `175.65 us` (✅ **1.00x**) | `260.80 us` (❌ *1.48x slower*)    |
| **`verify`** | `203.35 us` (✅ **1.00x**) | `382.92 us` (❌ *1.88x slower*)    |

### sign-verify_eddsa-ed448

|              | `v5.17`                   | `v5.18`                           |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `516.27 us` (✅ **1.00x**) | `604.83 us` (❌ *1.17x slower*)    |
| **`verify`** | `268.19 us` (✅ **1.00x**) | `390.41 us` (❌ *1.46x slower*)    |

### sign-verify_rsa-pss

|                     | `v5.17`                   | `v5.18`                           |
|:--------------------|:--------------------------|:--------------------------------- |
| **`sign - 2048`**   | `24.76 ms` (✅ **1.00x**)  | `27.17 ms` (✅ **1.10x slower**)   |
| **`sign - 3072`**   | `78.73 ms` (✅ **1.00x**)  | `79.69 ms` (✅ **1.01x slower**)   |
| **`sign - 4096`**   | `178.30 ms` (✅ **1.00x**) | `177.30 ms` (✅ **1.01x faster**)  |
| **`verify - 2048`** | `232.44 us` (✅ **1.00x**) | `203.01 us` (✅ **1.15x faster**)  |
| **`verify - 3072`** | `240.48 us` (✅ **1.00x**) | `370.23 us` (❌ *1.54x slower*)    |
| **`verify - 4096`** | `359.95 us` (✅ **1.00x**) | `357.50 us` (✅ **1.01x faster**)  |

### kem_pqc

|                                    | `v5.18`                    |
|:-----------------------------------|:-------------------------- |
| **`decapsulate - ML-KEM-1024`**    | `532.68 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-512`**     | `385.31 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768`**     | `699.08 us` (✅ **1.00x**)  |
| **`decapsulate - X25519MLKEM768`** | `624.76 us` (✅ **1.00x**)  |
| **`decapsulate - X448MLKEM1024`**  | `914.24 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-1024`**    | `560.70 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512`**     | `404.74 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-768`**     | `515.25 us` (✅ **1.00x**)  |
| **`encapsulate - X25519MLKEM768`** | `547.34 us` (✅ **1.00x**)  |
| **`encapsulate - X448MLKEM1024`**  | `740.34 us` (✅ **1.00x**)  |

### key-creation_pqc

|                          | `v5.18`                    |
|:-------------------------|:-------------------------- |
| **`ML-DSA-44`**          | `5.53 ms` (✅ **1.00x**)    |
| **`ML-DSA-65`**          | `4.63 ms` (✅ **1.00x**)    |
| **`ML-DSA-87`**          | `3.73 ms` (✅ **1.00x**)    |
| **`ML-KEM-1024`**        | `4.37 ms` (✅ **1.00x**)    |
| **`ML-KEM-512`**         | `4.25 ms` (✅ **1.00x**)    |
| **`ML-KEM-768`**         | `5.38 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHA2-128f`**  | `4.28 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHA2-128s`**  | `31.42 ms` (✅ **1.00x**)   |
| **`SLH-DSA-SHA2-192f`**  | `5.17 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHA2-192s`**  | `56.27 ms` (✅ **1.00x**)   |
| **`SLH-DSA-SHA2-256f`**  | `8.61 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHA2-256s`**  | `30.43 ms` (✅ **1.00x**)   |
| **`SLH-DSA-SHAKE-128f`** | `5.66 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHAKE-128s`** | `74.39 ms` (✅ **1.00x**)   |
| **`SLH-DSA-SHAKE-192f`** | `6.15 ms` (✅ **1.00x**)    |
| **`SLH-DSA-SHAKE-192s`** | `104.22 ms` (✅ **1.00x**)  |
| **`SLH-DSA-SHAKE-256f`** | `13.23 ms` (✅ **1.00x**)   |
| **`SLH-DSA-SHAKE-256s`** | `73.85 ms` (✅ **1.00x**)   |
| **`X25519MLKEM768`**     | `3.33 ms` (✅ **1.00x**)    |
| **`X448MLKEM1024`**      | `4.30 ms` (✅ **1.00x**)    |

### sign-verify_ml-dsa

|                   | `v5.18`                    |
|:------------------|:-------------------------- |
| **`sign - 44`**   | `1.47 ms` (✅ **1.00x**)    |
| **`sign - 65`**   | `1.55 ms` (✅ **1.00x**)    |
| **`sign - 87`**   | `2.48 ms` (✅ **1.00x**)    |
| **`verify - 44`** | `652.10 us` (✅ **1.00x**)  |
| **`verify - 65`** | `1.33 ms` (✅ **1.00x**)    |
| **`verify - 87`** | `790.54 us` (✅ **1.00x**)  |

### sign-verify_slh-dsa

|                           | `v5.18`                    |
|:--------------------------|:-------------------------- |
| **`sign - SHA2-128f`**    | `14.56 ms` (✅ **1.00x**)   |
| **`sign - SHA2-128s`**    | `206.06 ms` (✅ **1.00x**)  |
| **`sign - SHA2-192f`**    | `27.77 ms` (✅ **1.00x**)   |
| **`sign - SHA2-192s`**    | `413.66 ms` (✅ **1.00x**)  |
| **`sign - SHA2-256f`**    | `42.66 ms` (✅ **1.00x**)   |
| **`sign - SHA2-256s`**    | `403.45 ms` (✅ **1.00x**)  |
| **`sign - SHAKE-128f`**   | `28.88 ms` (✅ **1.00x**)   |
| **`sign - SHAKE-128s`**   | `517.29 ms` (✅ **1.00x**)  |
| **`sign - SHAKE-192f`**   | `47.97 ms` (✅ **1.00x**)   |
| **`sign - SHAKE-192s`**   | `914.51 ms` (✅ **1.00x**)  |
| **`sign - SHAKE-256f`**   | `90.70 ms` (✅ **1.00x**)   |
| **`sign - SHAKE-256s`**   | `793.36 ms` (✅ **1.00x**)  |
| **`verify - SHA2-128f`**  | `2.71 ms` (✅ **1.00x**)    |
| **`verify - SHA2-128s`**  | `1.13 ms` (✅ **1.00x**)    |
| **`verify - SHA2-192f`**  | `4.91 ms` (✅ **1.00x**)    |
| **`verify - SHA2-192s`**  | `2.05 ms` (✅ **1.00x**)    |
| **`verify - SHA2-256f`**  | `6.01 ms` (✅ **1.00x**)    |
| **`verify - SHA2-256s`**  | `3.60 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-128f`** | `4.18 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-128s`** | `1.90 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-192f`** | `7.80 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-192s`** | `3.32 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-256f`** | `7.54 ms` (✅ **1.00x**)    |
| **`verify - SHAKE-256s`** | `5.73 ms` (✅ **1.00x**)    |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)

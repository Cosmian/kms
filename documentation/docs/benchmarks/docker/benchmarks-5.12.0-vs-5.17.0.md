# Benchmark diff — KMS 5.12.0 vs 5.17.0

Baseline image: `ghcr.io/cosmian/kms:5.12.0`
Compare image:  `ghcr.io/cosmian/kms:5.17.0`

Source command:

```bash
cargo run -p ckms --release --features non-fips -- bench --mode all --format json --version-label v<VERSION>
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
| **`128-bit key decrypt - 1 request`**     | `117.77 us` (✅ **1.00x**) | `102.59 us` (✅ **1.15x faster**)  |
| **`128-bit key decrypt - 10 requests`**   | `327.04 us` (✅ **1.00x**) | `290.60 us` (✅ **1.13x faster**)  |
| **`128-bit key decrypt - 100 requests`**  | `1.72 ms` (✅ **1.00x**)   | `1.55 ms` (✅ **1.11x faster**)    |
| **`128-bit key decrypt - 1000 requests`** | `13.59 ms` (✅ **1.00x**)  | `14.29 ms` (✅ **1.05x slower**)   |
| **`128-bit key decrypt - 50 requests`**   | `877.57 us` (✅ **1.00x**) | `842.19 us` (✅ **1.04x faster**)  |
| **`128-bit key decrypt - 500 requests`**  | `6.75 ms` (✅ **1.00x**)   | `7.17 ms` (✅ **1.06x slower**)    |
| **`128-bit key encrypt - 1 request`**     | `157.03 us` (✅ **1.00x**) | `162.96 us` (✅ **1.04x slower**)  |
| **`128-bit key encrypt - 10 requests`**   | `346.37 us` (✅ **1.00x**) | `312.41 us` (✅ **1.11x faster**)  |
| **`128-bit key encrypt - 100 requests`**  | `2.11 ms` (✅ **1.00x**)   | `1.73 ms` (✅ **1.22x faster**)    |
| **`128-bit key encrypt - 1000 requests`** | `14.53 ms` (✅ **1.00x**)  | `15.35 ms` (✅ **1.06x slower**)   |
| **`128-bit key encrypt - 50 requests`**   | `850.72 us` (✅ **1.00x**) | `925.77 us` (✅ **1.09x slower**)  |
| **`128-bit key encrypt - 500 requests`**  | `8.99 ms` (✅ **1.00x**)   | `8.30 ms` (✅ **1.08x faster**)    |
| **`256-bit key decrypt - 1 request`**     | `183.48 us` (✅ **1.00x**) | `165.00 us` (✅ **1.11x faster**)  |
| **`256-bit key decrypt - 10 requests`**   | `291.95 us` (✅ **1.00x**) | `259.93 us` (✅ **1.12x faster**)  |
| **`256-bit key decrypt - 100 requests`**  | `1.52 ms` (✅ **1.00x**)   | `1.49 ms` (✅ **1.02x faster**)    |
| **`256-bit key decrypt - 1000 requests`** | `13.60 ms` (✅ **1.00x**)  | `13.48 ms` (✅ **1.01x faster**)   |
| **`256-bit key decrypt - 50 requests`**   | `1.07 ms` (✅ **1.00x**)   | `881.52 us` (✅ **1.21x faster**)  |
| **`256-bit key decrypt - 500 requests`**  | `6.87 ms` (✅ **1.00x**)   | `6.71 ms` (✅ **1.02x faster**)    |
| **`256-bit key encrypt - 1 request`**     | `159.01 us` (✅ **1.00x**) | `177.83 us` (❌ *1.12x slower*)    |
| **`256-bit key encrypt - 10 requests`**   | `269.49 us` (✅ **1.00x**) | `308.50 us` (❌ *1.14x slower*)    |
| **`256-bit key encrypt - 100 requests`**  | `1.92 ms` (✅ **1.00x**)   | `1.73 ms` (✅ **1.11x faster**)    |
| **`256-bit key encrypt - 1000 requests`** | `15.11 ms` (✅ **1.00x**)  | `16.02 ms` (✅ **1.06x slower**)   |
| **`256-bit key encrypt - 50 requests`**   | `881.41 us` (✅ **1.00x**) | `977.15 us` (✅ **1.11x slower**)  |
| **`256-bit key encrypt - 500 requests`**  | `7.21 ms` (✅ **1.00x**)   | `7.56 ms` (✅ **1.05x slower**)    |

### RSA AES KEY WRAP - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.56 ms` (✅ **1.00x**)  | `29.62 ms` (❌ *1.12x slower*)     |
| **`2048-bit key decrypt - 10 requests`**  | `244.12 ms` (✅ **1.00x**) | `236.38 ms` (✅ **1.03x faster**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.36 s` (✅ **1.00x**)    | `2.33 s` (✅ **1.01x faster**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.22 s` (✅ **1.00x**)    | `1.17 s` (✅ **1.04x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `225.52 us` (✅ **1.00x**) | `260.29 us` (❌ *1.15x slower*)    |
| **`2048-bit key encrypt - 10 requests`**  | `1.55 ms` (✅ **1.00x**)   | `1.73 ms` (❌ *1.12x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `11.81 ms` (✅ **1.00x**)  | `15.12 ms` (❌ *1.28x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `6.17 ms` (✅ **1.00x**)   | `8.60 ms` (❌ *1.39x slower*)      |
| **`3072-bit key decrypt - 1 request`**    | `72.52 ms` (✅ **1.00x**)  | `77.13 ms` (✅ **1.06x slower**)   |
| **`3072-bit key decrypt - 10 requests`**  | `720.80 ms` (✅ **1.00x**) | `723.03 ms` (✅ **1.00x slower**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.19 s` (✅ **1.00x**)    | `7.23 s` (✅ **1.01x slower**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.60 s` (✅ **1.00x**)    | `3.61 s` (✅ **1.00x slower**)     |
| **`3072-bit key encrypt - 1 request`**    | `278.06 us` (✅ **1.00x**) | `315.90 us` (❌ *1.14x slower*)    |
| **`3072-bit key encrypt - 10 requests`**  | `1.94 ms` (✅ **1.00x**)   | `2.17 ms` (❌ *1.12x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `15.09 ms` (✅ **1.00x**)  | `17.58 ms` (❌ *1.17x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `7.73 ms` (✅ **1.00x**)   | `11.76 ms` (❌ *1.52x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `162.92 ms` (✅ **1.00x**) | `178.54 ms` (✅ **1.10x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.65 s` (✅ **1.00x**)    | `1.66 s` (✅ **1.01x slower**)     |
| **`4096-bit key decrypt - 100 requests`** | `16.50 s` (✅ **1.00x**)   | `16.61 s` (✅ **1.01x slower**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.27 s` (✅ **1.00x**)    | `8.27 s` (✅ **1.00x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `337.79 us` (✅ **1.00x**) | `338.85 us` (✅ **1.00x slower**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.76 ms` (✅ **1.00x**)   | `2.70 ms` (✅ **1.02x faster**)    |
| **`4096-bit key encrypt - 100 requests`** | `18.63 ms` (✅ **1.00x**)  | `21.35 ms` (❌ *1.15x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `10.26 ms` (✅ **1.00x**)  | `13.82 ms` (❌ *1.35x slower*)     |

### RSA OAEP - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.90 ms` (✅ **1.00x**)  | `25.73 ms` (✅ **1.05x faster**)   |
| **`2048-bit key decrypt - 10 requests`**  | `247.97 ms` (✅ **1.00x**) | `235.79 ms` (✅ **1.05x faster**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.37 s` (✅ **1.00x**)    | `2.35 s` (✅ **1.01x faster**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.21 s` (✅ **1.00x**)    | `1.18 s` (✅ **1.03x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `260.57 us` (✅ **1.00x**) | `271.44 us` (✅ **1.04x slower**)  |
| **`2048-bit key encrypt - 10 requests`**  | `1.68 ms` (✅ **1.00x**)   | `1.84 ms` (✅ **1.09x slower**)    |
| **`2048-bit key encrypt - 100 requests`** | `11.82 ms` (✅ **1.00x**)  | `15.04 ms` (❌ *1.27x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `6.42 ms` (✅ **1.00x**)   | `8.54 ms` (❌ *1.33x slower*)      |
| **`3072-bit key decrypt - 1 request`**    | `73.29 ms` (✅ **1.00x**)  | `71.75 ms` (✅ **1.02x faster**)   |
| **`3072-bit key decrypt - 10 requests`**  | `726.11 ms` (✅ **1.00x**) | `724.14 ms` (✅ **1.00x faster**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.23 s` (✅ **1.00x**)    | `7.44 s` (✅ **1.03x slower**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.62 s` (✅ **1.00x**)    | `3.61 s` (✅ **1.00x faster**)     |
| **`3072-bit key encrypt - 1 request`**    | `296.00 us` (✅ **1.00x**) | `291.77 us` (✅ **1.01x faster**)  |
| **`3072-bit key encrypt - 10 requests`**  | `2.03 ms` (✅ **1.00x**)   | `2.33 ms` (❌ *1.15x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `15.25 ms` (✅ **1.00x**)  | `19.02 ms` (❌ *1.25x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `8.00 ms` (✅ **1.00x**)   | `10.83 ms` (❌ *1.35x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `164.32 ms` (✅ **1.00x**) | `171.21 ms` (✅ **1.04x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.65 s` (✅ **1.00x**)    | `1.65 s` (✅ **1.00x slower**)     |
| **`4096-bit key decrypt - 100 requests`** | `16.55 s` (✅ **1.00x**)   | `16.49 s` (✅ **1.00x faster**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.29 s` (✅ **1.00x**)    | `8.26 s` (✅ **1.00x faster**)     |
| **`4096-bit key encrypt - 1 request`**    | `330.56 us` (✅ **1.00x**) | `346.41 us` (✅ **1.05x slower**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.86 ms` (✅ **1.00x**)   | `3.21 ms` (❌ *1.12x slower*)      |
| **`4096-bit key encrypt - 100 requests`** | `18.80 ms` (✅ **1.00x**)  | `21.92 ms` (❌ *1.17x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `9.93 ms` (✅ **1.00x**)   | `15.65 ms` (❌ *1.58x slower*)     |

### RSA PKCSv1.5 - plaintext of 32 bytes

|                                           | `v5.12.0`                 | `v5.17.0`                         |
|:------------------------------------------|:--------------------------|:--------------------------------- |
| **`2048-bit key decrypt - 1 request`**    | `26.89 ms` (✅ **1.00x**)  | `25.18 ms` (✅ **1.07x faster**)   |
| **`2048-bit key decrypt - 10 requests`**  | `240.10 ms` (✅ **1.00x**) | `237.73 ms` (✅ **1.01x faster**)  |
| **`2048-bit key decrypt - 100 requests`** | `2.35 s` (✅ **1.00x**)    | `2.35 s` (✅ **1.00x slower**)     |
| **`2048-bit key decrypt - 50 requests`**  | `1.18 s` (✅ **1.00x**)    | `1.17 s` (✅ **1.01x faster**)     |
| **`2048-bit key encrypt - 1 request`**    | `235.54 us` (✅ **1.00x**) | `295.43 us` (❌ *1.25x slower*)    |
| **`2048-bit key encrypt - 10 requests`**  | `1.53 ms` (✅ **1.00x**)   | `1.71 ms` (❌ *1.12x slower*)      |
| **`2048-bit key encrypt - 100 requests`** | `11.62 ms` (✅ **1.00x**)  | `14.65 ms` (❌ *1.26x slower*)     |
| **`2048-bit key encrypt - 50 requests`**  | `6.08 ms` (✅ **1.00x**)   | `8.59 ms` (❌ *1.41x slower*)      |
| **`3072-bit key decrypt - 1 request`**    | `72.51 ms` (✅ **1.00x**)  | `75.57 ms` (✅ **1.04x slower**)   |
| **`3072-bit key decrypt - 10 requests`**  | `725.87 ms` (✅ **1.00x**) | `722.93 ms` (✅ **1.00x faster**)  |
| **`3072-bit key decrypt - 100 requests`** | `7.22 s` (✅ **1.00x**)    | `7.19 s` (✅ **1.00x faster**)     |
| **`3072-bit key decrypt - 50 requests`**  | `3.60 s` (✅ **1.00x**)    | `3.59 s` (✅ **1.00x faster**)     |
| **`3072-bit key encrypt - 1 request`**    | `304.72 us` (✅ **1.00x**) | `315.80 us` (✅ **1.04x slower**)  |
| **`3072-bit key encrypt - 10 requests`**  | `1.88 ms` (✅ **1.00x**)   | `2.14 ms` (❌ *1.14x slower*)      |
| **`3072-bit key encrypt - 100 requests`** | `14.85 ms` (✅ **1.00x**)  | `17.68 ms` (❌ *1.19x slower*)     |
| **`3072-bit key encrypt - 50 requests`**  | `7.60 ms` (✅ **1.00x**)   | `11.44 ms` (❌ *1.50x slower*)     |
| **`4096-bit key decrypt - 1 request`**    | `164.19 ms` (✅ **1.00x**) | `170.04 ms` (✅ **1.04x slower**)  |
| **`4096-bit key decrypt - 10 requests`**  | `1.65 s` (✅ **1.00x**)    | `1.65 s` (✅ **1.00x faster**)     |
| **`4096-bit key decrypt - 100 requests`** | `16.49 s` (✅ **1.00x**)   | `16.55 s` (✅ **1.00x slower**)    |
| **`4096-bit key decrypt - 50 requests`**  | `8.25 s` (✅ **1.00x**)    | `8.28 s` (✅ **1.00x slower**)     |
| **`4096-bit key encrypt - 1 request`**    | `333.19 us` (✅ **1.00x**) | `355.54 us` (✅ **1.07x slower**)  |
| **`4096-bit key encrypt - 10 requests`**  | `2.30 ms` (✅ **1.00x**)   | `2.67 ms` (❌ *1.16x slower*)      |
| **`4096-bit key encrypt - 100 requests`** | `18.86 ms` (✅ **1.00x**)  | `21.71 ms` (❌ *1.15x slower*)     |
| **`4096-bit key encrypt - 50 requests`**  | `9.30 ms` (✅ **1.00x**)   | `11.52 ms` (❌ *1.24x slower*)     |

### encrypt_aes-gcm-siv

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `138.13 us` (✅ **1.00x**) | `123.54 us` (✅ **1.12x faster**)  |
| **`decrypt - 256`** | `145.36 us` (✅ **1.00x**) | `157.70 us` (✅ **1.08x slower**)  |
| **`encrypt - 128`** | `158.52 us` (✅ **1.00x**) | `167.76 us` (✅ **1.06x slower**)  |
| **`encrypt - 256`** | `117.78 us` (✅ **1.00x**) | `164.02 us` (❌ *1.39x slower*)    |

### encrypt_aes-gcm

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `166.27 us` (✅ **1.00x**) | `148.94 us` (✅ **1.12x faster**)  |
| **`decrypt - 256`** | `140.17 us` (✅ **1.00x**) | `144.78 us` (✅ **1.03x slower**)  |
| **`encrypt - 128`** | `164.74 us` (✅ **1.00x**) | `184.74 us` (❌ *1.12x slower*)    |
| **`encrypt - 256`** | `174.34 us` (✅ **1.00x**) | `161.55 us` (✅ **1.08x faster**)  |
| **`decrypt - 192`** | `N/A`                     | `125.63 us` (✅ **1.00x**)         |
| **`encrypt - 192`** | `N/A`                     | `150.11 us` (✅ **1.00x**)         |

### encrypt_aes-xts

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 128`** | `167.89 us` (✅ **1.00x**) | `143.13 us` (✅ **1.17x faster**)  |
| **`decrypt - 256`** | `147.60 us` (✅ **1.00x**) | `154.94 us` (✅ **1.05x slower**)  |
| **`encrypt - 128`** | `152.85 us` (✅ **1.00x**) | `163.32 us` (✅ **1.07x slower**)  |
| **`encrypt - 256`** | `164.50 us` (✅ **1.00x**) | `161.06 us` (✅ **1.02x faster**)  |

### encrypt_chacha20-poly1305

|                   | `v5.12.0`                 | `v5.17.0`                         |
|:------------------|:--------------------------|:--------------------------------- |
| **`decrypt_256`** | `134.69 us` (✅ **1.00x**) | `134.33 us` (✅ **1.00x faster**)  |
| **`encrypt_256`** | `128.87 us` (✅ **1.00x**) | `149.74 us` (❌ *1.16x slower*)    |

### encrypt_covercrypt

|               | `v5.12.0`                 | `v5.17.0`                         |
|:--------------|:--------------------------|:--------------------------------- |
| **`decrypt`** | `433.71 us` (✅ **1.00x**) | `12.51 ms` (❌ *28.84x slower*)    |
| **`encrypt`** | `303.15 us` (✅ **1.00x**) | `5.52 ms` (❌ *18.21x slower*)     |

### encrypt_ecies

|                       | `v5.12.0`                 | `v5.17.0`                         |
|:----------------------|:--------------------------|:--------------------------------- |
| **`decrypt - P-256`** | `228.78 us` (✅ **1.00x**) | `231.80 us` (✅ **1.01x slower**)  |
| **`decrypt - P-384`** | `1.75 ms` (✅ **1.00x**)   | `1.26 ms` (✅ **1.38x faster**)    |
| **`decrypt - P-521`** | `3.85 ms` (✅ **1.00x**)   | `2.80 ms` (✅ **1.38x faster**)    |
| **`encrypt - P-256`** | `308.08 us` (✅ **1.00x**) | `266.49 us` (✅ **1.16x faster**)  |
| **`encrypt - P-384`** | `1.96 ms` (✅ **1.00x**)   | `1.26 ms` (✅ **1.56x faster**)    |
| **`encrypt - P-521`** | `4.59 ms` (✅ **1.00x**)   | `3.01 ms` (✅ **1.52x faster**)    |

### encrypt_rsa-aes-kwp

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `25.51 ms` (✅ **1.00x**)  | `24.80 ms` (✅ **1.03x faster**)   |
| **`decrypt - 3072`** | `77.18 ms` (✅ **1.00x**)  | `72.68 ms` (✅ **1.06x faster**)   |
| **`decrypt - 4096`** | `166.19 ms` (✅ **1.00x**) | `171.19 ms` (✅ **1.03x slower**)  |
| **`encrypt - 2048`** | `174.69 us` (✅ **1.00x**) | `207.15 us` (❌ *1.19x slower*)    |
| **`encrypt - 3072`** | `211.59 us` (✅ **1.00x**) | `251.04 us` (❌ *1.19x slower*)    |
| **`encrypt - 4096`** | `243.57 us` (✅ **1.00x**) | `267.89 us` (✅ **1.10x slower**)  |

### encrypt_rsa-oaep

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `25.17 ms` (✅ **1.00x**)  | `25.51 ms` (✅ **1.01x slower**)   |
| **`decrypt - 3072`** | `74.88 ms` (✅ **1.00x**)  | `74.01 ms` (✅ **1.01x faster**)   |
| **`decrypt - 4096`** | `173.86 ms` (✅ **1.00x**) | `165.83 ms` (✅ **1.05x faster**)  |
| **`encrypt - 2048`** | `168.65 us` (✅ **1.00x**) | `223.06 us` (❌ *1.32x slower*)    |
| **`encrypt - 3072`** | `220.99 us` (✅ **1.00x**) | `248.15 us` (❌ *1.12x slower*)    |
| **`encrypt - 4096`** | `260.85 us` (✅ **1.00x**) | `306.48 us` (❌ *1.17x slower*)    |

### encrypt_rsa-pkcs1v15

|                      | `v5.12.0`                 | `v5.17.0`                         |
|:---------------------|:--------------------------|:--------------------------------- |
| **`decrypt - 2048`** | `27.55 ms` (✅ **1.00x**)  | `24.27 ms` (✅ **1.14x faster**)   |
| **`decrypt - 3072`** | `73.06 ms` (✅ **1.00x**)  | `74.81 ms` (✅ **1.02x slower**)   |
| **`decrypt - 4096`** | `167.95 ms` (✅ **1.00x**) | `173.18 ms` (✅ **1.03x slower**)  |
| **`encrypt - 2048`** | `193.42 us` (✅ **1.00x**) | `204.73 us` (✅ **1.06x slower**)  |
| **`encrypt - 3072`** | `204.83 us` (✅ **1.00x**) | `248.86 us` (❌ *1.21x slower*)    |
| **`encrypt - 4096`** | `287.72 us` (✅ **1.00x**) | `288.90 us` (✅ **1.00x slower**)  |

### encrypt_salsa-sealed-box

|               | `v5.12.0`                 | `v5.17.0`                         |
|:--------------|:--------------------------|:--------------------------------- |
| **`decrypt`** | `237.93 us` (✅ **1.00x**) | `229.12 us` (✅ **1.04x faster**)  |
| **`encrypt`** | `193.87 us` (✅ **1.00x**) | `246.34 us` (❌ *1.27x slower*)    |

### key-creation_covercrypt

|                      | `v5.12.0`                | `v5.17.0`                        |
|:---------------------|:-------------------------|:-------------------------------- |
| **`master-keypair`** | `13.91 ms` (✅ **1.00x**) | `30.79 ms` (❌ *2.21x slower*)    |

### key-creation_ec

|                 | `v5.12.0`                | `v5.17.0`                        |
|:----------------|:-------------------------|:-------------------------------- |
| **`ed25519`**   | `3.61 ms` (✅ **1.00x**)  | `6.47 ms` (❌ *1.79x slower*)     |
| **`ed448`**     | `13.52 ms` (✅ **1.00x**) | `9.92 ms` (✅ **1.36x faster**)   |
| **`p256`**      | `12.49 ms` (✅ **1.00x**) | `9.64 ms` (✅ **1.30x faster**)   |
| **`p384`**      | `7.75 ms` (✅ **1.00x**)  | `12.33 ms` (❌ *1.59x slower*)    |
| **`p521`**      | `5.85 ms` (✅ **1.00x**)  | `14.36 ms` (❌ *2.45x slower*)    |
| **`secp256k1`** | `13.43 ms` (✅ **1.00x**) | `10.46 ms` (✅ **1.28x faster**)  |

### key-creation_rsa

|                | `v5.12.0`                 | `v5.17.0`                         |
|:---------------|:--------------------------|:--------------------------------- |
| **`rsa-2048`** | `45.06 ms` (✅ **1.00x**)  | `32.91 ms` (✅ **1.37x faster**)   |
| **`rsa-3072`** | `128.90 ms` (✅ **1.00x**) | `104.26 ms` (✅ **1.24x faster**)  |
| **`rsa-4096`** | `311.39 ms` (✅ **1.00x**) | `355.59 ms` (❌ *1.14x slower*)    |

### key-creation_symmetric

|                    | `v5.12.0`                | `v5.17.0`                        |
|:-------------------|:-------------------------|:-------------------------------- |
| **`aes-128`**      | `3.05 ms` (✅ **1.00x**)  | `2.42 ms` (✅ **1.26x faster**)   |
| **`aes-192`**      | `12.20 ms` (✅ **1.00x**) | `11.09 ms` (✅ **1.10x faster**)  |
| **`aes-256`**      | `12.08 ms` (✅ **1.00x**) | `11.34 ms` (✅ **1.07x faster**)  |
| **`chacha20-256`** | `11.77 ms` (✅ **1.00x**) | `8.78 ms` (✅ **1.34x faster**)   |

### sign-verify_ecdsa-p256

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `213.36 us` (✅ **1.00x**) | `551.98 us` (❌ *2.59x slower*)    |
| **`verify`** | `251.62 us` (✅ **1.00x**) | `222.51 us` (✅ **1.13x faster**)  |

### sign-verify_ecdsa-p384

|              | `v5.12.0`               | `v5.17.0`                         |
|:-------------|:------------------------|:--------------------------------- |
| **`sign`**   | `1.56 ms` (✅ **1.00x**) | `1.28 ms` (✅ **1.22x faster**)    |
| **`verify`** | `1.12 ms` (✅ **1.00x**) | `662.75 us` (✅ **1.69x faster**)  |

### sign-verify_ecdsa-p521

|              | `v5.12.0`               | `v5.17.0`                       |
|:-------------|:------------------------|:------------------------------- |
| **`sign`**   | `3.33 ms` (✅ **1.00x**) | `3.32 ms` (✅ **1.00x faster**)  |
| **`verify`** | `2.18 ms` (✅ **1.00x**) | `1.20 ms` (🚀 **1.81x faster**)  |

### sign-verify_ecdsa-secp256k1

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `730.43 us` (✅ **1.00x**) | `500.17 us` (✅ **1.46x faster**)  |
| **`verify`** | `573.13 us` (✅ **1.00x**) | `402.03 us` (✅ **1.43x faster**)  |

### sign-verify_eddsa-ed25519

|              | `v5.12.0`                 | `v5.17.0`                         |
|:-------------|:--------------------------|:--------------------------------- |
| **`sign`**   | `190.97 us` (✅ **1.00x**) | `185.64 us` (✅ **1.03x faster**)  |
| **`verify`** | `205.45 us` (✅ **1.00x**) | `183.37 us` (✅ **1.12x faster**)  |

### sign-verify_rsa-pss

|                     | `v5.12.0`                 | `v5.17.0`                         |
|:--------------------|:--------------------------|:--------------------------------- |
| **`sign - 2048`**   | `25.75 ms` (✅ **1.00x**)  | `25.36 ms` (✅ **1.02x faster**)   |
| **`sign - 3072`**   | `76.39 ms` (✅ **1.00x**)  | `72.14 ms` (✅ **1.06x faster**)   |
| **`sign - 4096`**   | `174.01 ms` (✅ **1.00x**) | `163.82 ms` (✅ **1.06x faster**)  |
| **`verify - 2048`** | `223.93 us` (✅ **1.00x**) | `159.96 us` (✅ **1.40x faster**)  |
| **`verify - 3072`** | `283.05 us` (✅ **1.00x**) | `220.05 us` (✅ **1.29x faster**)  |
| **`verify - 4096`** | `322.66 us` (✅ **1.00x**) | `269.58 us` (✅ **1.20x faster**)  |

### kem_configurable

|                                       | `v5.17.0`                  |
|:--------------------------------------|:-------------------------- |
| **`decapsulate - ML-KEM-512`**        | `370.14 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-512_P-256`**  | `312.37 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-512_X25519`** | `345.11 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768`**        | `337.05 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768_P-256`**  | `413.00 us` (✅ **1.00x**)  |
| **`decapsulate - ML-KEM-768_X25519`** | `372.03 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512`**        | `309.40 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512_P-256`**  | `488.09 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-512_X25519`** | `3.76 ms` (✅ **1.00x**)    |
| **`encapsulate - ML-KEM-768`**        | `433.29 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-768_P-256`**  | `557.89 us` (✅ **1.00x**)  |
| **`encapsulate - ML-KEM-768_X25519`** | `3.85 ms` (✅ **1.00x**)    |

### key-creation_kem

|                         | `v5.17.0`                 |
|:------------------------|:------------------------- |
| **`ML-KEM-512`**        | `10.52 ms` (✅ **1.00x**)  |
| **`ML-KEM-512_P-256`**  | `12.14 ms` (✅ **1.00x**)  |
| **`ML-KEM-512_X25519`** | `17.10 ms` (✅ **1.00x**)  |
| **`ML-KEM-768`**        | `10.09 ms` (✅ **1.00x**)  |
| **`ML-KEM-768_P-256`**  | `11.56 ms` (✅ **1.00x**)  |
| **`ML-KEM-768_X25519`** | `16.43 ms` (✅ **1.00x**)  |

### sign-verify_eddsa-ed448

|              | `v5.17.0`                  |
|:-------------|:-------------------------- |
| **`sign`**   | `413.33 us` (✅ **1.00x**)  |
| **`verify`** | `285.47 us` (✅ **1.00x**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)


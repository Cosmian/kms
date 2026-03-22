# Benchmarks

> Generated on 2026-03-22 02:24:21 UTC
>
> KMS server version: "5.17.0 (OpenSSL 3.6.0 1 Oct 2025-non-FIPS)"

## Machine Info

```
Architecture:                            x86_64
CPU op-mode(s):                          32-bit, 64-bit
Address sizes:                           46 bits physical, 48 bits virtual
Byte Order:                              Little Endian
CPU(s):                                  32
On-line CPU(s) list:                     0-31
Vendor ID:                               GenuineIntel
Model name:                              Intel(R) Core(TM) i9-14900T
CPU family:                              6
Model:                                   183
Thread(s) per core:                      2
Core(s) per socket:                      24
Socket(s):                               1
Stepping:                                1
CPU(s) scaling MHz:                      19%
CPU max MHz:                             5500,0000
CPU min MHz:                             800,0000
BogoMIPS:                                2227,20
Flags:                                   fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf tsc_known_freq pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid rdseed adx smap clflushopt clwb intel_pt sha_ni xsaveopt xsavec xgetbv1 xsaves split_lock_detect user_shstk avx_vnni dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp hwp_pkg_req hfi vnmi umip pku ospke waitpkg gfni vaes vpclmulqdq tme rdpid movdiri movdir64b fsrm md_clear serialize pconfig arch_lbr ibt flush_l1d arch_capabilities ibpb_exit_to_user
Virtualization:                          VT-x
L1d cache:                               896 KiB (24 instances)
L1i cache:                               1,3 MiB (24 instances)
L2 cache:                                32 MiB (12 instances)
L3 cache:                                36 MiB (1 instance)
NUMA node(s):                            1
NUMA node0 CPU(s):                       0-31
Vulnerability Gather data sampling:      Not affected
Vulnerability Indirect target selection: Not affected
Vulnerability Itlb multihit:             Not affected
Vulnerability L1tf:                      Not affected
Vulnerability Mds:                       Not affected
Vulnerability Meltdown:                  Not affected
Vulnerability Mmio stale data:           Not affected
Vulnerability Reg file data sampling:    Mitigation; Clear Register File
Vulnerability Retbleed:                  Not affected
Vulnerability Spec rstack overflow:      Not affected
Vulnerability Spec store bypass:         Mitigation; Speculative Store Bypass disabled via prctl
Vulnerability Spectre v1:                Mitigation; usercopy/swapgs barriers and __user pointer sanitization
Vulnerability Spectre v2:                Mitigation; Enhanced / Automatic IBRS; IBPB conditional; PBRSB-eIBRS SW sequence; BHI BHI_DIS_S
Vulnerability Srbds:                     Not affected
Vulnerability Tsa:                       Not affected
Vulnerability Tsx async abort:           Not affected
Vulnerability Vmscape:                   Mitigation; IBPB before exit to userspace
```

## Results

## Benchmark Results

### AES GCM - plaintext of 64 bytes

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `150.47 µs` | `169.32 µs` | `124.22 µs` | `169.23 µs` |
| **`10 requests`** | `286.80 µs` | `357.41 µs` | `303.87 µs` | `376.59 µs` |
| **`100 requests`** | `2.86 ms` | `48.51 ms` | `2.12 ms` | `49.14 ms` |
| **`1000 requests`** | `20.22 ms` | `23.34 ms` | `18.31 ms` | `24.05 ms` |
| **`50 requests`** | `1.13 ms` | `1.39 ms` | `1.06 ms` | `1.44 ms` |
| **`500 requests`** | `62.27 ms` | `8.40 ms` | `63.22 ms` | `7.73 ms` |

### RSA AES KEY WRAP - plaintext of 32 bytes

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `25.73 ms` | `300.91 µs` | `79.14 ms` | `373.39 µs` | `179.01 ms` | `365.00 µs` |
| **`10 requests`** | `258.94 ms` | `2.79 ms` | `785.78 ms` | `2.66 ms` | `1.79 s` | `3.13 ms` |
| **`100 requests`** | `2.57 s` | `18.51 ms` | `7.87 s` | `20.80 ms` | `17.96 s` | `38.15 ms` |
| **`50 requests`** | `1.30 s` | `70.30 ms` | `3.96 s` | `73.17 ms` | `9.01 s` | `78.99 ms` |

### RSA OAEP - plaintext of 32 bytes

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `26.71 ms` | `357.82 µs` | `79.60 ms` | `350.28 µs` | `182.52 ms` | `478.04 µs` |
| **`10 requests`** | `257.63 ms` | `1.87 ms` | `782.11 ms` | `2.73 ms` | `1.79 s` | `3.43 ms` |
| **`100 requests`** | `2.59 s` | `16.16 ms` | `7.87 s` | `21.51 ms` | `17.96 s` | `39.13 ms` |
| **`50 requests`** | `1.31 s` | `69.57 ms` | `3.97 s` | `72.25 ms` | `9.03 s` | `76.50 ms` |

### RSA PKCSv1.5 - plaintext of 32 bytes

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `29.50 ms` | `289.49 µs` | `81.08 ms` | `303.89 µs` | `184.45 ms` | `451.00 µs` |
| **`10 requests`** | `256.35 ms` | `2.47 ms` | `789.88 ms` | `2.82 ms` | `1.80 s` | `3.35 ms` |
| **`100 requests`** | `2.58 s` | `16.53 ms` | `7.89 s` | `24.91 ms` | `18.19 s` | `31.93 ms` |
| **`50 requests`** | `1.30 s` | `70.01 ms` | `3.96 s` | `73.24 ms` | `9.02 s` | `76.62 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `158.29 µs` | `194.87 µs` |
| **`192`** | `190.82 µs` | `183.81 µs` |
| **`256`** | `140.49 µs` | `194.22 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `148.16 µs` | `189.28 µs` |
| **`256`** | `138.91 µs` | `166.30 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `96.75 µs` | `164.66 µs` |
| **`256`** | `154.02 µs` | `203.78 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `183.87 µs` | `232.33 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `12.42 ms` | `5.86 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `263.54 µs` | `372.04 µs` |
| **`P-384`** | `1.70 ms` | `1.41 ms` |
| **`P-521`** | `3.29 ms` | `3.21 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `26.62 ms` | `237.18 µs` |
| **`3072`** | `79.27 ms` | `291.09 µs` |
| **`4096`** | `184.36 ms` | `372.88 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `26.84 ms` | `257.55 µs` |
| **`3072`** | `78.66 ms` | `330.04 µs` |
| **`4096`** | `183.07 ms` | `295.22 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.13 ms` | `246.18 µs` |
| **`3072`** | `79.91 ms` | `292.25 µs` |
| **`4096`** | `179.60 ms` | `351.66 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `248.32 µs` | `312.21 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `313.85 µs` | `400.16 µs` |
| **`ML-KEM-512/P-256`** | `264.94 µs` | `652.70 µs` |
| **`ML-KEM-512/X25519`** | `279.23 µs` | `3.97 ms` |
| **`ML-KEM-768`** | `292.90 µs` | `512.62 µs` |
| **`ML-KEM-768/P-256`** | `391.50 µs` | `686.10 µs` |
| **`ML-KEM-768/X25519`** | `383.05 µs` | `4.36 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `31.25 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `10.44 ms` | `12.10 ms` | `9.89 ms` | `13.61 ms` | `13.83 ms` | `10.78 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `8.47 ms` | `12.48 ms` | `8.49 ms` | `10.78 ms` | `10.55 ms` | `14.92 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `34.79 ms` | `127.66 ms` | `342.95 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.61 ms` | `11.10 ms` | `10.67 ms` | `7.01 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `646.55 µs` | `281.21 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.50 ms` | `720.81 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `2.94 ms` | `1.73 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `610.62 µs` | `458.98 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `255.16 µs` | `205.54 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `408.13 µs` | `308.29 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `27.26 ms` | `251.10 µs` |
| **`3072`** | `79.02 ms` | `313.72 µs` |
| **`4096`** | `180.19 ms` | `310.98 µs` |

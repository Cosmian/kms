# Benchmarks

> Generated on 2026-03-25 05:40:19 UTC
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
CPU(s) scaling MHz:                      20%
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

### batch/aes-gcm

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `143.97 µs` | `151.78 µs` | `108.49 µs` | `236.68 µs` |
| **`10 requests`** | `206.00 µs` | `393.19 µs` | `471.80 µs` | `387.14 µs` |
| **`50 requests`** | `843.74 µs` | `835.15 µs` | `1.20 ms` | `732.20 µs` |
| **`100 requests`** | `1.45 ms` | `47.85 ms` | `1.41 ms` | `48.49 ms` |
| **`500 requests`** | `65.30 ms` | `7.90 ms` | `63.11 ms` | `8.38 ms` |
| **`1000 requests`** | `20.88 ms` | `18.18 ms` | `14.85 ms` | `22.59 ms` |

### batch/rsa-aes-kwp

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `25.69 ms` | `210.57 µs` | `74.43 ms` | `260.46 µs` | `166.31 ms` | `389.34 µs` |
| **`10 requests`** | `243.20 ms` | `2.15 ms` | `760.88 ms` | `2.27 ms` | `1.68 s` | `3.78 ms` |
| **`50 requests`** | `1.28 s` | `68.64 ms` | `3.77 s` | `73.99 ms` | `8.61 s` | `81.74 ms` |
| **`100 requests`** | `2.47 s` | `17.68 ms` | `7.51 s` | `22.05 ms` | `17.10 s` | `27.98 ms` |

### batch/rsa-oaep

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `28.19 ms` | `282.88 µs` | `74.13 ms` | `372.08 µs` | `181.00 ms` | `403.51 µs` |
| **`10 requests`** | `251.05 ms` | `1.74 ms` | `745.54 ms` | `2.36 ms` | `1.75 s` | `3.98 ms` |
| **`50 requests`** | `1.23 s` | `71.60 ms` | `3.80 s` | `70.20 ms` | `8.67 s` | `77.78 ms` |
| **`100 requests`** | `2.49 s` | `12.78 ms` | `7.72 s` | `18.68 ms` | `17.25 s` | `33.98 ms` |

### batch/rsa-pkcs1v15

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `23.94 ms` | `290.50 µs` | `79.74 ms` | `372.99 µs` | `168.60 ms` | `337.05 µs` |
| **`10 requests`** | `247.09 ms` | `3.14 ms` | `731.67 ms` | `1.84 ms` | `1.76 s` | `2.55 ms` |
| **`50 requests`** | `1.23 s` | `74.71 ms` | `3.81 s` | `73.37 ms` | `8.51 s` | `78.65 ms` |
| **`100 requests`** | `2.44 s` | `14.97 ms` | `7.46 s` | `17.87 ms` | `17.06 s` | `24.75 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `276.58 µs` | `176.77 µs` |
| **`192`** | `157.69 µs` | `181.21 µs` |
| **`256`** | `141.43 µs` | `184.87 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `128.15 µs` | `271.99 µs` |
| **`256`** | `82.68 µs` | `190.86 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `137.13 µs` | `124.04 µs` |
| **`256`** | `155.57 µs` | `456.42 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `134.67 µs` | `188.13 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `12.43 ms` | `6.22 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `174.72 µs` | `568.71 µs` |
| **`P-384`** | `1.26 ms` | `1.66 ms` |
| **`P-521`** | `2.28 ms` | `2.36 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `23.53 ms` | `198.50 µs` |
| **`3072`** | `72.21 ms` | `198.93 µs` |
| **`4096`** | `167.72 ms` | `370.66 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `23.90 ms` | `330.58 µs` |
| **`3072`** | `77.18 ms` | `204.67 µs` |
| **`4096`** | `177.63 ms` | `332.06 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.51 ms` | `235.78 µs` |
| **`3072`** | `73.21 ms` | `280.02 µs` |
| **`4096`** | `176.65 ms` | `334.39 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `336.13 µs` | `177.76 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `271.02 µs` | `343.14 µs` |
| **`ML-KEM-512/P-256`** | `197.68 µs` | `608.94 µs` |
| **`ML-KEM-512/X25519`** | `265.81 µs` | `3.03 ms` |
| **`ML-KEM-768`** | `265.78 µs` | `461.26 µs` |
| **`ML-KEM-768/P-256`** | `417.15 µs` | `489.57 µs` |
| **`ML-KEM-768/X25519`** | `834.20 µs` | `3.78 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `23.96 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.31 ms` | `3.87 ms` | `2.39 ms` | `4.84 ms` | `5.84 ms` | `4.19 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `3.49 ms` | `2.88 ms` | `4.52 ms` | `3.50 ms` | `3.52 ms` | `3.56 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `31.71 ms` | `131.86 ms` | `206.22 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `2.80 ms` | `2.81 ms` | `2.73 ms` | `2.62 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `473.13 µs` | `216.50 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.42 ms` | `885.36 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `3.65 ms` | `1.77 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `700.76 µs` | `351.49 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `178.29 µs` | `233.12 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `398.40 µs` | `233.27 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `24.53 ms` | `290.78 µs` |
| **`3072`** | `79.01 ms` | `258.87 µs` |
| **`4096`** | `179.21 ms` | `339.39 µs` |

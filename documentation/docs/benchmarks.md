# Benchmarks

> Generated on 2026-03-23 18:57:34 UTC
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

### AES GCM - plaintext of 64 bytes

AES-GCM batch — encrypt/decrypt N items in a single BulkData call.

| | `128-bit key decrypt` | `128-bit key encrypt` | `256-bit key decrypt` | `256-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `85.24 µs` | `257.29 µs` | `243.89 µs` | `357.29 µs` |
| **`10 requests`** | `267.28 µs` | `414.48 µs` | `406.68 µs` | `402.65 µs` |
| **`50 requests`** | `1.07 ms` | `1.30 ms` | `2.01 ms` | `1.16 ms` |
| **`100 requests`** | `1.82 ms` | `47.04 ms` | `1.39 ms` | `48.90 ms` |
| **`500 requests`** | `66.19 ms` | `9.11 ms` | `65.18 ms` | `8.48 ms` |
| **`1000 requests`** | `16.65 ms` | `22.74 ms` | `20.21 ms` | `22.98 ms` |

### RSA AES KEY WRAP - plaintext of 32 bytes

RSA AES Key Wrap batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `24.57 ms` | `265.83 µs` | `76.93 ms` | `333.53 µs` | `168.57 ms` | `677.65 µs` |
| **`10 requests`** | `244.06 ms` | `1.99 ms` | `764.71 ms` | `2.45 ms` | `1.81 s` | `3.01 ms` |
| **`50 requests`** | `1.28 s` | `73.10 ms` | `3.93 s` | `80.55 ms` | `8.82 s` | `80.10 ms` |
| **`100 requests`** | `2.56 s` | `13.59 ms` | `7.69 s` | `24.16 ms` | `17.63 s` | `27.76 ms` |

### RSA OAEP - plaintext of 32 bytes

RSA-OAEP batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `32.88 ms` | `400.07 µs` | `72.26 ms` | `365.45 µs` | `174.50 ms` | `480.87 µs` |
| **`10 requests`** | `262.89 ms` | `2.32 ms` | `742.85 ms` | `3.47 ms` | `1.74 s` | `2.16 ms` |
| **`50 requests`** | `1.34 s` | `73.99 ms` | `3.89 s` | `76.85 ms` | `8.84 s` | `82.41 ms` |
| **`100 requests`** | `2.53 s` | `20.20 ms` | `7.73 s` | `22.54 ms` | `17.63 s` | `30.88 ms` |

### RSA PKCSv1.5 - plaintext of 32 bytes

RSA PKCS#1 v1.5 batch — encrypt/decrypt N items in a single KMIP message.

| | `2048-bit key decrypt` | `2048-bit key encrypt` | `3072-bit key decrypt` | `3072-bit key encrypt` | `4096-bit key decrypt` | `4096-bit key encrypt` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`1 request`** | `28.99 ms` | `509.96 µs` | `76.01 ms` | `476.44 µs` | `167.64 ms` | `404.74 µs` |
| **`10 requests`** | `236.34 ms` | `3.43 ms` | `744.50 ms` | `4.87 ms` | `1.76 s` | `2.13 ms` |
| **`50 requests`** | `1.28 s` | `76.41 ms` | `3.91 s` | `83.48 ms` | `8.86 s` | `80.82 ms` |
| **`100 requests`** | `2.55 s` | `15.31 ms` | `7.67 s` | `22.21 ms` | `17.66 s` | `36.46 ms` |

### encrypt/aes-gcm

AES-GCM encrypt and decrypt (128/192/256-bit keys, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `316.46 µs` | `448.98 µs` |
| **`192`** | `357.50 µs` | `179.18 µs` |
| **`256`** | `104.18 µs` | `239.36 µs` |

### encrypt/aes-gcm-siv

AES-GCM-SIV encrypt and decrypt (128/256-bit keys, 64-byte plaintext). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `260.31 µs` | `281.04 µs` |
| **`256`** | `469.66 µs` | `168.06 µs` |

### encrypt/aes-xts

AES-XTS encrypt and decrypt (128/256-bit AES, 64-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`128`** | `215.99 µs` | `413.67 µs` |
| **`256`** | `89.34 µs` | `504.55 µs` |

### encrypt/chacha20-poly1305

ChaCha20-Poly1305 encrypt and decrypt (256-bit key, 64-byte plaintext). Non-FIPS.

| | `decrypt/256` | `encrypt/256` |
| :--- | :--- | :--- |
| | `258.43 µs` | `233.36 µs` |

### encrypt/covercrypt

Covercrypt attribute-based encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `12.59 ms` | `5.62 ms` |

### encrypt/ecies

ECIES encrypt and decrypt on NIST curves (P-256/P-384/P-521). Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`P-256`** | `258.30 µs` | `299.97 µs` |
| **`P-384`** | `1.49 ms` | `1.29 ms` |
| **`P-521`** | `3.27 ms` | `3.20 ms` |

### encrypt/rsa-aes-kwp

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.55 ms` | `259.01 µs` |
| **`3072`** | `72.11 ms` | `426.76 µs` |
| **`4096`** | `163.13 ms` | `727.94 µs` |

### encrypt/rsa-oaep

RSA-OAEP encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `27.45 ms` | `309.05 µs` |
| **`3072`** | `77.45 ms` | `549.79 µs` |
| **`4096`** | `171.33 ms` | `339.46 µs` |

### encrypt/rsa-pkcs1v15

RSA PKCS#1 v1.5 encrypt and decrypt (2048/3072/4096-bit keys, 32-byte plaintext).

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| **`2048`** | `24.57 ms` | `322.13 µs` |
| **`3072`** | `77.15 ms` | `233.58 µs` |
| **`4096`** | `174.30 ms` | `337.52 µs` |

### encrypt/salsa-sealed-box

Salsa Sealed Box (X25519) encrypt and decrypt. Non-FIPS.

| | `decrypt` | `encrypt` |
| :--- | :--- | :--- |
| | `444.47 µs` | `466.29 µs` |

### kem/configurable

Configurable KEM encapsulate and decapsulate (ML-KEM, hybrid variants). Non-FIPS.

| | `decapsulate` | `encapsulate` |
| :--- | :--- | :--- |
| **`ML-KEM-512`** | `516.00 µs` | `452.63 µs` |
| **`ML-KEM-512/P-256`** | `282.01 µs` | `763.11 µs` |
| **`ML-KEM-512/X25519`** | `773.10 µs` | `3.96 ms` |
| **`ML-KEM-768`** | `611.97 µs` | `455.69 µs` |
| **`ML-KEM-768/P-256`** | `419.89 µs` | `510.23 µs` |
| **`ML-KEM-768/X25519`** | `460.42 µs` | `3.76 ms` |

### key-creation/covercrypt

Covercrypt master key pair generation. Non-FIPS.

| | `master-keypair` |
| :--- | :--- |
| | `33.39 ms` |

### key-creation/ec

Elliptic curve key pair generation (NIST and non-FIPS curves).

| | `ed25519` | `ed448` | `p256` | `p384` | `p521` | `secp256k1` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `11.55 ms` | `12.68 ms` | `12.15 ms` | `14.18 ms` | `13.86 ms` | `12.65 ms` |

### key-creation/kem

Configurable KEM key pair generation (ML-KEM, hybrid variants). Non-FIPS.

| | `ML-KEM-512` | `ML-KEM-512/P-256` | `ML-KEM-512/X25519` | `ML-KEM-768` | `ML-KEM-768/P-256` | `ML-KEM-768/X25519` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| | `9.38 ms` | `10.82 ms` | `16.48 ms` | `10.78 ms` | `10.10 ms` | `15.66 ms` |

### key-creation/rsa

RSA key pair generation (2048/3072/4096-bit).

| | `rsa-2048` | `rsa-3072` | `rsa-4096` |
| :--- | :--- | :--- | :--- |
| | `37.96 ms` | `130.34 ms` | `217.64 ms` |

### key-creation/symmetric

AES (and ChaCha20 in non-FIPS) symmetric key creation.

| | `aes-128` | `aes-192` | `aes-256` | `chacha20-256` |
| :--- | :--- | :--- | :--- | :--- |
| | `11.55 ms` | `11.42 ms` | `11.43 ms` | `11.01 ms` |

### sign-verify/ecdsa-p256

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.16 ms` | `344.64 µs` |

### sign-verify/ecdsa-p384

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `1.86 ms` | `780.59 µs` |

### sign-verify/ecdsa-p521

ECDSA sign and verify on NIST curves.

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `3.35 ms` | `1.58 ms` |

### sign-verify/ecdsa-secp256k1

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `652.89 µs` | `475.25 µs` |

### sign-verify/eddsa-ed25519

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `474.66 µs` | `258.25 µs` |

### sign-verify/eddsa-ed448

Non-FIPS EC signature operations (secp256k1, Ed25519, Ed448).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| | `497.99 µs` | `506.43 µs` |

### sign-verify/rsa-pss

RSA-PSS sign and verify (SHA-256, 2048/3072/4096-bit).

| | `sign` | `verify` |
| :--- | :--- | :--- |
| **`2048`** | `23.29 ms` | `293.69 µs` |
| **`3072`** | `70.68 ms` | `245.01 µs` |
| **`4096`** | `161.95 ms` | `265.60 µs` |

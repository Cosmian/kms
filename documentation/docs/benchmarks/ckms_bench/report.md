# KMS Performance Comparison

**Versions**: `v5.24.0`
**Generated**: 2026-07-01

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-07-01 12:51:55 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 848 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.8.0-124-generic |

### Load test parameters

| Parameter | Value |
|---|---|
| Mode | all |
| Protocols | all |
| Measurement window | 20 s per concurrency level |
| Concurrency levels | 1,2,4,8,16,32 |
| Warm-up | 5 s |
| Cooldown between levels | 2 s |

### CPU detail (`lscpu`)

```text
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
CPU(s) scaling MHz:                      23%
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

---

## Protocols

The KMS server was exercised over three distinct wire protocols.
Each benchmark column is labelled with the protocol name it used.

| Protocol | Transport | Encoding | Endpoint | Description |
|---|---|---|---|---|
| **ttlv-json** | HTTP/1.1 | KMIP 2.1 JSON-TTLV | `POST /kmip/2_1` | Primary interoperability protocol — any KMIP 2.1 compliant client can use it |
| **ttlv-bytes** | HTTP/1.1 | KMIP 2.1 binary TTLV | `POST /kmip` | Binary wire format; eliminates JSON parsing overhead — typically 10–30 % faster |
| **jose** | HTTP/1.1 | JWE / JWS (JOSE) | `POST /v1/crypto/` | REST API for OAuth2/OIDC workloads that prefer JWA algorithm identifiers over KMIP |

**KMIP TTLV** (Tag-Type-Length-Value) is the native encoding of the KMIP 2.1 standard (OASIS KMIP Spec v2.1, §9.1). The **JSON** variant wraps every field in a `{"tag": …, "type": …, "value": …}` JSON object and base64-encodes binary values. The **binary** variant uses a compact 8-byte fixed header (3-byte tag, 1-byte type, 4-byte length) per value, removing JSON tokenisation, base64, and UTF-8 overhead entirely.

**JOSE** (JSON Object Signing and Encryption, RFC 7516 / RFC 7515) exposes KMS key material through `/v1/crypto/` REST endpoints. It is used by cloud integrations (Google CSE, Microsoft DKE, Azure EKM) and any workload that speaks JWA algorithm identifiers (A256GCM, RS256, ES384 …) rather than KMIP semantics.

---

## Benchmark Methodology

### Plaintext / payload sizes

All encrypt/decrypt benchmarks use a **fixed-size random payload**. Sizes represent a realistic key-wrapping or small-message encryption workload without introducing significant data-transfer overhead on a loopback connection.

| Algorithm / category | Plaintext size | Notes |
|---|---|---|
| AES-GCM (128 / 192 / 256-bit key) | 64 bytes | FIPS 140-3 |
| AES-GCM-SIV (128 / 256-bit key) | 64 bytes | Non-FIPS |
| AES-XTS (128 / 256-bit AES = 256 / 512-bit key) | 64 bytes | FIPS 140-3; requires 16-byte IV |
| ChaCha20-Poly1305 (256-bit key) | 64 bytes | Non-FIPS |
| ECIES — P-256 / P-384 / P-521 | 64 bytes | Non-FIPS; EC public-key encryption |
| Salsa Sealed Box (X25519) | 64 bytes | Non-FIPS |
| Covercrypt (attribute-based encryption) | 64 bytes | Non-FIPS |
| JOSE JWE — `dir` + AES-GCM (A128GCM / A192GCM / A256GCM) | 64 bytes | Symmetric (direct key agreement) |
| JOSE JWE — RSA-OAEP + AES-GCM (2048 / 4096-bit) | 64 bytes | Asymmetric (RSA-OAEP CEK wrapping) |
| RSA-OAEP (2048 / 3072 / 4096-bit) | 32 bytes | Limited by RSA block size |
| RSA-PKCS#1 v1.5 (2048 / 3072 / 4096-bit) | 32 bytes | Non-FIPS |
| RSA-AES Key Wrap — KWP (2048 / 3072 / 4096-bit) | 32 bytes | FIPS 140-3 |
| Sign / Verify — all algorithms | 32 bytes | Message is hashed internally |
| JOSE JWS / MAC | 32 bytes | |

### Load test (`ckms bench --load`)

The load test sweeps a configurable list of concurrency levels. At each level *N* concurrent async tasks send pre-serialised requests in tight loops for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase** (default: 5 s) that is excluded from measurements. Pre-serialisation happens once at setup time and the same bytes are reused on every iteration, isolating server-side KMS latency from client-side encoding overhead.
Recorded metrics per *(protocol, operation, concurrency)* triple:

- **Throughput** — requests per second (req/s)
- **p50 / p95 / p99** — round-trip latency percentiles (ms)

### Criterion micro-benchmarks (`ckms bench`)

Criterion (Rust, v0.5) measures the **round-trip latency of a single request** from the ckms client library through the KMS server and back over a loopback TCP connection. The server is started once and kept alive across all benchmarks in the suite.
The reported value is the **mean ± 95 % confidence interval** over a configurable number of samples (preset `quick`: 3 s warm-up + 5 s measurement per benchmark).

> **Infrastructure note:** Both test types use a **local SQLite** backend (temporary, discarded after the run). This isolates pure cryptographic and KMIP serialisation overhead from database I/O. Throughput figures will differ on a production deployment backed by PostgreSQL or Redis-Findex.

---

## Load Tests

### encrypt/aes-gcm

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 8,890 | 14,069 | 29,068 |
| 2 | 15,382 | 24,554 | 51,413 |
| 4 | 25,260 | 38,138 | 79,760 |
| 8 | 32,679 | 51,267 | 100,883 |
| 16 | 45,303 | 68,091 | 125,458 |
| 32 | 50,485 | 72,115 | 193,472 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign/es256

| Concurrency | jose (req/s) |
|---|---|
| 1 | 2,481 |
| 2 | 4,492 |
| 4 | 7,246 |
| 8 | 10,941 |
| 16 | 15,420 |
| 32 | 21,602 |

![Throughput — sign/es256](load/sign_es256.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,469 | 2,418 |
| 2 | 4,408 | 4,305 |
| 4 | 6,846 | 6,883 |
| 8 | 10,530 | 10,459 |
| 16 | 15,062 | 14,944 |
| 32 | 20,732 | 20,595 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 5,551 |
| 2 | 3,716 |
| 4 | 8,176 |
| 8 | 5,069 |
| 16 | 5,912 |
| 32 | 5,511 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 995 |
| 2 | 1,910 |
| 4 | 3,091 |
| 8 | 4,481 |
| 16 | 5,917 |
| 32 | 6,227 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 47.3 µs | 75.8 µs | — |
| aes-gcm-siv/decrypt/256 | 45.9 µs | 96.3 µs | — |
| aes-gcm-siv/encrypt/128 | 48.7 µs | 110.4 µs | — |
| aes-gcm-siv/encrypt/256 | 73.2 µs | 100.9 µs | — |
| aes-gcm/decrypt/128 | 46.8 µs | 58.1 µs | 56.9 µs |
| aes-gcm/decrypt/192 | 58.8 µs | 50.5 µs | 37.8 µs |
| aes-gcm/decrypt/256 | 56.4 µs | 64.7 µs | 32.9 µs |
| aes-gcm/encrypt/128 | 55.0 µs | 108.0 µs | 70.4 µs |
| aes-gcm/encrypt/192 | 67.3 µs | 54.1 µs | 39.2 µs |
| aes-gcm/encrypt/256 | 72.1 µs | 90.4 µs | 42.9 µs |
| aes-xts/decrypt/128 | 63.6 µs | 82.7 µs | — |
| aes-xts/decrypt/256 | 48.1 µs | 75.5 µs | — |
| aes-xts/encrypt/128 | 61.5 µs | 83.1 µs | — |
| aes-xts/encrypt/256 | 56.4 µs | 116.1 µs | — |
| chacha20-poly1305/decrypt/256 | 50.5 µs | 86.9 µs | — |
| chacha20-poly1305/encrypt/256 | 56.5 µs | 72.5 µs | — |
| salsa-sealed-box/decrypt | 147.7 µs | 139.2 µs | — |
| salsa-sealed-box/encrypt | 115.7 µs | 123.5 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 13.03 ms | 12.61 ms | — |
| covercrypt/encrypt | 5.24 ms | 5.10 ms | — |
| ecies/decrypt/P-256 | 120.0 µs | 148.9 µs | — |
| ecies/decrypt/P-384 | 1.21 ms | 1.11 ms | — |
| ecies/decrypt/P-521 | 2.17 ms | 3.97 ms | — |
| ecies/encrypt/P-256 | 143.4 µs | 199.7 µs | — |
| ecies/encrypt/P-384 | 1.07 ms | 1.13 ms | — |
| ecies/encrypt/P-521 | 2.48 ms | 2.61 ms | — |
| rsa-aes-kwp/decrypt/2048 | 25.59 ms | 25.40 ms | — |
| rsa-aes-kwp/decrypt/3072 | 84.37 ms | 74.88 ms | — |
| rsa-aes-kwp/decrypt/4096 | 182.38 ms | 169.19 ms | — |
| rsa-aes-kwp/encrypt/2048 | 85.9 µs | 132.8 µs | — |
| rsa-aes-kwp/encrypt/3072 | 109.1 µs | 110.8 µs | — |
| rsa-aes-kwp/encrypt/4096 | 119.0 µs | 124.5 µs | — |
| rsa-oaep/decrypt/2048 | 26.34 ms | 24.74 ms | 24.65 ms |
| rsa-oaep/decrypt/3072 | 84.14 ms | 75.15 ms | — |
| rsa-oaep/decrypt/4096 | 173.25 ms | 186.80 ms | 169.89 ms |
| rsa-oaep/encrypt/2048 | 86.0 µs | 138.7 µs | 60.6 µs |
| rsa-oaep/encrypt/3072 | 90.0 µs | 101.2 µs | — |
| rsa-oaep/encrypt/4096 | 131.5 µs | 129.6 µs | 115.0 µs |
| rsa-pkcs1v15/decrypt/2048 | 24.80 ms | 24.61 ms | — |
| rsa-pkcs1v15/decrypt/3072 | 78.38 ms | 74.63 ms | — |
| rsa-pkcs1v15/decrypt/4096 | 172.64 ms | 170.00 ms | — |
| rsa-pkcs1v15/encrypt/2048 | 83.6 µs | 116.5 µs | — |
| rsa-pkcs1v15/encrypt/3072 | 122.8 µs | 163.4 µs | — |
| rsa-pkcs1v15/encrypt/4096 | 138.5 µs | 111.4 µs | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json |
|---|---|
| configurable/decapsulate/ML-KEM-512 | 94.9 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 94.7 µs |
| configurable/decapsulate/ML-KEM-512/X25519 | 98.2 µs |
| configurable/decapsulate/ML-KEM-768 | 123.5 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 116.3 µs |
| configurable/decapsulate/ML-KEM-768/X25519 | 119.3 µs |
| configurable/encapsulate/ML-KEM-512 | 151.4 µs |
| configurable/encapsulate/ML-KEM-512/P-256 | 335.3 µs |
| configurable/encapsulate/ML-KEM-512/X25519 | 3.79 ms |
| configurable/encapsulate/ML-KEM-768 | 197.7 µs |
| configurable/encapsulate/ML-KEM-768/P-256 | 339.5 µs |
| configurable/encapsulate/ML-KEM-768/X25519 | 3.69 ms |
| pqc/decapsulate/ML-KEM-1024 | 146.2 µs |
| pqc/decapsulate/ML-KEM-512 | 102.4 µs |
| pqc/decapsulate/ML-KEM-768 | 122.1 µs |
| pqc/decapsulate/X25519MLKEM768 | 197.7 µs |
| pqc/decapsulate/X448MLKEM1024 | 408.1 µs |
| pqc/encapsulate/ML-KEM-1024 | 150.5 µs |
| pqc/encapsulate/ML-KEM-512 | 95.0 µs |
| pqc/encapsulate/ML-KEM-768 | 105.2 µs |
| pqc/encapsulate/X25519MLKEM768 | 149.7 µs |
| pqc/encapsulate/X448MLKEM1024 | 376.7 µs |

---

### Key Creation

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| EC/ES256 | — | — | 246.8 µs |
| EC/ES384 | — | — | 921.9 µs |
| RSA/2048 | — | — | 30.19 ms |
| aes-128 | — | 369.0 µs | — |
| aes-256 | — | 223.1 µs | — |
| aes-gcm/oct/128 | — | — | 193.7 µs |
| aes-gcm/oct/256 | — | — | 211.2 µs |
| covercrypt/master-keypair | 22.42 ms | — | — |
| ec-p256 | — | 392.0 µs | — |
| ec/ed25519 | 510.0 µs | — | — |
| ec/ed448 | 644.6 µs | — | — |
| ec/p256 | 481.8 µs | — | — |
| ec/p384 | 937.9 µs | — | — |
| ec/p521 | 1.53 ms | — | — |
| ec/secp256k1 | 536.6 µs | — | — |
| kem/ML-KEM-512 | 952.4 µs | — | — |
| kem/ML-KEM-512/P-256 | 742.0 µs | — | — |
| kem/ML-KEM-512/X25519 | 2.15 ms | — | — |
| kem/ML-KEM-768 | 853.6 µs | — | — |
| kem/ML-KEM-768/P-256 | 1.08 ms | — | — |
| kem/ML-KEM-768/X25519 | 2.59 ms | — | — |
| pqc/ML-DSA-44 | 1.23 ms | — | — |
| pqc/ML-DSA-65 | 1.17 ms | — | — |
| pqc/ML-DSA-87 | 986.0 µs | — | — |
| pqc/ML-KEM-1024 | 1.52 ms | — | — |
| pqc/ML-KEM-512 | 650.2 µs | — | — |
| pqc/ML-KEM-768 | 1.47 ms | — | — |
| pqc/SLH-DSA-SHA2-128f | 831.1 µs | — | — |
| pqc/SLH-DSA-SHA2-128s | 26.44 ms | — | — |
| pqc/SLH-DSA-SHA2-192f | 1.24 ms | — | — |
| pqc/SLH-DSA-SHA2-192s | 40.39 ms | — | — |
| pqc/SLH-DSA-SHA2-256f | 2.12 ms | — | — |
| pqc/SLH-DSA-SHA2-256s | 26.90 ms | — | — |
| pqc/SLH-DSA-SHAKE-128f | 1.73 ms | — | — |
| pqc/SLH-DSA-SHAKE-128s | 70.30 ms | — | — |
| pqc/SLH-DSA-SHAKE-192f | 2.11 ms | — | — |
| pqc/SLH-DSA-SHAKE-192s | 100.96 ms | — | — |
| pqc/SLH-DSA-SHAKE-256f | 4.87 ms | — | — |
| pqc/SLH-DSA-SHAKE-256s | 70.15 ms | — | — |
| pqc/X25519MLKEM768 | 1.04 ms | — | — |
| pqc/X448MLKEM1024 | 785.8 µs | — | — |
| rsa-2048 | — | 29.59 ms | — |
| rsa/rsa-2048 | 32.98 ms | — | — |
| rsa/rsa-3072 | 87.92 ms | — | — |
| rsa/rsa-4096 | 338.01 ms | — | — |
| symmetric/aes-128 | 276.2 µs | — | — |
| symmetric/aes-192 | 364.5 µs | — | — |
| symmetric/aes-256 | 397.2 µs | — | — |
| symmetric/chacha20-256 | 301.1 µs | — | — |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 473.5 µs | 523.4 µs | — |
| ecdsa-p256/verify | 149.3 µs | 138.3 µs | — |
| ecdsa-p384/sign | 1.09 ms | — | — |
| ecdsa-p384/verify | 521.7 µs | — | — |
| ecdsa-p521/sign | 2.26 ms | — | — |
| ecdsa-p521/verify | 1.16 ms | — | — |
| ecdsa-secp256k1/sign | 410.3 µs | — | — |
| ecdsa-secp256k1/verify | 319.4 µs | — | — |
| eddsa-ed25519/sign | 88.5 µs | — | — |
| eddsa-ed25519/verify | 134.2 µs | — | — |
| eddsa-ed448/sign | 302.7 µs | — | — |
| eddsa-ed448/verify | 186.3 µs | — | — |
| ml-dsa/sign/44 | 577.6 µs | — | — |
| ml-dsa/sign/65 | 834.7 µs | — | — |
| ml-dsa/sign/87 | 987.4 µs | — | — |
| ml-dsa/verify/44 | 226.8 µs | — | — |
| ml-dsa/verify/65 | 258.6 µs | — | — |
| ml-dsa/verify/87 | 363.5 µs | — | — |
| rsa-pss/sign/2048 | 24.73 ms | 24.36 ms | — |
| rsa-pss/sign/3072 | 75.63 ms | — | — |
| rsa-pss/sign/4096 | 185.10 ms | — | — |
| rsa-pss/verify/2048 | 87.5 µs | 168.8 µs | — |
| rsa-pss/verify/3072 | 103.9 µs | — | — |
| rsa-pss/verify/4096 | 133.6 µs | — | — |
| sign/ES256 | — | — | 499.0 µs |
| sign/ES384 | — | — | 1.04 ms |
| sign/EdDSA | — | — | 93.3 µs |
| sign/PS256 | — | — | 24.59 ms |
| sign/RS256 | — | — | 25.59 ms |
| slh-dsa/sign/SHA2-128f | 10.33 ms | — | — |
| slh-dsa/sign/SHA2-128s | 198.69 ms | — | — |
| slh-dsa/sign/SHA2-192f | 21.29 ms | — | — |
| slh-dsa/sign/SHA2-192s | 417.12 ms | — | — |
| slh-dsa/sign/SHA2-256f | 38.03 ms | — | — |
| slh-dsa/sign/SHA2-256s | 388.56 ms | — | — |
| slh-dsa/sign/SHAKE-128f | 26.49 ms | — | — |
| slh-dsa/sign/SHAKE-128s | 531.64 ms | — | — |
| slh-dsa/sign/SHAKE-192f | 42.12 ms | — | — |
| slh-dsa/sign/SHAKE-192s | 898.98 ms | — | — |
| slh-dsa/sign/SHAKE-256f | 87.56 ms | — | — |
| slh-dsa/sign/SHAKE-256s | 792.19 ms | — | — |
| slh-dsa/verify/SHA2-128f | 1.12 ms | — | — |
| slh-dsa/verify/SHA2-128s | 491.3 µs | — | — |
| slh-dsa/verify/SHA2-192f | 2.15 ms | — | — |
| slh-dsa/verify/SHA2-192s | 964.2 µs | — | — |
| slh-dsa/verify/SHA2-256f | 2.65 ms | — | — |
| slh-dsa/verify/SHA2-256s | 1.36 ms | — | — |
| slh-dsa/verify/SHAKE-128f | 3.34 ms | — | — |
| slh-dsa/verify/SHAKE-128s | 908.1 µs | — | — |
| slh-dsa/verify/SHAKE-192f | 3.18 ms | — | — |
| slh-dsa/verify/SHAKE-192s | 1.48 ms | — | — |
| slh-dsa/verify/SHAKE-256f | 4.65 ms | — | — |
| slh-dsa/verify/SHAKE-256s | 2.33 ms | — | — |
| verify/ES256 | — | — | 182.5 µs |
| verify/ES384 | — | — | 495.1 µs |
| verify/EdDSA | — | — | 114.3 µs |
| verify/PS256 | — | — | 69.2 µs |
| verify/RS256 | — | — | 51.4 µs |

---

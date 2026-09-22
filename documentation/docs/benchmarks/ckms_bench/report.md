# KMS Performance Comparison

**Versions**: `v5.27.1`  
**Generated**: 2026-09-22

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-22 15:43:08 UTC |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 3,282 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-139-generic |

### Load test parameters

| Parameter | Value |
|---|---|
| Mode | all |
| Protocols | all |
| Measurement window | 20 s per concurrency level |
| Concurrency levels | 1,2,4,8,16 |
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
CPU(s) scaling MHz:                      26%
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
| 1 | 3,031 | 3,762 | 22,783 |
| 2 | 4,800 | 6,792 | 40,427 |
| 4 | 9,034 | 11,110 | 62,082 |
| 8 | 13,099 | 15,621 | 76,459 |
| 16 | 17,841 | 21,225 | 99,672 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 2,270 | 2,300 | 2,454 |
| 2 | 3,860 | 4,118 | 4,502 |
| 4 | 6,587 | 6,654 | 7,208 |
| 8 | 10,078 | 10,104 | 10,860 |
| 16 | 14,441 | 14,382 | 14,941 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 10,545 | 10,550 | 13,831 |
| 2 | 16,991 | 16,803 | 24,512 |
| 4 | 29,110 | 29,328 | 38,659 |
| 8 | 41,779 | 40,850 | 53,899 |
| 16 | 59,497 | 57,096 | 74,688 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,606 | 2,556 |
| 2 | 4,354 | 4,653 |
| 4 | 7,388 | 7,529 |
| 8 | 10,836 | 10,737 |
| 16 | 14,557 | 14,023 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 4,575 |
| 2 | 2,953 |
| 4 | 5,917 |
| 8 | 4,189 |
| 16 | 7,552 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 349 |
| 2 | 642 |
| 4 | 1,067 |
| 8 | 1,560 |
| 16 | 2,004 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 67.9 µs | 92.6 µs | — |
| aes-gcm-siv/decrypt/256 | 70.2 µs | 73.8 µs | — |
| aes-gcm-siv/encrypt/128 | 80.5 µs | 70.2 µs | — |
| aes-gcm-siv/encrypt/256 | 76.0 µs | 67.7 µs | — |
| aes-gcm/decrypt/128 | 73.1 µs | 116.1 µs | 38.4 µs |
| aes-gcm/decrypt/192 | 69.8 µs | 83.0 µs | 39.0 µs |
| aes-gcm/decrypt/256 | 77.0 µs | 71.5 µs | 40.3 µs |
| aes-gcm/encrypt/128 | 74.4 µs | 92.4 µs | 37.0 µs |
| aes-gcm/encrypt/192 | 74.6 µs | 75.0 µs | 38.5 µs |
| aes-gcm/encrypt/256 | 72.9 µs | 81.1 µs | 37.2 µs |
| aes-xts/decrypt/128 | 65.1 µs | 72.9 µs | — |
| aes-xts/decrypt/256 | 65.3 µs | 81.9 µs | — |
| aes-xts/encrypt/128 | 78.4 µs | 71.5 µs | — |
| aes-xts/encrypt/256 | 79.8 µs | 100.7 µs | — |
| chacha20-poly1305/decrypt/256 | 78.0 µs | 80.6 µs | — |
| chacha20-poly1305/encrypt/256 | 67.2 µs | 65.2 µs | — |
| salsa-sealed-box/decrypt | 145.8 µs | 144.5 µs | — |
| salsa-sealed-box/encrypt | 804.62 ms | 1.11 s | — |


---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 12.00 ms | 12.52 ms | — |
| covercrypt/encrypt | 833.51 ms | 1.13 s | — |
| ecies/decrypt/P-256 | 144.1 µs | 169.0 µs | — |
| ecies/decrypt/P-384 | 1.10 ms | — | — |
| ecies/encrypt/P-256 | 814.78 ms | 1.10 s | — |
| ecies/encrypt/P-384 | 868.65 ms | 1.09 s | — |
| rsa-aes-kwp/decrypt/4096 | 172.41 ms | 169.56 ms | — |
| rsa-aes-kwp/encrypt/4096 | 877.42 ms | 1.18 s | — |
| rsa-oaep/decrypt/2048 | — | — | 23.06 ms |
| rsa-oaep/decrypt/4096 | 170.19 ms | 170.23 ms | 162.66 ms |
| rsa-oaep/encrypt/2048 | — | — | 127.4 µs |
| rsa-oaep/encrypt/4096 | 859.20 ms | 1.18 s | 185.1 µs |
| rsa-pkcs1v15/decrypt/4096 | 170.30 ms | 165.33 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 829.58 ms | 1.12 s | — |


---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 131.3 µs | 120.4 µs |
| configurable/decapsulate/ML-KEM-768 | 152.8 µs | — |
| configurable/encapsulate/ML-KEM-512 | 842.01 ms | 1.09 s |
| configurable/encapsulate/ML-KEM-768 | 812.61 ms | 1.11 s |
| pqc/decapsulate/ML-KEM-512 | 150.9 µs | 177.6 µs |
| pqc/decapsulate/ML-KEM-768 | 187.0 µs | — |
| pqc/encapsulate/ML-KEM-512 | 836.49 ms | 1.12 s |
| pqc/encapsulate/ML-KEM-768 | 849.93 ms | 1.09 s |


---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 22.47 ms |
| ec/ed25519 | 575.0 µs |
| ec/ed448 | 527.7 µs |
| ec/p256 | 749.3 µs |
| ec/p384 | 825.0 µs |
| ec/p521 | 1.64 ms |
| ec/secp256k1 | 658.2 µs |
| kem/ML-KEM-512 | 822.7 µs |
| kem/ML-KEM-512/P-256 | 580.2 µs |
| kem/ML-KEM-512/X25519 | 2.19 ms |
| kem/ML-KEM-768 | 801.5 µs |
| kem/ML-KEM-768/P-256 | 632.9 µs |
| kem/ML-KEM-768/X25519 | 2.32 ms |
| pqc/ML-DSA-44 | 507.3 µs |
| pqc/ML-DSA-65 | 571.1 µs |
| pqc/ML-DSA-87 | 661.8 µs |
| pqc/ML-KEM-1024 | 513.4 µs |
| pqc/ML-KEM-512 | 665.3 µs |
| pqc/ML-KEM-768 | 486.1 µs |
| pqc/X25519MLKEM768 | 430.8 µs |
| pqc/X448MLKEM1024 | 533.7 µs |
| rsa/rsa-4096 | 223.20 ms |
| symmetric/aes-128 | 724.2 µs |
| symmetric/aes-192 | 510.2 µs |
| symmetric/aes-256 | 560.1 µs |
| symmetric/chacha20-256 | 485.6 µs |


---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 459.2 µs | 432.2 µs | 422.5 µs |
| ecdsa-p256/verify | 1.09 s | 1.40 s | 1.52 s |
| ecdsa-p384/sign | 990.9 µs | 1.56 ms | 1.04 ms |
| ecdsa-p384/verify | 1.11 s | 1.41 s | 1.52 s |
| ecdsa-p521/sign | 2.46 ms | 3.77 ms | — |
| ecdsa-p521/verify | 1.19 s | 1.39 s | — |
| ecdsa-secp256k1/sign | 401.0 µs | 513.1 µs | — |
| ecdsa-secp256k1/verify | 1.19 s | 1.52 s | — |
| eddsa-ed25519/sign | 105.1 µs | 106.8 µs | 88.5 µs |
| eddsa-ed25519/verify | 1.14 s | 1.52 s | 1.44 s |
| eddsa-ed448/sign | 333.2 µs | 344.6 µs | — |
| eddsa-ed448/verify | 1.09 s | 1.53 s | — |
| ml-dsa/sign/44 | 486.3 µs | 503.0 µs | — |
| ml-dsa/sign/65 | 785.8 µs | 758.0 µs | — |
| ml-dsa/verify/44 | 1.09 s | 1.41 s | — |
| ml-dsa/verify/65 | 1.11 s | 1.51 s | — |
| rsa-pkcs1v15/sign | — | — | 23.54 ms |
| rsa-pkcs1v15/verify | — | — | 1.52 s |
| rsa-pss/sign | — | — | 29.75 ms |
| rsa-pss/sign/4096 | 166.06 ms | 165.59 ms | — |
| rsa-pss/verify | — | — | 1.40 s |
| rsa-pss/verify/4096 | 1.12 s | 1.38 s | — |
| slh-dsa/sign/SHA2-128f | 10.09 ms | 9.58 ms | — |
| slh-dsa/sign/SHA2-256f | 35.44 ms | 37.15 ms | — |
| slh-dsa/verify/SHA2-128f | 1.33 s | 1.52 s | — |
| slh-dsa/verify/SHA2-256f | 1.10 s | 1.49 s | — |


---


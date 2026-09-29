# KMS Performance Comparison

**Versions**: `v5.24.0`
**Generated**: 2026-07-09

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-07-09 13:28:17 UTC |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 3,302 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.4 LTS |
| Kernel | 6.8.0-134-generic |

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
CPU(s) scaling MHz:                      33%
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
| 1 | 1,655 | 16,036 | 35,238 |
| 2 | 8,736 | 28,303 | 62,117 |
| 4 | 15,919 | 42,097 | 90,314 |
| 8 | 24,447 | 52,235 | 105,688 |
| 16 | 32,661 | 58,492 | 89,942 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,902 | 4,601 | 4,840 |
| 2 | 3,579 | 8,421 | 8,899 |
| 4 | 7,214 | 13,683 | 14,240 |
| 8 | 12,598 | 19,260 | 20,329 |
| 16 | 18,646 | 26,443 | 28,094 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 2,292 |
| 2 | 3,743 |
| 4 | 3,199 |
| 8 | 3,462 |
| 16 | 3,487 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,631 |
| 2 | 2,924 |
| 4 | 4,767 |
| 8 | 6,072 |
| 16 | 7,932 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 46.3 µs | 47.1 µs | — |
| aes-gcm-siv/decrypt/256 | 45.1 µs | 38.1 µs | — |
| aes-gcm-siv/encrypt/128 | 49.8 µs | 59.8 µs | — |
| aes-gcm-siv/encrypt/256 | 42.6 µs | 45.6 µs | — |
| aes-gcm/decrypt/128 | 75.3 µs | 47.8 µs | 32.5 µs |
| aes-gcm/decrypt/192 | 41.4 µs | 53.1 µs | 31.6 µs |
| aes-gcm/decrypt/256 | 46.2 µs | 61.4 µs | 30.6 µs |
| aes-gcm/encrypt/128 | 38.5 µs | 47.4 µs | 37.3 µs |
| aes-gcm/encrypt/192 | 51.9 µs | 56.2 µs | 32.4 µs |
| aes-gcm/encrypt/256 | 58.3 µs | 49.8 µs | 32.2 µs |
| aes-xts/decrypt/128 | 47.8 µs | 47.6 µs | — |
| aes-xts/decrypt/256 | 46.2 µs | 53.8 µs | — |
| aes-xts/encrypt/128 | 44.5 µs | 44.9 µs | — |
| aes-xts/encrypt/256 | 45.9 µs | 46.5 µs | — |
| chacha20-poly1305/decrypt/256 | 45.2 µs | 42.4 µs | — |
| chacha20-poly1305/encrypt/256 | 46.5 µs | 39.1 µs | — |
| salsa-sealed-box/decrypt | 116.9 µs | 100.7 µs | — |
| salsa-sealed-box/encrypt | 167.5 µs | 458.73 ms | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 253.6 µs | 232.8 µs | — |
| covercrypt/encrypt | 287.7 µs | 536.10 ms | — |
| ecies/decrypt/P-256 | 126.5 µs | 109.5 µs | — |
| ecies/decrypt/P-384 | 1.03 ms | 947.9 µs | — |
| ecies/decrypt/P-521 | 2.29 ms | — | — |
| ecies/encrypt/P-256 | 194.6 µs | 467.52 ms | — |
| ecies/encrypt/P-384 | 1.09 ms | 536.21 ms | — |
| ecies/encrypt/P-521 | 2.40 ms | 477.34 ms | — |
| rsa-aes-kwp/decrypt/4096 | 174.76 ms | 168.30 ms | — |
| rsa-aes-kwp/encrypt/4096 | 177.2 µs | 531.17 ms | — |
| rsa-oaep/decrypt/2048 | — | — | 23.02 ms |
| rsa-oaep/decrypt/4096 | 178.91 ms | 167.20 ms | 167.28 ms |
| rsa-oaep/encrypt/2048 | — | — | 93.5 µs |
| rsa-oaep/encrypt/4096 | 164.6 µs | 531.28 ms | 143.7 µs |
| rsa-pkcs1v15/decrypt/4096 | 177.32 ms | 167.42 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 155.7 µs | 492.94 ms | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 69.1 µs | 57.9 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 63.4 µs | — |
| configurable/decapsulate/ML-KEM-768 | 72.4 µs | 66.4 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 77.8 µs | — |
| configurable/encapsulate/ML-KEM-512 | 147.9 µs | 469.28 ms |
| configurable/encapsulate/ML-KEM-512/P-256 | 308.0 µs | 527.73 ms |
| configurable/encapsulate/ML-KEM-768 | 167.7 µs | 462.83 ms |
| configurable/encapsulate/ML-KEM-768/P-256 | 370.7 µs | — |
| pqc/decapsulate/ML-KEM-1024 | 129.6 µs | — |
| pqc/decapsulate/ML-KEM-512 | 94.5 µs | 88.0 µs |
| pqc/decapsulate/ML-KEM-768 | 108.6 µs | 91.9 µs |
| pqc/decapsulate/X25519MLKEM768 | 182.9 µs | — |
| pqc/encapsulate/ML-KEM-1024 | 194.5 µs | 480.22 ms |
| pqc/encapsulate/ML-KEM-512 | 196.6 µs | 453.94 ms |
| pqc/encapsulate/ML-KEM-768 | 230.6 µs | 531.89 ms |
| pqc/encapsulate/X25519MLKEM768 | 244.3 µs | — |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 706.9 µs |
| ec/ed25519 | 368.5 µs |
| ec/ed448 | 490.0 µs |
| ec/p256 | 352.0 µs |
| ec/p384 | 822.5 µs |
| ec/p521 | 1.64 ms |
| ec/secp256k1 | 574.3 µs |
| kem/ML-KEM-512 | 371.8 µs |
| kem/ML-KEM-512/P-256 | 499.2 µs |
| kem/ML-KEM-512/X25519 | 338.1 µs |
| kem/ML-KEM-768 | 425.3 µs |
| kem/ML-KEM-768/P-256 | 465.5 µs |
| kem/ML-KEM-768/X25519 | 378.7 µs |
| pqc/ML-DSA-44 | 500.6 µs |
| pqc/ML-DSA-65 | 532.0 µs |
| pqc/ML-DSA-87 | 581.3 µs |
| pqc/ML-KEM-1024 | 418.3 µs |
| pqc/ML-KEM-512 | 385.9 µs |
| pqc/ML-KEM-768 | 410.1 µs |
| pqc/X25519MLKEM768 | 300.2 µs |
| pqc/X448MLKEM1024 | 436.4 µs |
| rsa/rsa-4096 | 515.10 ms |
| symmetric/aes-128 | 237.3 µs |
| symmetric/aes-192 | 224.6 µs |
| symmetric/aes-256 | 269.6 µs |
| symmetric/chacha20-256 | 242.2 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 263.6 µs | 234.9 µs | 231.5 µs |
| ecdsa-p256/verify | 557.86 ms | 1.01 s | 1.18 s |
| ecdsa-p384/sign | 1.17 ms | 966.6 µs | 998.1 µs |
| ecdsa-p384/verify | 554.38 ms | 1.12 s | 1.17 s |
| ecdsa-p521/sign | 2.50 ms | 2.62 ms | — |
| ecdsa-p521/verify | 548.90 ms | 1.10 s | — |
| ecdsa-secp256k1/sign | 351.7 µs | 356.5 µs | — |
| ecdsa-secp256k1/verify | 474.97 ms | 1.02 s | — |
| eddsa-ed25519/sign | 87.0 µs | 92.0 µs | 87.3 µs |
| eddsa-ed25519/verify | 466.31 ms | 1.03 s | 1.03 s |
| eddsa-ed448/sign | 303.4 µs | 290.9 µs | — |
| eddsa-ed448/verify | 530.69 ms | 1.17 s | — |
| ml-dsa/sign/44 | 511.8 µs | 458.9 µs | — |
| ml-dsa/sign/65 | 814.0 µs | 766.5 µs | — |
| ml-dsa/sign/87 | 1.00 ms | — | — |
| ml-dsa/verify/44 | 536.02 ms | 1.16 s | — |
| ml-dsa/verify/65 | 470.30 ms | 1.03 s | — |
| ml-dsa/verify/87 | 480.09 ms | — | — |
| rsa-pkcs1v15/sign | — | — | 23.42 ms |
| rsa-pkcs1v15/verify | — | — | 1.16 s |
| rsa-pss/sign | — | — | 24.11 ms |
| rsa-pss/sign/4096 | 181.90 ms | 172.64 ms | — |
| rsa-pss/verify | — | — | 1.02 s |
| rsa-pss/verify/4096 | 532.30 ms | 1.18 s | — |
| slh-dsa/sign/SHA2-128f | 10.41 ms | 9.52 ms | — |
| slh-dsa/sign/SHA2-256f | 37.66 ms | 34.76 ms | — |
| slh-dsa/sign/SHAKE-128f | 26.75 ms | — | — |
| slh-dsa/verify/SHA2-128f | 543.67 ms | 1.02 s | — |
| slh-dsa/verify/SHA2-256f | 487.30 ms | 1.18 s | — |
| slh-dsa/verify/SHAKE-128f | 477.53 ms | — | — |

---

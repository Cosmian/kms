# KMS Performance Comparison

**Versions**: `v5.27.1`  
**Generated**: 2026-09-13

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-13 07:49:24 UTC |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 2,885 MHz |
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
| 1 | 2,052 | 2,601 | 15,722 |
| 2 | 3,913 | 4,794 | 27,764 |
| 4 | 6,677 | 8,168 | 42,684 |
| 8 | 10,744 | 12,981 | 68,645 |
| 16 | 15,832 | 18,953 | 90,019 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,574 | 1,625 | 1,741 |
| 2 | 2,975 | 3,020 | 3,217 |
| 4 | 5,191 | 5,285 | 5,601 |
| 8 | 8,517 | 8,504 | 9,027 |
| 16 | 13,067 | 13,036 | 14,058 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 7,280 | 7,321 | 9,486 |
| 2 | 13,050 | 13,577 | 17,686 |
| 4 | 21,849 | 21,832 | 28,590 |
| 8 | 35,785 | 35,558 | 45,893 |
| 16 | 49,900 | 49,604 | 64,872 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,986 |
| 2 | 3,734 |
| 4 | 5,769 |
| 8 | 4,618 |
| 16 | 7,386 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 243 |
| 2 | 459 |
| 4 | 820 |
| 8 | 1,275 |
| 16 | 1,882 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 140.1 µs | 66.8 µs | — |
| aes-gcm-siv/decrypt/256 | 140.5 µs | 65.7 µs | — |
| aes-gcm-siv/encrypt/128 | 141.9 µs | 65.5 µs | — |
| aes-gcm-siv/encrypt/256 | 141.0 µs | 58.3 µs | — |
| aes-gcm/decrypt/128 | 111.5 µs | 72.8 µs | 36.5 µs |
| aes-gcm/decrypt/192 | 162.1 µs | 78.9 µs | 45.8 µs |
| aes-gcm/decrypt/256 | 135.4 µs | 72.2 µs | 34.3 µs |
| aes-gcm/encrypt/128 | 122.0 µs | 59.7 µs | 38.2 µs |
| aes-gcm/encrypt/192 | 129.2 µs | 73.1 µs | 37.3 µs |
| aes-gcm/encrypt/256 | 137.8 µs | 67.7 µs | 35.4 µs |
| aes-xts/decrypt/128 | 121.7 µs | 60.2 µs | — |
| aes-xts/decrypt/256 | 127.2 µs | 56.1 µs | — |
| aes-xts/encrypt/128 | 122.8 µs | 62.8 µs | — |
| aes-xts/encrypt/256 | 147.6 µs | 64.7 µs | — |
| chacha20-poly1305/decrypt/256 | 124.6 µs | 64.6 µs | — |
| chacha20-poly1305/encrypt/256 | 127.0 µs | 60.9 µs | — |
| salsa-sealed-box/decrypt | 308.3 µs | 141.6 µs | — |
| salsa-sealed-box/encrypt | 1.35 s | 1.22 s | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 15.58 ms | 11.14 ms | — |
| covercrypt/encrypt | 1.34 s | 1.26 s | — |
| ecies/decrypt/P-256 | 246.6 µs | 131.5 µs | — |
| ecies/encrypt/P-256 | 1.33 s | 1.22 s | — |
| ecies/encrypt/P-384 | 1.38 s | 1.26 s | — |
| rsa-aes-kwp/decrypt/4096 | 231.74 ms | 163.30 ms | — |
| rsa-aes-kwp/encrypt/4096 | 1.41 s | 1.30 s | — |
| rsa-oaep/decrypt/2048 | — | — | 22.70 ms |
| rsa-oaep/decrypt/4096 | 235.09 ms | 163.75 ms | 160.19 ms |
| rsa-oaep/encrypt/2048 | — | — | 126.7 µs |
| rsa-oaep/encrypt/4096 | 1.41 s | 1.30 s | 183.4 µs |
| rsa-pkcs1v15/decrypt/4096 | 234.90 ms | 162.87 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 1.36 s | 1.25 s | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 179.6 µs | 108.7 µs |
| configurable/encapsulate/ML-KEM-512 | 1.38 s | 1.22 s |
| configurable/encapsulate/ML-KEM-768 | 1.13 s | 1.22 s |
| pqc/decapsulate/ML-KEM-512 | 146.5 µs | 131.0 µs |
| pqc/encapsulate/ML-KEM-512 | 992.92 ms | 1.23 s |
| pqc/encapsulate/ML-KEM-768 | 1.03 s | 1.24 s |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 24.79 ms |
| ec/ed25519 | 478.5 µs |
| ec/ed448 | 479.2 µs |
| ec/p256 | 741.6 µs |
| ec/p384 | 1.44 ms |
| ec/p521 | 1.61 ms |
| ec/secp256k1 | 634.3 µs |
| kem/ML-KEM-512 | 1.16 ms |
| kem/ML-KEM-512/P-256 | 905.0 µs |
| kem/ML-KEM-512/X25519 | 2.15 ms |
| kem/ML-KEM-768 | 790.0 µs |
| kem/ML-KEM-768/P-256 | 946.7 µs |
| kem/ML-KEM-768/X25519 | 2.21 ms |
| pqc/ML-DSA-44 | 823.4 µs |
| pqc/ML-DSA-65 | 803.9 µs |
| pqc/ML-DSA-87 | 902.0 µs |
| pqc/ML-KEM-1024 | 835.6 µs |
| pqc/ML-KEM-512 | 637.7 µs |
| pqc/ML-KEM-768 | 948.6 µs |
| pqc/X25519MLKEM768 | 988.9 µs |
| pqc/X448MLKEM1024 | 798.1 µs |
| rsa/rsa-4096 | 202.52 ms |
| symmetric/aes-128 | 584.7 µs |
| symmetric/aes-192 | 562.7 µs |
| symmetric/aes-256 | 445.0 µs |
| symmetric/chacha20-256 | 480.5 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 458.2 µs | 418.2 µs | 416.6 µs |
| ecdsa-p256/verify | 1.31 s | 1.59 s | 1.72 s |
| ecdsa-p384/sign | 996.3 µs | 1.00 ms | 930.6 µs |
| ecdsa-p384/verify | 1.26 s | 1.60 s | 1.71 s |
| ecdsa-p521/sign | 2.24 ms | 2.41 ms | — |
| ecdsa-p521/verify | 1.23 s | 1.65 s | — |
| ecdsa-secp256k1/sign | 385.3 µs | 388.2 µs | — |
| ecdsa-secp256k1/verify | 1.26 s | 1.59 s | — |
| eddsa-ed25519/sign | 110.8 µs | 113.5 µs | 84.5 µs |
| eddsa-ed25519/verify | 1.29 s | 1.60 s | 1.59 s |
| eddsa-ed448/sign | 292.5 µs | 277.1 µs | — |
| eddsa-ed448/verify | 1.22 s | 1.71 s | — |
| ml-dsa/sign/44 | 571.8 µs | 478.7 µs | — |
| ml-dsa/sign/65 | 766.2 µs | 726.0 µs | — |
| ml-dsa/verify/44 | 1.24 s | 1.70 s | — |
| ml-dsa/verify/65 | 1.23 s | 1.59 s | — |
| rsa-pkcs1v15/sign | — | — | 23.43 ms |
| rsa-pkcs1v15/verify | — | — | 1.70 s |
| rsa-pss/sign | — | — | 23.67 ms |
| rsa-pss/sign/4096 | 162.92 ms | 163.01 ms | — |
| rsa-pss/verify | — | — | 1.59 s |
| rsa-pss/verify/4096 | 1.25 s | 1.71 s | — |
| slh-dsa/sign/SHA2-128f | 9.41 ms | 9.48 ms | — |
| slh-dsa/sign/SHA2-256f | 34.54 ms | 35.06 ms | — |
| slh-dsa/verify/SHA2-128f | 1.26 s | 1.59 s | — |
| slh-dsa/verify/SHA2-256f | 1.22 s | 1.70 s | — |

---

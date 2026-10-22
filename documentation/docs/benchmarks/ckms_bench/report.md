# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-21

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-21 00:00:12 UTC |
| HSM backend | None (Software) |
| Command | `mise run bench:load` |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 800 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-147-generic |

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
CPU(s) scaling MHz:                      28%
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

## Architecture

```mermaid
graph TB
    subgraph cli["Local: ckms CLI"]
        ckms["<b>ckms load</b><br/>(concurrent load driver)"]
    end

    subgraph srv["KMS Server"]
        kmip["KMIP 2.1<br/>(HTTP/TLS)"]
        crypto["Software Crypto<br/>(OpenSSL 3.6.2)"]
        db["Key Storage<br/>(SQLite/PostgreSQL)"]
    end

    ckms -->|HTTP/TLS| kmip
    kmip --> crypto
    crypto --> db

    style ckms fill:#4A90E2
    style kmip fill:#7ED321
    style crypto fill:#F5A623
    style db fill:#BD10E0
```

**Components**:

- **ckms**: Configurable concurrent load generator (ops/sec sweep)
- **KMIP Endpoint**: Protocol handler for request/response marshaling
- **Software Crypto**: AES-GCM, RSA-PKCS, ECDSA-P256, EdDSA-Ed25519 via OpenSSL 3.6.2
- **Key Storage**: Key material persistence (SQLite or PostgreSQL)

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

### Load test (`mise run bench:load`)

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
| 1 | 6,237 | 10,650 | 28,038 |
| 2 | 10,797 | 17,267 | 48,887 |
| 4 | 18,378 | 27,891 | 75,160 |
| 8 | 25,032 | 37,336 | 97,895 |
| 16 | 35,154 | 50,283 | 123,612 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 8,177 | 9,023 | 15,921 |
| 2 | 14,228 | 15,016 | 27,648 |
| 4 | 22,697 | 23,787 | 43,478 |
| 8 | 31,234 | 32,051 | 56,520 |
| 16 | 42,170 | 43,370 | 78,438 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 8,776 | 9,260 | 15,120 |
| 2 | 15,217 | 15,309 | 27,474 |
| 4 | 24,312 | 25,514 | 42,844 |
| 8 | 33,549 | 35,016 | 58,802 |
| 16 | 46,815 | 48,142 | 83,175 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,684 | 2,727 |
| 2 | 4,779 | 4,790 |
| 4 | 7,464 | 7,625 |
| 8 | 10,931 | 10,888 |
| 16 | 15,557 | 15,697 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,790 |
| 2 | 2,610 |
| 4 | 3,181 |
| 8 | 4,341 |
| 16 | 3,246 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 997 |
| 2 | 1,810 |
| 4 | 3,063 |
| 8 | 4,611 |
| 16 | 6,498 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 101.8 µs | 80.4 µs | — |
| aes-gcm-siv/decrypt/256 | 88.8 µs | 101.7 µs | — |
| aes-gcm-siv/encrypt/128 | 75.7 µs | 74.0 µs | — |
| aes-gcm-siv/encrypt/256 | 87.3 µs | 84.5 µs | — |
| aes-gcm/decrypt/128 | 101.0 µs | 83.0 µs | 29.9 µs |
| aes-gcm/decrypt/192 | 80.5 µs | 80.1 µs | 33.0 µs |
| aes-gcm/decrypt/256 | 86.9 µs | 114.5 µs | 30.5 µs |
| aes-gcm/encrypt/128 | 92.4 µs | 93.3 µs | 63.4 µs |
| aes-gcm/encrypt/192 | 80.9 µs | 172.2 µs | 53.3 µs |
| aes-gcm/encrypt/256 | 71.8 µs | 91.1 µs | 31.9 µs |
| aes-xts/decrypt/128 | 68.1 µs | 80.4 µs | — |
| aes-xts/decrypt/256 | 88.5 µs | 102.1 µs | — |
| aes-xts/encrypt/128 | 118.1 µs | 87.1 µs | — |
| aes-xts/encrypt/256 | 84.4 µs | 111.0 µs | — |
| chacha20-poly1305/decrypt/256 | 92.2 µs | 119.6 µs | — |
| chacha20-poly1305/encrypt/256 | 79.2 µs | 122.2 µs | — |
| salsa-sealed-box/decrypt | 163.1 µs | 163.5 µs | — |
| salsa-sealed-box/encrypt | 186.4 µs | 174.9 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 11.88 ms | 12.46 ms | — |
| covercrypt/encrypt | 5.30 ms | 5.24 ms | — |
| ecies/decrypt/P-256 | 199.9 µs | 157.7 µs | — |
| ecies/decrypt/P-384 | 1.07 ms | 1.02 ms | — |
| ecies/decrypt/P-521 | 2.20 ms | 2.94 ms | — |
| ecies/encrypt/P-256 | 195.2 µs | 164.8 µs | — |
| ecies/encrypt/P-384 | 1.03 ms | 1.08 ms | — |
| ecies/encrypt/P-521 | 2.51 ms | 2.20 ms | — |
| rsa-aes-kwp/decrypt/4096 | 167.05 ms | 166.11 ms | — |
| rsa-aes-kwp/encrypt/4096 | 170.3 µs | 265.3 µs | — |
| rsa-oaep/decrypt/2048 | — | — | 22.68 ms |
| rsa-oaep/decrypt/4096 | 166.52 ms | 172.91 ms | 161.67 ms |
| rsa-oaep/encrypt/2048 | — | — | 72.4 µs |
| rsa-oaep/encrypt/4096 | 157.9 µs | 146.9 µs | 108.2 µs |
| rsa-pkcs1v15/decrypt/4096 | 169.09 ms | 166.31 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 227.3 µs | 167.6 µs | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 94.7 µs | 226.8 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 121.1 µs | 108.7 µs |
| configurable/decapsulate/ML-KEM-768 | 115.2 µs | 90.1 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 113.3 µs | 114.4 µs |
| configurable/encapsulate/ML-KEM-512 | 171.5 µs | 157.0 µs |
| configurable/encapsulate/ML-KEM-512/P-256 | 330.2 µs | 380.2 µs |
| configurable/encapsulate/ML-KEM-768 | 219.2 µs | 241.8 µs |
| configurable/encapsulate/ML-KEM-768/P-256 | 369.2 µs | 358.1 µs |
| pqc/decapsulate/ML-KEM-1024 | 183.6 µs | 152.6 µs |
| pqc/decapsulate/ML-KEM-512 | 126.2 µs | 120.0 µs |
| pqc/decapsulate/ML-KEM-768 | 145.5 µs | 159.8 µs |
| pqc/decapsulate/X25519MLKEM768 | 217.9 µs | 192.2 µs |
| pqc/encapsulate/ML-KEM-1024 | 156.3 µs | 140.6 µs |
| pqc/encapsulate/ML-KEM-512 | 126.6 µs | 109.9 µs |
| pqc/encapsulate/ML-KEM-768 | 119.0 µs | 143.5 µs |
| pqc/encapsulate/X25519MLKEM768 | 180.4 µs | 201.4 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 22.22 ms |
| ec/ed25519 | 384.5 µs |
| ec/ed448 | 441.2 µs |
| ec/p256 | 488.9 µs |
| ec/p384 | 951.9 µs |
| ec/p521 | 1.35 ms |
| ec/secp256k1 | 551.7 µs |
| kem/ML-KEM-512 | 610.9 µs |
| kem/ML-KEM-512/P-256 | 528.2 µs |
| kem/ML-KEM-512/X25519 | 2.18 ms |
| kem/ML-KEM-768 | 477.7 µs |
| kem/ML-KEM-768/P-256 | 634.6 µs |
| kem/ML-KEM-768/X25519 | 2.23 ms |
| pqc/ML-DSA-44 | 451.7 µs |
| pqc/ML-DSA-65 | 624.5 µs |
| pqc/ML-DSA-87 | 754.6 µs |
| pqc/ML-KEM-1024 | 470.0 µs |
| pqc/ML-KEM-512 | 498.5 µs |
| pqc/ML-KEM-768 | 469.9 µs |
| pqc/X25519MLKEM768 | 500.9 µs |
| pqc/X448MLKEM1024 | 609.8 µs |
| rsa/rsa-4096 | 284.72 ms |
| symmetric/aes-128 | 228.8 µs |
| symmetric/aes-192 | 253.5 µs |
| symmetric/aes-256 | 184.7 µs |
| symmetric/chacha20-256 | 183.1 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 115.1 µs | 123.8 µs | 130.5 µs |
| ecdsa-p256/verify | 171.5 µs | 175.0 µs | 169.4 µs |
| ecdsa-p384/sign | 1.32 ms | 1.38 ms | 1.14 ms |
| ecdsa-p384/verify | 592.1 µs | 531.2 µs | 501.6 µs |
| ecdsa-p521/sign | 2.23 ms | 2.38 ms | — |
| ecdsa-p521/verify | 1.04 ms | 1.05 ms | — |
| ecdsa-secp256k1/sign | 388.8 µs | 376.9 µs | — |
| ecdsa-secp256k1/verify | 382.6 µs | 345.1 µs | — |
| eddsa-ed25519/sign | 137.7 µs | 118.5 µs | 76.0 µs |
| eddsa-ed25519/verify | 166.8 µs | 150.7 µs | 174.6 µs |
| eddsa-ed448/sign | 338.8 µs | 295.3 µs | — |
| eddsa-ed448/verify | 221.7 µs | 223.8 µs | — |
| ml-dsa/sign/44 | 542.6 µs | 513.9 µs | — |
| ml-dsa/sign/65 | 813.5 µs | 825.6 µs | — |
| ml-dsa/sign/87 | 1.12 ms | 952.9 µs | — |
| ml-dsa/verify/44 | 197.8 µs | 162.9 µs | — |
| ml-dsa/verify/65 | 244.4 µs | 216.0 µs | — |
| ml-dsa/verify/87 | 336.7 µs | 273.3 µs | — |
| rsa-pkcs1v15/sign | — | — | 23.87 ms |
| rsa-pkcs1v15/verify | — | — | 104.9 µs |
| rsa-pss/sign | — | — | 23.72 ms |
| rsa-pss/sign/4096 | 168.07 ms | 169.38 ms | — |
| rsa-pss/verify | — | — | 98.3 µs |
| rsa-pss/verify/4096 | 173.8 µs | 155.3 µs | — |
| slh-dsa/sign/SHA2-128f | 9.83 ms | 9.79 ms | — |
| slh-dsa/sign/SHA2-256f | 36.97 ms | 35.37 ms | — |
| slh-dsa/sign/SHAKE-128f | 27.22 ms | 26.42 ms | — |
| slh-dsa/sign/SHAKE-256f | 83.44 ms | 83.72 ms | — |
| slh-dsa/verify/SHA2-128f | 971.9 µs | 787.0 µs | — |
| slh-dsa/verify/SHA2-256f | 1.80 ms | 1.20 ms | — |
| slh-dsa/verify/SHAKE-128f | 1.83 ms | 1.74 ms | — |
| slh-dsa/verify/SHAKE-256f | 3.17 ms | — | — |

---

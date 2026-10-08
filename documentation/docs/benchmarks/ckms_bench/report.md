# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-08

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-08 00:43:34 UTC |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 1,435 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-146-generic |

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
CPU(s) scaling MHz:                      22%
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
| 1 | 2,953 | 3,881 | 23,798 |
| 2 | 5,327 | 6,928 | 40,920 |
| 4 | 9,080 | 10,936 | 66,398 |
| 8 | 13,091 | 16,007 | 84,753 |
| 16 | 18,328 | 21,956 | 105,014 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 2,127 | 2,347 | 2,497 |
| 2 | 3,864 | 4,187 | 4,528 |
| 4 | 6,487 | 6,860 | 7,385 |
| 8 | 10,181 | 10,280 | 11,040 |
| 16 | 14,630 | 14,685 | 15,736 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 10,184 | 10,953 | 14,522 |
| 2 | 17,411 | 17,131 | 25,489 |
| 4 | 30,464 | 30,526 | 40,361 |
| 8 | 44,048 | 42,809 | 56,244 |
| 16 | 60,962 | 58,908 | 77,952 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,669 | 2,625 |
| 2 | 4,635 | 4,757 |
| 4 | 7,836 | 7,714 |
| 8 | 11,067 | 11,058 |
| 16 | 15,048 | 14,972 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 2,869 |
| 2 | 2,802 |
| 4 | 3,914 |
| 8 | 3,141 |
| 16 | 3,674 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 353 |
| 2 | 661 |
| 4 | 1,047 |
| 8 | 1,586 |
| 16 | 2,159 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 64.5 µs | 70.6 µs | — |
| aes-gcm-siv/decrypt/256 | 73.7 µs | 65.2 µs | — |
| aes-gcm-siv/encrypt/128 | 63.3 µs | 71.9 µs | — |
| aes-gcm-siv/encrypt/256 | 68.3 µs | 67.6 µs | — |
| aes-gcm/decrypt/128 | 65.9 µs | 76.8 µs | 34.3 µs |
| aes-gcm/decrypt/192 | 65.9 µs | 69.3 µs | 35.7 µs |
| aes-gcm/decrypt/256 | 66.8 µs | 73.5 µs | 36.4 µs |
| aes-gcm/encrypt/128 | 65.5 µs | 73.3 µs | 40.5 µs |
| aes-gcm/encrypt/192 | 63.9 µs | 119.2 µs | 35.5 µs |
| aes-gcm/encrypt/256 | 69.9 µs | 64.6 µs | 35.3 µs |
| aes-xts/decrypt/128 | 59.8 µs | 60.3 µs | — |
| aes-xts/decrypt/256 | 59.0 µs | 59.4 µs | — |
| aes-xts/encrypt/128 | 71.4 µs | 67.9 µs | — |
| aes-xts/encrypt/256 | 78.6 µs | 69.2 µs | — |
| chacha20-poly1305/decrypt/256 | 62.9 µs | 70.7 µs | — |
| chacha20-poly1305/encrypt/256 | 63.5 µs | 64.7 µs | — |
| salsa-sealed-box/decrypt | 132.5 µs | 183.1 µs | — |
| salsa-sealed-box/encrypt | 142.9 µs | 176.9 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 11.88 ms | 11.64 ms | — |
| covercrypt/encrypt | 5.21 ms | 4.95 ms | — |
| ecies/decrypt/P-256 | 134.3 µs | 138.1 µs | — |
| ecies/decrypt/P-384 | 1.30 ms | 955.1 µs | — |
| ecies/decrypt/P-521 | 2.23 ms | 2.34 ms | — |
| ecies/encrypt/P-256 | 184.7 µs | 176.7 µs | — |
| ecies/encrypt/P-384 | 1.53 ms | 1.03 ms | — |
| ecies/encrypt/P-521 | 2.32 ms | 2.97 ms | — |
| rsa-aes-kwp/decrypt/4096 | 165.57 ms | 167.22 ms | — |
| rsa-aes-kwp/encrypt/4096 | 174.7 µs | 159.4 µs | — |
| rsa-oaep/decrypt/2048 | — | — | 22.70 ms |
| rsa-oaep/decrypt/4096 | 167.38 ms | 167.01 ms | 165.10 ms |
| rsa-oaep/encrypt/2048 | — | — | 125.5 µs |
| rsa-oaep/encrypt/4096 | 196.0 µs | 165.2 µs | 183.2 µs |
| rsa-pkcs1v15/decrypt/4096 | 164.97 ms | 166.02 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 167.9 µs | 161.2 µs | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 135.2 µs | 125.7 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 149.4 µs | 117.1 µs |
| configurable/decapsulate/ML-KEM-768 | 148.7 µs | 136.7 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 157.5 µs | 155.9 µs |
| configurable/encapsulate/ML-KEM-512 | 169.6 µs | 181.5 µs |
| configurable/encapsulate/ML-KEM-512/P-256 | 332.3 µs | 328.8 µs |
| configurable/encapsulate/ML-KEM-768 | 284.0 µs | 216.4 µs |
| configurable/encapsulate/ML-KEM-768/P-256 | 374.3 µs | 445.0 µs |
| pqc/decapsulate/ML-KEM-1024 | 211.3 µs | 199.9 µs |
| pqc/decapsulate/ML-KEM-512 | 159.3 µs | 127.3 µs |
| pqc/decapsulate/ML-KEM-768 | 182.9 µs | 163.6 µs |
| pqc/decapsulate/X25519MLKEM768 | 242.0 µs | 227.4 µs |
| pqc/encapsulate/ML-KEM-1024 | 181.4 µs | 143.1 µs |
| pqc/encapsulate/ML-KEM-512 | 121.4 µs | 125.9 µs |
| pqc/encapsulate/ML-KEM-768 | 159.6 µs | 122.0 µs |
| pqc/encapsulate/X25519MLKEM768 | 180.0 µs | 177.4 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 21.63 ms |
| ec/ed25519 | 420.2 µs |
| ec/ed448 | 540.1 µs |
| ec/p256 | 419.5 µs |
| ec/p384 | 895.3 µs |
| ec/p521 | 1.37 ms |
| ec/secp256k1 | 518.8 µs |
| kem/ML-KEM-512 | 805.6 µs |
| kem/ML-KEM-512/P-256 | 775.9 µs |
| kem/ML-KEM-512/X25519 | 1.75 ms |
| kem/ML-KEM-768 | 967.7 µs |
| kem/ML-KEM-768/P-256 | 635.7 µs |
| kem/ML-KEM-768/X25519 | 2.23 ms |
| pqc/ML-DSA-44 | 646.5 µs |
| pqc/ML-DSA-65 | 636.9 µs |
| pqc/ML-DSA-87 | 901.0 µs |
| pqc/ML-KEM-1024 | 569.6 µs |
| pqc/ML-KEM-512 | 603.7 µs |
| pqc/ML-KEM-768 | 1.21 ms |
| pqc/X25519MLKEM768 | 621.9 µs |
| pqc/X448MLKEM1024 | 598.7 µs |
| rsa/rsa-4096 | 408.93 ms |
| symmetric/aes-128 | 229.1 µs |
| symmetric/aes-192 | 213.4 µs |
| symmetric/aes-256 | 513.0 µs |
| symmetric/chacha20-256 | 235.8 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 434.4 µs | 426.4 µs | 416.2 µs |
| ecdsa-p256/verify | 180.3 µs | 220.3 µs | 121.6 µs |
| ecdsa-p384/sign | 1.11 ms | 1.27 ms | 952.1 µs |
| ecdsa-p384/verify | 675.3 µs | 576.8 µs | 556.4 µs |
| ecdsa-p521/sign | 2.23 ms | 2.36 ms | — |
| ecdsa-p521/verify | 1.23 ms | 1.14 ms | — |
| ecdsa-secp256k1/sign | 422.8 µs | 379.4 µs | — |
| ecdsa-secp256k1/verify | 362.4 µs | 374.8 µs | — |
| eddsa-ed25519/sign | 102.9 µs | 109.9 µs | 85.5 µs |
| eddsa-ed25519/verify | 159.3 µs | 175.2 µs | 133.5 µs |
| eddsa-ed448/sign | 279.6 µs | 274.7 µs | — |
| eddsa-ed448/verify | 226.7 µs | 214.5 µs | — |
| ml-dsa/sign/44 | 518.2 µs | 499.9 µs | — |
| ml-dsa/sign/65 | 774.7 µs | 741.1 µs | — |
| ml-dsa/sign/87 | 932.5 µs | 997.1 µs | — |
| ml-dsa/verify/44 | 339.3 µs | 297.4 µs | — |
| ml-dsa/verify/65 | 422.5 µs | 395.9 µs | — |
| ml-dsa/verify/87 | 547.1 µs | 507.2 µs | — |
| rsa-pkcs1v15/sign | — | — | 23.34 ms |
| rsa-pkcs1v15/verify | — | — | 81.2 µs |
| rsa-pss/sign | — | — | 23.66 ms |
| rsa-pss/sign/4096 | 166.36 ms | 166.95 ms | — |
| rsa-pss/verify | — | — | 117.5 µs |
| rsa-pss/verify/4096 | 190.0 µs | 181.0 µs | — |
| slh-dsa/sign/SHA2-128f | 9.65 ms | 9.67 ms | — |
| slh-dsa/sign/SHA2-256f | 34.79 ms | 38.00 ms | — |
| slh-dsa/sign/SHAKE-128f | 25.19 ms | 24.63 ms | — |
| slh-dsa/sign/SHAKE-256f | 79.82 ms | 81.92 ms | — |
| slh-dsa/verify/SHA2-128f | 1.65 ms | 1.56 ms | — |
| slh-dsa/verify/SHA2-256f | 3.82 ms | 3.42 ms | — |
| slh-dsa/verify/SHAKE-128f | 2.55 ms | 2.36 ms | — |
| slh-dsa/verify/SHAKE-256f | 5.16 ms | — | — |

---

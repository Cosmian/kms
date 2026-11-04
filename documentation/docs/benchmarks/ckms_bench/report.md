# KMS Performance Comparison

**Versions**: `v5.29.0`
**Generated**: 2026-10-29

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-29 15:33:25 UTC |
| HSM backend | None (Software) |
| Command | `mise run bench:load` |
| Build | release / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 1,013 MHz |
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
| 1 | 6,363 | 9,768 | 25,485 |
| 2 | 10,815 | 17,653 | 44,565 |
| 4 | 17,677 | 27,228 | 70,616 |
| 8 | 25,083 | 37,012 | 89,164 |
| 16 | 34,873 | 49,655 | 113,772 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 8,820 | 8,881 | 15,607 |
| 2 | 14,258 | 14,960 | 27,338 |
| 4 | 23,378 | 24,128 | 43,655 |
| 8 | 31,381 | 32,618 | 57,842 |
| 16 | 42,513 | 43,440 | 78,631 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 9,304 | 9,550 | 15,409 |
| 2 | 15,250 | 15,382 | 26,930 |
| 4 | 24,759 | 25,456 | 42,689 |
| 8 | 34,308 | 35,056 | 59,424 |
| 16 | 46,901 | 48,168 | 83,395 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,790 | 2,741 |
| 2 | 4,723 | 4,586 |
| 4 | 7,725 | 7,744 |
| 8 | 11,010 | 10,807 |
| 16 | 15,511 | 15,647 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,660 |
| 2 | 4,030 |
| 4 | 2,841 |
| 8 | 3,356 |
| 16 | 3,439 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,031 |
| 2 | 1,822 |
| 4 | 3,092 |
| 8 | 4,659 |
| 16 | 6,472 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 81.8 µs | 68.3 µs | — |
| aes-gcm-siv/decrypt/256 | 91.4 µs | 62.0 µs | — |
| aes-gcm-siv/encrypt/128 | 75.0 µs | 77.2 µs | — |
| aes-gcm-siv/encrypt/256 | 74.4 µs | 98.1 µs | — |
| aes-gcm/decrypt/128 | 80.8 µs | 82.7 µs | 38.6 µs |
| aes-gcm/decrypt/192 | 79.1 µs | 71.9 µs | 32.1 µs |
| aes-gcm/decrypt/256 | 80.5 µs | 85.6 µs | 34.3 µs |
| aes-gcm/encrypt/128 | 65.1 µs | 73.3 µs | 33.0 µs |
| aes-gcm/encrypt/192 | 83.5 µs | 89.9 µs | 39.5 µs |
| aes-gcm/encrypt/256 | 114.3 µs | 85.8 µs | 32.8 µs |
| aes-xts/decrypt/128 | 70.5 µs | 69.6 µs | — |
| aes-xts/decrypt/256 | 68.2 µs | 67.3 µs | — |
| aes-xts/encrypt/128 | 77.8 µs | 73.6 µs | — |
| aes-xts/encrypt/256 | 85.4 µs | 65.8 µs | — |
| chacha20-poly1305/decrypt/256 | 84.5 µs | 66.3 µs | — |
| chacha20-poly1305/encrypt/256 | 81.4 µs | 81.0 µs | — |
| salsa-sealed-box/decrypt | 149.0 µs | 150.1 µs | — |
| salsa-sealed-box/encrypt | 144.9 µs | 131.4 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| covercrypt/decrypt | 12.02 ms | 11.82 ms | — |
| covercrypt/encrypt | 5.08 ms | 5.04 ms | — |
| ecies/decrypt/P-256 | 199.9 µs | 143.5 µs | — |
| ecies/decrypt/P-384 | 1.03 ms | 990.8 µs | — |
| ecies/decrypt/P-521 | 2.21 ms | 2.29 ms | — |
| ecies/encrypt/P-256 | 278.8 µs | 166.3 µs | — |
| ecies/encrypt/P-384 | 1.11 ms | 988.4 µs | — |
| ecies/encrypt/P-521 | 2.21 ms | 2.97 ms | — |
| rsa-aes-kwp/decrypt/4096 | 164.18 ms | 163.39 ms | — |
| rsa-aes-kwp/encrypt/4096 | 163.0 µs | 157.8 µs | — |
| rsa-oaep/decrypt/2048 | — | — | 22.51 ms |
| rsa-oaep/decrypt/4096 | 164.83 ms | 164.41 ms | 158.82 ms |
| rsa-oaep/encrypt/2048 | — | — | 70.6 µs |
| rsa-oaep/encrypt/4096 | 148.1 µs | 143.3 µs | 108.7 µs |
| rsa-pkcs1v15/decrypt/4096 | 178.64 ms | 163.57 ms | — |
| rsa-pkcs1v15/encrypt/4096 | 181.7 µs | 149.2 µs | — |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 192.4 µs | 203.3 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 326.9 µs | 311.0 µs |
| configurable/decapsulate/ML-KEM-768 | 244.0 µs | 238.1 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 383.1 µs | 367.8 µs |
| configurable/encapsulate/ML-KEM-512 | 184.4 µs | 154.4 µs |
| configurable/encapsulate/ML-KEM-512/P-256 | 321.1 µs | 320.2 µs |
| configurable/encapsulate/ML-KEM-768 | 272.1 µs | 196.6 µs |
| configurable/encapsulate/ML-KEM-768/P-256 | 368.7 µs | 329.9 µs |
| pqc/decapsulate/ML-KEM-1024 | 186.3 µs | 175.8 µs |
| pqc/decapsulate/ML-KEM-512 | 120.2 µs | 109.4 µs |
| pqc/decapsulate/ML-KEM-768 | 142.0 µs | 137.6 µs |
| pqc/decapsulate/X25519MLKEM768 | 241.6 µs | 188.4 µs |
| pqc/encapsulate/ML-KEM-1024 | 141.7 µs | 121.0 µs |
| pqc/encapsulate/ML-KEM-512 | 121.6 µs | 102.3 µs |
| pqc/encapsulate/ML-KEM-768 | 123.5 µs | 115.3 µs |
| pqc/encapsulate/X25519MLKEM768 | 180.2 µs | 152.6 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 22.41 ms |
| ec/ed25519 | 371.1 µs |
| ec/ed448 | 422.0 µs |
| ec/p256 | 303.6 µs |
| ec/p384 | 684.2 µs |
| ec/p521 | 2.05 ms |
| ec/secp256k1 | 673.0 µs |
| kem/ML-KEM-512 | 352.6 µs |
| kem/ML-KEM-512/P-256 | 434.1 µs |
| kem/ML-KEM-512/X25519 | 2.07 ms |
| kem/ML-KEM-768 | 448.5 µs |
| kem/ML-KEM-768/P-256 | 512.8 µs |
| kem/ML-KEM-768/X25519 | 2.19 ms |
| pqc/ML-DSA-44 | 463.9 µs |
| pqc/ML-DSA-65 | 574.5 µs |
| pqc/ML-DSA-87 | 1.11 ms |
| pqc/ML-KEM-1024 | 441.3 µs |
| pqc/ML-KEM-512 | 377.9 µs |
| pqc/ML-KEM-768 | 416.5 µs |
| pqc/X25519MLKEM768 | 514.0 µs |
| pqc/X448MLKEM1024 | 567.8 µs |
| rsa/rsa-4096 | 245.45 ms |
| symmetric/aes-128 | 233.7 µs |
| symmetric/aes-192 | 219.5 µs |
| symmetric/aes-256 | 230.7 µs |
| symmetric/chacha20-256 | 425.1 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 129.2 µs | 154.5 µs | 74.7 µs |
| ecdsa-p256/verify | 170.0 µs | 153.8 µs | 149.6 µs |
| ecdsa-p384/sign | 1.05 ms | 1.00 ms | 1.11 ms |
| ecdsa-p384/verify | 576.5 µs | 516.7 µs | 536.8 µs |
| ecdsa-p521/sign | 2.22 ms | 2.44 ms | — |
| ecdsa-p521/verify | 1.05 ms | 1.20 ms | — |
| ecdsa-secp256k1/sign | 406.5 µs | 365.6 µs | — |
| ecdsa-secp256k1/verify | 336.4 µs | 336.9 µs | — |
| eddsa-ed25519/sign | 119.7 µs | 114.3 µs | 97.5 µs |
| eddsa-ed25519/verify | 164.6 µs | 181.5 µs | 133.5 µs |
| eddsa-ed448/sign | 318.4 µs | 314.6 µs | — |
| eddsa-ed448/verify | 216.3 µs | 242.4 µs | — |
| ml-dsa/sign/44 | 544.8 µs | 517.6 µs | — |
| ml-dsa/sign/65 | 782.7 µs | 774.4 µs | — |
| ml-dsa/sign/87 | 1.13 ms | 960.9 µs | — |
| ml-dsa/verify/44 | 196.5 µs | 158.3 µs | — |
| ml-dsa/verify/65 | 299.6 µs | 200.5 µs | — |
| ml-dsa/verify/87 | 318.9 µs | 269.2 µs | — |
| rsa-pkcs1v15/sign | — | — | 23.19 ms |
| rsa-pkcs1v15/verify | — | — | 88.0 µs |
| rsa-pss/sign | — | — | 23.09 ms |
| rsa-pss/sign/4096 | 165.72 ms | 165.35 ms | — |
| rsa-pss/verify | — | — | 81.8 µs |
| rsa-pss/verify/4096 | 158.3 µs | 146.7 µs | — |
| slh-dsa/sign/SHA2-128f | 10.18 ms | 9.44 ms | — |
| slh-dsa/sign/SHA2-256f | 36.79 ms | 34.48 ms | — |
| slh-dsa/sign/SHAKE-128f | 24.86 ms | 24.16 ms | — |
| slh-dsa/sign/SHAKE-256f | 80.15 ms | 80.31 ms | — |
| slh-dsa/verify/SHA2-128f | 952.5 µs | 713.2 µs | — |
| slh-dsa/verify/SHA2-256f | 1.72 ms | 1.20 ms | — |
| slh-dsa/verify/SHAKE-128f | 1.89 ms | 1.67 ms | — |
| slh-dsa/verify/SHAKE-256f | 3.02 ms | 2.53 ms | — |

---

# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-08

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-07 23:12:31 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 800 MHz |
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
CPU(s) scaling MHz:                      30%
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
        ckms["<b>ckms load</b>"]
    end

    subgraph srv["Local KMS Server + SoftHSM2"]
        kmip["KMIP 2.1<br/>(HTTP)"]
        crypto["Software Crypto"]
        kek["KEK<br/>(HSM-resident)"]
    end

    subgraph hsm["SoftHSM2"]
        pkcs11["PKCS#11 Slot"]
        kek_material["KEK Material"]
    end

    db["Key Storage<br/>(wrapped)"]

    ckms -->|HTTP| kmip
    kmip --> crypto
    crypto -->|unwrap| kek
    kek -->|C_Decrypt| pkcs11
    pkcs11 --> kek_material
    crypto --> db

    style ckms fill:#4A90E2
    style kmip fill:#7ED321
    style crypto fill:#F5A623
    style kek fill:#FF6B6B
    style pkcs11 fill:#BD10E0
```

**Components**:

- **ckms**: Concurrent load generator
- **KMIP Endpoint**: HTTP protocol handler
- **Software Crypto**: Handles data encryption/decryption with unwrapped keys
- **KEK**: HSM-resident Key Encryption Key (used to wrap/unwrap data keys)
- **PKCS#11 Slot**: HSM backend for KEK unwrap operations
- **Key Storage**: Database of wrapped keys

---

## Protocols

> **HSM-backed KEK, software crypto.** The root key-encryption-key (KEK) used to wrap every benchmarked key is HSM-resident (SoftHSM2); only its unwrap touches the HSM. Encrypt/Sign themselves still execute in KMS software (OpenSSL), same as the plain software baseline — this report isolates the cost of HSM-backed key wrapping. For benchmarks where the cryptographic operation itself executes ON the HSM, see the dedicated HSM-delegated-crypto report.

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

> **HSM-backed KEK.** The server is started with a SoftHSM2-registered `key_encryption_key` (KEK): every benchmarked software key is wrapped by this HSM-resident KEK at rest, and unwrapped via a PKCS#11 round-trip on each use. All other methodology below (payload sizes, load-test/criterion procedure) is identical to the plain software baseline — the only difference is this extra HSM unwrap step per operation.

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
| 1 | 3,060 | 3,706 | 18,623 |
| 2 | 5,488 | 6,638 | 32,797 |
| 4 | 8,880 | 10,559 | 52,361 |
| 8 | 12,734 | 15,138 | 61,798 |
| 16 | 17,673 | 21,016 | 74,310 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 2,220 | 2,285 | 1,698 |
| 2 | 4,003 | 3,735 | 3,035 |
| 4 | 6,470 | 6,547 | 5,118 |
| 8 | 9,622 | 9,830 | 9,432 |
| 16 | 14,050 | 14,097 | 14,269 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 9,927 | 9,376 | 11,594 |
| 2 | 16,658 | 16,013 | 21,141 |
| 4 | 27,274 | 26,804 | 34,107 |
| 8 | 38,446 | 37,456 | 46,756 |
| 16 | 53,122 | 51,765 | 65,793 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,562 | 2,521 |
| 2 | 4,515 | 4,548 |
| 4 | 7,243 | 7,078 |
| 8 | 10,506 | 10,431 |
| 16 | 14,365 | 14,263 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,034 |
| 2 | 1,590 |
| 4 | 2,762 |
| 8 | 4,197 |
| 16 | 3,822 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 348 |
| 2 | 670 |
| 4 | 1,012 |
| 8 | 1,568 |
| 16 | 2,140 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 92.0 µs | 128.3 µs | — |
| aes-gcm-siv/decrypt/256 | 95.5 µs | 99.7 µs | — |
| aes-gcm-siv/encrypt/128 | 77.0 µs | 98.0 µs | — |
| aes-gcm-siv/encrypt/256 | 72.2 µs | 82.5 µs | — |
| aes-gcm/decrypt/128 | 83.0 µs | 87.5 µs | 45.7 µs |
| aes-gcm/decrypt/192 | 92.8 µs | 81.2 µs | 46.7 µs |
| aes-gcm/decrypt/256 | 83.1 µs | 88.9 µs | 45.1 µs |
| aes-gcm/encrypt/128 | 78.7 µs | 85.8 µs | 52.4 µs |
| aes-gcm/encrypt/192 | 81.7 µs | 90.7 µs | 44.7 µs |
| aes-gcm/encrypt/256 | 78.2 µs | 98.3 µs | 47.2 µs |
| aes-xts/decrypt/128 | 71.5 µs | 103.6 µs | — |
| aes-xts/decrypt/256 | 86.7 µs | 70.7 µs | — |
| aes-xts/encrypt/128 | 83.3 µs | 89.9 µs | — |
| aes-xts/encrypt/256 | 81.3 µs | 94.6 µs | — |
| chacha20-poly1305/decrypt/256 | 77.7 µs | 92.2 µs | — |
| chacha20-poly1305/encrypt/256 | 87.8 µs | 97.1 µs | — |
| salsa-sealed-box/decrypt | 163.5 µs | 166.5 µs | — |
| salsa-sealed-box/encrypt | 858.2 µs | 274.0 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 156.6 µs | 331.7 µs |
| ecies/decrypt/P-384 | 970.6 µs | 1.14 ms |
| ecies/decrypt/P-521 | 2.63 ms | 2.11 ms |
| ecies/encrypt/P-256 | 395.2 µs | 307.8 µs |
| ecies/encrypt/P-384 | 1.33 ms | 1.30 ms |
| ecies/encrypt/P-521 | 2.79 ms | 2.22 ms |
| rsa-aes-kwp/decrypt/4096 | 171.16 ms | 168.47 ms |
| rsa-aes-kwp/encrypt/4096 | 349.0 µs | 543.7 µs |
| rsa-oaep/decrypt/4096 | 172.20 ms | 167.59 ms |
| rsa-oaep/encrypt/4096 | 593.1 µs | 283.7 µs |
| rsa-pkcs1v15/decrypt/4096 | 166.78 ms | 165.15 ms |
| rsa-pkcs1v15/encrypt/4096 | 992.7 µs | 286.5 µs |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-1024 | 269.7 µs | 259.8 µs |
| pqc/decapsulate/ML-KEM-512 | 174.1 µs | 160.9 µs |
| pqc/decapsulate/ML-KEM-768 | 210.4 µs | 200.0 µs |
| pqc/encapsulate/ML-KEM-1024 | 626.6 µs | 539.8 µs |
| pqc/encapsulate/ML-KEM-512 | 318.2 µs | 613.6 µs |
| pqc/encapsulate/ML-KEM-768 | 419.8 µs | 382.0 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 568.8 µs |
| ec/ed448 | 783.6 µs |
| ec/p256 | 701.3 µs |
| ec/p384 | 1.16 ms |
| ec/p521 | 1.70 ms |
| ec/secp256k1 | 826.7 µs |
| pqc/ML-DSA-44 | 1.95 ms |
| pqc/ML-DSA-65 | 1.74 ms |
| pqc/ML-DSA-87 | 2.42 ms |
| pqc/ML-KEM-1024 | 1.26 ms |
| pqc/ML-KEM-512 | 1.41 ms |
| pqc/ML-KEM-768 | 1.41 ms |
| pqc/SLH-DSA-SHA2-128f | 2.05 ms |
| pqc/SLH-DSA-SHA2-256f | 2.61 ms |
| rsa/rsa-4096 | 326.01 ms |
| symmetric/aes-128 | 576.5 µs |
| symmetric/aes-192 | 433.0 µs |
| symmetric/aes-256 | 287.6 µs |
| symmetric/chacha20-256 | 678.3 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 472.9 µs | 532.9 µs | 432.7 µs |
| ecdsa-p256/verify | 343.1 µs | 343.8 µs | 246.3 µs |
| ecdsa-p384/sign | 988.1 µs | 1.01 ms | 980.2 µs |
| ecdsa-p384/verify | 814.1 µs | 696.1 µs | 665.0 µs |
| ecdsa-p521/sign | 2.32 ms | 2.19 ms | — |
| ecdsa-p521/verify | 1.45 ms | 1.24 ms | — |
| ecdsa-secp256k1/sign | 423.9 µs | 425.7 µs | — |
| ecdsa-secp256k1/verify | 498.6 µs | 488.7 µs | — |
| eddsa-ed25519/sign | 129.4 µs | 115.9 µs | 127.6 µs |
| eddsa-ed25519/verify | 494.4 µs | 369.7 µs | 392.1 µs |
| eddsa-ed448/sign | 296.3 µs | 301.6 µs | — |
| eddsa-ed448/verify | 335.1 µs | 405.1 µs | — |
| ml-dsa/sign/44 | 614.6 µs | 732.5 µs | — |
| ml-dsa/sign/65 | 835.6 µs | 764.9 µs | — |
| ml-dsa/sign/87 | 1.03 ms | 922.3 µs | — |
| ml-dsa/verify/44 | 451.8 µs | 483.2 µs | — |
| ml-dsa/verify/65 | 708.7 µs | 565.5 µs | — |
| ml-dsa/verify/87 | 740.3 µs | 652.6 µs | — |
| rsa-pkcs1v15/sign | — | — | 25.33 ms |
| rsa-pkcs1v15/verify | — | — | 855.0 µs |
| rsa-pss/sign | — | — | 24.51 ms |
| rsa-pss/sign/4096 | 166.55 ms | 181.63 ms | — |
| rsa-pss/verify | — | — | 633.5 µs |
| rsa-pss/verify/4096 | 459.7 µs | 414.8 µs | — |
| slh-dsa/sign/SHA2-128f | 9.76 ms | 9.45 ms | — |
| slh-dsa/sign/SHA2-256f | 35.65 ms | 34.78 ms | — |
| slh-dsa/sign/SHAKE-128f | 25.54 ms | 24.70 ms | — |
| slh-dsa/sign/SHAKE-256f | 85.35 ms | 80.85 ms | — |
| slh-dsa/verify/SHA2-128f | 1.90 ms | 1.70 ms | — |
| slh-dsa/verify/SHA2-256f | 4.07 ms | 3.76 ms | — |
| slh-dsa/verify/SHAKE-128f | 2.87 ms | 2.69 ms | — |
| slh-dsa/verify/SHAKE-256f | 5.87 ms | 4.98 ms | — |

---

# KMS Performance Comparison

**Versions**: `v5.27.1`
**Generated**: 2026-09-25

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-24 23:57:09 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 1,037 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-142-generic |

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
| 1 | 2,963 | 3,640 | 17,258 |
| 2 | 5,281 | 6,486 | 30,988 |
| 4 | 8,761 | 10,458 | 49,685 |
| 8 | 12,620 | 14,967 | 63,644 |
| 16 | 17,437 | 20,654 | 84,360 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 2,268 | 2,244 | 2,305 |
| 2 | 3,990 | 3,975 | 4,253 |
| 4 | 6,332 | 6,566 | 6,727 |
| 8 | 9,610 | 9,802 | 10,270 |
| 16 | 14,063 | 13,872 | 14,884 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 9,121 | 8,701 | 11,224 |
| 2 | 15,757 | 15,093 | 19,962 |
| 4 | 26,825 | 25,324 | 32,055 |
| 8 | 37,257 | 35,784 | 45,386 |
| 16 | 52,368 | 50,401 | 63,545 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,500 | 2,419 |
| 2 | 4,467 | 4,282 |
| 4 | 7,311 | 6,839 |
| 8 | 10,357 | 10,159 |
| 16 | 13,991 | 13,913 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,609 |
| 2 | 4,356 |
| 4 | 2,628 |
| 8 | 5,278 |
| 16 | 3,504 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 349 |
| 2 | 641 |
| 4 | 1,055 |
| 8 | 1,576 |
| 16 | 2,144 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 95.2 µs | 92.2 µs | — |
| aes-gcm-siv/decrypt/256 | 102.2 µs | 118.4 µs | — |
| aes-gcm-siv/encrypt/128 | 107.3 µs | 97.1 µs | — |
| aes-gcm-siv/encrypt/256 | 81.9 µs | 98.7 µs | — |
| aes-gcm/decrypt/128 | 107.8 µs | 78.7 µs | 74.8 µs |
| aes-gcm/decrypt/192 | 99.1 µs | 84.9 µs | 46.3 µs |
| aes-gcm/decrypt/256 | 127.0 µs | 116.5 µs | 53.0 µs |
| aes-gcm/encrypt/128 | 101.4 µs | 96.8 µs | 85.5 µs |
| aes-gcm/encrypt/192 | 99.3 µs | 87.6 µs | 63.0 µs |
| aes-gcm/encrypt/256 | 86.1 µs | 100.9 µs | 58.9 µs |
| aes-xts/decrypt/128 | 90.5 µs | 85.1 µs | — |
| aes-xts/decrypt/256 | 162.0 µs | 144.2 µs | — |
| aes-xts/encrypt/128 | 113.3 µs | 111.2 µs | — |
| aes-xts/encrypt/256 | 101.5 µs | 94.8 µs | — |
| chacha20-poly1305/decrypt/256 | 102.6 µs | 109.6 µs | — |
| chacha20-poly1305/encrypt/256 | 102.6 µs | 99.3 µs | — |
| salsa-sealed-box/decrypt | 177.4 µs | 178.5 µs | — |
| salsa-sealed-box/encrypt | 154.9 µs | 150.9 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 161.6 µs | 182.2 µs |
| ecies/decrypt/P-384 | 1.05 ms | 1.03 ms |
| ecies/decrypt/P-521 | 2.43 ms | 2.20 ms |
| ecies/encrypt/P-256 | 200.2 µs | 191.2 µs |
| ecies/encrypt/P-384 | 1.63 ms | 1.07 ms |
| ecies/encrypt/P-521 | 2.98 ms | 2.24 ms |
| rsa-aes-kwp/decrypt/4096 | 171.37 ms | 173.85 ms |
| rsa-aes-kwp/encrypt/4096 | 197.7 µs | 208.8 µs |
| rsa-oaep/decrypt/4096 | 172.85 ms | 174.33 ms |
| rsa-oaep/encrypt/4096 | 164.6 µs | 177.3 µs |
| rsa-pkcs1v15/decrypt/4096 | 173.90 ms | 169.47 ms |
| rsa-pkcs1v15/encrypt/4096 | 186.9 µs | 205.2 µs |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-1024 | 275.8 µs | 317.7 µs |
| pqc/decapsulate/ML-KEM-512 | 194.2 µs | 166.4 µs |
| pqc/decapsulate/ML-KEM-768 | 232.1 µs | 206.4 µs |
| pqc/encapsulate/ML-KEM-1024 | 189.7 µs | 158.5 µs |
| pqc/encapsulate/ML-KEM-512 | 118.8 µs | 186.4 µs |
| pqc/encapsulate/ML-KEM-768 | 173.1 µs | 171.3 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 767.5 µs |
| ec/ed448 | 657.2 µs |
| ec/p256 | 567.3 µs |
| ec/p384 | 1.18 ms |
| ec/p521 | 1.87 ms |
| ec/secp256k1 | 853.5 µs |
| pqc/ML-DSA-44 | 1.07 ms |
| pqc/ML-DSA-65 | 1.47 ms |
| pqc/ML-DSA-87 | 1.29 ms |
| pqc/ML-KEM-1024 | 1.17 ms |
| pqc/ML-KEM-512 | 1.00 ms |
| pqc/ML-KEM-768 | 1.14 ms |
| pqc/SLH-DSA-SHA2-128f | 968.5 µs |
| pqc/SLH-DSA-SHA2-256f | 2.61 ms |
| rsa/rsa-4096 | 395.25 ms |
| symmetric/aes-128 | 996.5 µs |
| symmetric/aes-192 | 962.4 µs |
| symmetric/aes-256 | 503.4 µs |
| symmetric/chacha20-256 | 424.2 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 496.3 µs | 506.9 µs | 471.6 µs |
| ecdsa-p256/verify | 230.6 µs | 224.0 µs | 153.6 µs |
| ecdsa-p384/sign | 1.05 ms | 1.04 ms | 1.06 ms |
| ecdsa-p384/verify | 599.9 µs | 723.7 µs | 645.2 µs |
| ecdsa-p521/sign | 2.34 ms | 2.34 ms | — |
| ecdsa-p521/verify | 1.86 ms | 1.07 ms | — |
| ecdsa-secp256k1/sign | 448.0 µs | 440.9 µs | — |
| ecdsa-secp256k1/verify | 670.8 µs | 439.8 µs | — |
| eddsa-ed25519/sign | 116.6 µs | 125.7 µs | 100.3 µs |
| eddsa-ed25519/verify | 338.2 µs | 409.5 µs | 139.9 µs |
| eddsa-ed448/sign | 346.1 µs | 342.2 µs | — |
| eddsa-ed448/verify | 322.3 µs | 352.4 µs | — |
| ml-dsa/sign/44 | 676.7 µs | 504.6 µs | — |
| ml-dsa/sign/65 | 881.5 µs | 1.07 ms | — |
| ml-dsa/sign/87 | 1.10 ms | 1.22 ms | — |
| ml-dsa/verify/44 | 400.2 µs | 383.6 µs | — |
| ml-dsa/verify/65 | 431.8 µs | 579.0 µs | — |
| ml-dsa/verify/87 | 715.5 µs | 1.02 ms | — |
| rsa-pkcs1v15/sign | — | — | 24.12 ms |
| rsa-pkcs1v15/verify | — | — | 108.6 µs |
| rsa-pss/sign | — | — | 24.85 ms |
| rsa-pss/sign/4096 | 171.43 ms | 170.55 ms | — |
| rsa-pss/verify | — | — | 177.3 µs |
| rsa-pss/verify/4096 | 350.3 µs | 217.9 µs | — |
| slh-dsa/sign/SHA2-128f | 10.33 ms | 10.68 ms | — |
| slh-dsa/sign/SHA2-256f | 36.94 ms | 36.53 ms | — |
| slh-dsa/sign/SHAKE-128f | 27.79 ms | 25.92 ms | — |
| slh-dsa/sign/SHAKE-256f | 83.76 ms | 86.85 ms | — |
| slh-dsa/verify/SHA2-128f | 1.93 ms | 3.29 ms | — |
| slh-dsa/verify/SHA2-256f | 4.31 ms | 3.69 ms | — |
| slh-dsa/verify/SHAKE-128f | 3.23 ms | 2.39 ms | — |
| slh-dsa/verify/SHAKE-256f | 5.25 ms | 5.10 ms | — |

---

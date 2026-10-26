# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-21

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-20 22:31:19 UTC |
| HSM backend | SoftHSM2 |
| Command | `mise run bench:hsm --hsm-model softhsm2` |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 4,278 MHz |
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
- **KEK**: SoftHSM2-resident Key Encryption Key (used to wrap/unwrap data keys)
- **PKCS#11 Slot**: SoftHSM2 backend for KEK unwrap operations
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

### Load test (`mise run bench:hsm --hsm-model softhsm2`)

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
| 1 | 3,609 | 3,378 | 25,272 |
| 2 | 5,414 | 3,945 | 42,463 |
| 4 | 7,688 | 7,936 | 67,869 |
| 8 | 4,343 | 6,959 | 85,292 |
| 16 | 4,320 | 2,902 | 109,406 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,246 | 3,843 | 13,113 |
| 2 | 2,615 | 3,452 | 22,327 |
| 4 | 7,337 | 6,654 | 36,520 |
| 8 | 4,004 | 5,800 | 48,325 |
| 16 | 2,994 | 3,892 | 66,252 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,509 | 3,827 | 12,602 |
| 2 | 2,387 | 4,714 | 22,368 |
| 4 | 5,249 | 7,233 | 35,736 |
| 8 | 4,080 | 5,102 | 49,195 |
| 16 | 2,793 | 3,076 | 69,541 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 1,923 | 1,994 |
| 2 | 3,096 | 3,238 |
| 4 | 4,622 | 5,068 |
| 8 | 5,981 | 6,198 |
| 16 | 6,086 | 6,011 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,985 |
| 2 | 3,010 |
| 4 | 2,426 |
| 8 | 3,015 |
| 16 | 2,867 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 820 |
| 2 | 1,560 |
| 4 | 2,584 |
| 8 | 3,594 |
| 16 | 4,809 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 533.3 µs | 498.4 µs | — |
| aes-gcm-siv/decrypt/256 | 874.3 µs | 587.0 µs | — |
| aes-gcm-siv/encrypt/128 | 845.6 µs | 244.2 µs | — |
| aes-gcm-siv/encrypt/256 | 846.4 µs | 810.2 µs | — |
| aes-gcm/decrypt/128 | 643.3 µs | 835.3 µs | 50.9 µs |
| aes-gcm/decrypt/192 | 682.9 µs | 644.4 µs | 34.5 µs |
| aes-gcm/decrypt/256 | 223.6 µs | 288.1 µs | 38.9 µs |
| aes-gcm/encrypt/128 | 759.9 µs | 180.3 µs | 48.2 µs |
| aes-gcm/encrypt/192 | 188.1 µs | 309.5 µs | 35.7 µs |
| aes-gcm/encrypt/256 | 755.2 µs | 653.1 µs | 63.1 µs |
| aes-xts/decrypt/128 | 530.3 µs | 566.6 µs | — |
| aes-xts/decrypt/256 | 262.0 µs | 725.7 µs | — |
| aes-xts/encrypt/128 | 389.1 µs | 203.7 µs | — |
| aes-xts/encrypt/256 | 436.0 µs | 845.1 µs | — |
| chacha20-poly1305/decrypt/256 | 644.9 µs | 206.2 µs | — |
| chacha20-poly1305/encrypt/256 | 869.0 µs | 529.3 µs | — |
| salsa-sealed-box/decrypt | 347.4 µs | 506.4 µs | — |
| salsa-sealed-box/encrypt | 581.0 µs | 226.5 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 284.6 µs | 270.7 µs |
| ecies/decrypt/P-384 | 1.20 ms | 1.69 ms |
| ecies/decrypt/P-521 | 2.43 ms | 2.50 ms |
| ecies/encrypt/P-256 | 586.4 µs | 481.2 µs |
| ecies/encrypt/P-384 | 1.58 ms | 1.21 ms |
| ecies/encrypt/P-521 | 2.50 ms | 2.48 ms |
| rsa-aes-kwp/decrypt/4096 | 167.18 ms | 168.38 ms |
| rsa-aes-kwp/encrypt/4096 | 331.7 µs | 373.7 µs |
| rsa-oaep/decrypt/4096 | 169.98 ms | 173.45 ms |
| rsa-oaep/encrypt/4096 | 395.7 µs | 425.0 µs |
| rsa-pkcs1v15/decrypt/4096 | 171.19 ms | 167.21 ms |
| rsa-pkcs1v15/encrypt/4096 | 383.1 µs | 259.1 µs |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-1024 | 836.3 µs | 418.6 µs |
| pqc/decapsulate/ML-KEM-512 | 440.1 µs | 801.4 µs |
| pqc/decapsulate/ML-KEM-768 | 1.65 ms | 374.5 µs |
| pqc/encapsulate/ML-KEM-1024 | 836.1 µs | 392.8 µs |
| pqc/encapsulate/ML-KEM-512 | 530.5 µs | 929.4 µs |
| pqc/encapsulate/ML-KEM-768 | 731.0 µs | 707.8 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 993.6 µs |
| ec/ed448 | 896.5 µs |
| ec/p256 | 774.0 µs |
| ec/p384 | 1.58 ms |
| ec/p521 | 2.09 ms |
| ec/secp256k1 | 1.15 ms |
| pqc/ML-DSA-44 | 2.81 ms |
| pqc/ML-DSA-65 | 2.41 ms |
| pqc/ML-DSA-87 | 4.09 ms |
| pqc/ML-KEM-1024 | 2.55 ms |
| pqc/ML-KEM-512 | 2.14 ms |
| pqc/ML-KEM-768 | 2.66 ms |
| pqc/SLH-DSA-SHA2-128f | — |
| pqc/SLH-DSA-SHA2-256f | — |
| rsa/rsa-4096 | 335.92 ms |
| symmetric/aes-128 | 807.8 µs |
| symmetric/aes-192 | 430.1 µs |
| symmetric/aes-256 | 816.7 µs |
| symmetric/chacha20-256 | 330.7 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 755.6 µs | 480.3 µs | 89.9 µs |
| ecdsa-p256/verify | 799.3 µs | 479.9 µs | 361.6 µs |
| ecdsa-p384/sign | 1.53 ms | 1.59 ms | 981.3 µs |
| ecdsa-p384/verify | 1.25 ms | 633.2 µs | 673.7 µs |
| ecdsa-p521/sign | 9.35 ms | 2.49 ms | — |
| ecdsa-p521/verify | 4.74 ms | 1.35 ms | — |
| ecdsa-secp256k1/sign | 2.49 ms | 563.3 µs | — |
| ecdsa-secp256k1/verify | 2.22 ms | 536.6 µs | — |
| eddsa-ed25519/sign | 565.0 µs | 727.1 µs | 86.6 µs |
| eddsa-ed25519/verify | 441.8 µs | 588.6 µs | 359.9 µs |
| eddsa-ed448/sign | 875.2 µs | 439.2 µs | — |
| eddsa-ed448/verify | 744.4 µs | 497.3 µs | — |
| ml-dsa/sign/44 | 1.08 ms | 863.3 µs | — |
| ml-dsa/sign/65 | 1.18 ms | 1.33 ms | — |
| ml-dsa/sign/87 | 1.34 ms | 1.30 ms | — |
| ml-dsa/verify/44 | 458.8 µs | 323.1 µs | — |
| ml-dsa/verify/65 | 476.1 µs | 506.9 µs | — |
| ml-dsa/verify/87 | 631.1 µs | 466.0 µs | — |
| rsa-pkcs1v15/sign | — | — | 24.14 ms |
| rsa-pkcs1v15/verify | — | — | 568.7 µs |
| rsa-pss/sign | — | — | 25.06 ms |
| rsa-pss/sign/4096 | 195.27 ms | 169.93 ms | — |
| rsa-pss/verify | — | — | 910.1 µs |
| rsa-pss/verify/4096 | 686.2 µs | 295.5 µs | — |
| slh-dsa/sign/SHA2-128f | 10.28 ms | 10.40 ms | — |
| slh-dsa/sign/SHA2-256f | 36.45 ms | 37.96 ms | — |
| slh-dsa/sign/SHAKE-128f | 26.00 ms | 26.62 ms | — |
| slh-dsa/sign/SHAKE-256f | 83.39 ms | 81.88 ms | — |
| slh-dsa/verify/SHA2-128f | 1.23 ms | 902.1 µs | — |
| slh-dsa/verify/SHA2-256f | 1.94 ms | 1.74 ms | — |
| slh-dsa/verify/SHAKE-128f | 2.19 ms | 3.08 ms | — |

---

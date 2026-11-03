# KMS Performance Comparison

**Versions**: `v5.29.0`
**Generated**: 2026-10-29

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-29 14:02:34 UTC |
| HSM backend | SoftHSM2 |
| Command | `mise run bench:hsm --hsm-model softhsm2` |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 4,034 MHz |
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
CPU(s) scaling MHz:                      32%
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
| 1 | 3,767 | 3,779 | 22,970 |
| 2 | 4,503 | 5,367 | 39,546 |
| 4 | 6,957 | 7,372 | 62,499 |
| 8 | 7,851 | 6,321 | 78,374 |
| 16 | 3,169 | 2,800 | 103,682 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 3,666 | 3,711 | 12,691 |
| 2 | 4,354 | 3,153 | 21,587 |
| 4 | 7,475 | 7,636 | 35,579 |
| 8 | 7,800 | 6,180 | 48,019 |
| 16 | 2,930 | 2,798 | 65,471 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 3,545 | 3,746 | 12,547 |
| 2 | 3,837 | 4,664 | 21,878 |
| 4 | 5,496 | 8,048 | 35,544 |
| 8 | 5,385 | 5,950 | 48,838 |
| 16 | 2,802 | 4,646 | 69,395 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,061 | 2,030 |
| 2 | 3,197 | 3,232 |
| 4 | 5,041 | 5,104 |
| 8 | 6,167 | 6,174 |
| 16 | 5,408 | 5,537 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,165 |
| 2 | 1,679 |
| 4 | 3,627 |
| 8 | 3,007 |
| 16 | 4,332 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 917 |
| 2 | 1,527 |
| 4 | 2,446 |
| 8 | 3,669 |
| 16 | 5,608 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 850.7 µs | 851.2 µs | — |
| aes-gcm-siv/decrypt/256 | 391.5 µs | 804.1 µs | — |
| aes-gcm-siv/encrypt/128 | 788.4 µs | 540.0 µs | — |
| aes-gcm-siv/encrypt/256 | 351.0 µs | 462.5 µs | — |
| aes-gcm/decrypt/128 | 832.0 µs | 321.2 µs | 38.8 µs |
| aes-gcm/decrypt/192 | 253.6 µs | 674.0 µs | 36.5 µs |
| aes-gcm/decrypt/256 | 883.9 µs | 783.6 µs | 40.5 µs |
| aes-gcm/encrypt/128 | 830.5 µs | 1.01 ms | 39.5 µs |
| aes-gcm/encrypt/192 | 830.8 µs | 681.6 µs | 39.7 µs |
| aes-gcm/encrypt/256 | 201.9 µs | 721.1 µs | 38.0 µs |
| aes-xts/decrypt/128 | 280.5 µs | 514.1 µs | — |
| aes-xts/decrypt/256 | 841.6 µs | 773.5 µs | — |
| aes-xts/encrypt/128 | 172.6 µs | 568.2 µs | — |
| aes-xts/encrypt/256 | 824.9 µs | 655.1 µs | — |
| chacha20-poly1305/decrypt/256 | 290.6 µs | 680.3 µs | — |
| chacha20-poly1305/encrypt/256 | 204.5 µs | 740.1 µs | — |
| salsa-sealed-box/decrypt | 347.1 µs | 262.2 µs | — |
| salsa-sealed-box/encrypt | 293.1 µs | 253.8 µs | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 302.7 µs | 249.4 µs |
| ecies/decrypt/P-384 | 1.19 ms | 1.18 ms |
| ecies/decrypt/P-521 | 2.41 ms | 2.40 ms |
| ecies/encrypt/P-256 | 389.9 µs | 383.1 µs |
| ecies/encrypt/P-384 | 1.20 ms | 1.28 ms |
| ecies/encrypt/P-521 | 2.33 ms | 2.40 ms |
| rsa-aes-kwp/decrypt/4096 | 167.01 ms | 164.85 ms |
| rsa-aes-kwp/encrypt/4096 | 320.9 µs | 287.4 µs |
| rsa-oaep/decrypt/4096 | 166.50 ms | 176.51 ms |
| rsa-oaep/encrypt/4096 | 358.2 µs | 361.7 µs |
| rsa-pkcs1v15/decrypt/4096 | 164.63 ms | 163.55 ms |
| rsa-pkcs1v15/encrypt/4096 | 345.3 µs | 278.7 µs |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| configurable/decapsulate/ML-KEM-512 | 355.6 µs | 471.2 µs |
| configurable/decapsulate/ML-KEM-512/P-256 | 469.3 µs | 564.0 µs |
| configurable/decapsulate/ML-KEM-768 | 465.6 µs | 414.1 µs |
| configurable/decapsulate/ML-KEM-768/P-256 | 614.4 µs | 524.4 µs |
| configurable/encapsulate/ML-KEM-512 | 316.7 µs | 281.0 µs |
| configurable/encapsulate/ML-KEM-512/P-256 | 468.8 µs | 451.0 µs |
| configurable/encapsulate/ML-KEM-768 | 340.1 µs | 339.7 µs |
| configurable/encapsulate/ML-KEM-768/P-256 | 518.3 µs | 607.9 µs |
| pqc/decapsulate/ML-KEM-1024 | 422.3 µs | 529.3 µs |
| pqc/decapsulate/ML-KEM-512 | 309.6 µs | 383.1 µs |
| pqc/decapsulate/ML-KEM-768 | 445.6 µs | 407.6 µs |
| pqc/decapsulate/X25519MLKEM768 | 430.2 µs | 758.9 µs |
| pqc/encapsulate/ML-KEM-1024 | 544.3 µs | 410.8 µs |
| pqc/encapsulate/ML-KEM-512 | 228.9 µs | 681.1 µs |
| pqc/encapsulate/ML-KEM-768 | 243.5 µs | 346.4 µs |
| pqc/encapsulate/X25519MLKEM768 | 373.1 µs | 622.7 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| covercrypt/master-keypair | 22.53 ms |
| ec/ed25519 | 943.2 µs |
| ec/ed448 | 887.7 µs |
| ec/p256 | 1.11 ms |
| ec/p384 | 1.19 ms |
| ec/p521 | 1.70 ms |
| ec/secp256k1 | 919.5 µs |
| kem/ML-KEM-512 | 885.7 µs |
| kem/ML-KEM-512/P-256 | 896.1 µs |
| kem/ML-KEM-512/X25519 | 2.52 ms |
| kem/ML-KEM-768 | 1.09 ms |
| kem/ML-KEM-768/P-256 | 944.5 µs |
| kem/ML-KEM-768/X25519 | 2.46 ms |
| pqc/ML-DSA-44 | 1.59 ms |
| pqc/ML-DSA-65 | 1.55 ms |
| pqc/ML-DSA-87 | 1.70 ms |
| pqc/ML-KEM-1024 | 1.27 ms |
| pqc/ML-KEM-512 | 1.07 ms |
| pqc/ML-KEM-768 | 1.22 ms |
| pqc/X25519MLKEM768 | 766.9 µs |
| pqc/X448MLKEM1024 | 1.01 ms |
| rsa/rsa-4096 | 264.97 ms |
| symmetric/aes-128 | 802.8 µs |
| symmetric/aes-192 | 804.1 µs |
| symmetric/aes-256 | 741.5 µs |
| symmetric/chacha20-256 | 980.1 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 342.8 µs | 284.1 µs | 92.0 µs |
| ecdsa-p256/verify | 351.1 µs | 275.0 µs | 261.7 µs |
| ecdsa-p384/sign | 1.29 ms | 1.31 ms | 935.1 µs |
| ecdsa-p384/verify | 704.5 µs | 711.5 µs | 619.5 µs |
| ecdsa-p521/sign | 2.42 ms | 4.21 ms | — |
| ecdsa-p521/verify | 1.33 ms | 1.77 ms | — |
| ecdsa-secp256k1/sign | 515.9 µs | 538.6 µs | — |
| ecdsa-secp256k1/verify | 488.7 µs | 498.3 µs | — |
| eddsa-ed25519/sign | 250.7 µs | 366.7 µs | 88.5 µs |
| eddsa-ed25519/verify | 280.3 µs | 313.1 µs | 707.9 µs |
| eddsa-ed448/sign | 457.8 µs | 458.4 µs | — |
| eddsa-ed448/verify | 543.7 µs | 337.0 µs | — |
| ml-dsa/sign/44 | 773.9 µs | 839.5 µs | — |
| ml-dsa/sign/65 | 1.05 ms | 1.30 ms | — |
| ml-dsa/sign/87 | 1.23 ms | 1.22 ms | — |
| ml-dsa/verify/44 | 545.1 µs | 862.9 µs | — |
| ml-dsa/verify/65 | 526.2 µs | 392.4 µs | — |
| ml-dsa/verify/87 | 482.3 µs | 490.8 µs | — |
| rsa-pkcs1v15/sign | — | — | 25.58 ms |
| rsa-pkcs1v15/verify | — | — | 809.9 µs |
| rsa-pss/sign | — | — | 23.80 ms |
| rsa-pss/sign/4096 | 165.57 ms | 170.26 ms | — |
| rsa-pss/verify | — | — | 677.0 µs |
| rsa-pss/verify/4096 | 305.4 µs | 327.5 µs | — |
| slh-dsa/sign/SHA2-128f | 10.09 ms | 9.50 ms | — |
| slh-dsa/sign/SHA2-256f | 35.13 ms | 36.34 ms | — |
| slh-dsa/sign/SHAKE-128f | 25.15 ms | 24.99 ms | — |
| slh-dsa/sign/SHAKE-256f | 80.83 ms | 80.43 ms | — |
| slh-dsa/verify/SHA2-128f | 1.21 ms | 927.5 µs | — |
| slh-dsa/verify/SHA2-256f | 2.02 ms | 1.62 ms | — |
| slh-dsa/verify/SHAKE-128f | 2.78 ms | 3.12 ms | — |
| slh-dsa/verify/SHAKE-256f | 3.26 ms | 3.08 ms | — |

---

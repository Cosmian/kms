# KMS Performance Comparison

**Versions**: `v5.27.1`  
**Generated**: 2026-09-13

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-13 11:01:13 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 2,244 MHz |
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
CPU(s) scaling MHz:                      44%
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
| 1 | 1,981 | 2,389 | 11,853 |
| 2 | 3,636 | 4,354 | 21,011 |
| 4 | 6,296 | 7,424 | 32,910 |
| 8 | 10,121 | 12,190 | 54,667 |
| 16 | 15,233 | 18,166 | 74,682 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,471 | 1,503 | 1,588 |
| 2 | 2,760 | 2,799 | 2,955 |
| 4 | 4,892 | 4,832 | 5,101 |
| 8 | 8,158 | 8,160 | 8,561 |
| 16 | 12,605 | 12,551 | 13,456 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 6,040 | 6,190 | 7,620 |
| 2 | 11,180 | 11,102 | 13,838 |
| 4 | 18,276 | 18,377 | 23,131 |
| 8 | 31,078 | 30,636 | 38,255 |
| 16 | 44,336 | 44,168 | 55,177 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 2,885 |
| 2 | 3,161 |
| 4 | 4,080 |
| 8 | 5,388 |
| 16 | 4,971 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 236 |
| 2 | 443 |
| 4 | 775 |
| 8 | 1,228 |
| 16 | 1,873 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 189.6 µs | 157.3 µs | — |
| aes-gcm-siv/decrypt/256 | 180.7 µs | 165.6 µs | — |
| aes-gcm-siv/encrypt/128 | 175.6 µs | 175.8 µs | — |
| aes-gcm-siv/encrypt/256 | 194.3 µs | 194.3 µs | — |
| aes-gcm/decrypt/128 | 181.8 µs | 188.3 µs | 80.9 µs |
| aes-gcm/decrypt/192 | 171.3 µs | 164.4 µs | 117.7 µs |
| aes-gcm/decrypt/256 | 170.0 µs | 158.6 µs | 130.2 µs |
| aes-gcm/encrypt/128 | 146.5 µs | 174.8 µs | 75.3 µs |
| aes-gcm/encrypt/192 | 168.6 µs | 155.5 µs | 105.2 µs |
| aes-gcm/encrypt/256 | 166.1 µs | 198.6 µs | 105.9 µs |
| aes-xts/decrypt/128 | 150.0 µs | 176.9 µs | — |
| aes-xts/decrypt/256 | 173.0 µs | 171.6 µs | — |
| aes-xts/encrypt/128 | 198.0 µs | 123.7 µs | — |
| aes-xts/encrypt/256 | 179.2 µs | 184.7 µs | — |
| chacha20-poly1305/decrypt/256 | 133.4 µs | 159.1 µs | — |
| chacha20-poly1305/encrypt/256 | 171.3 µs | 170.3 µs | — |
| salsa-sealed-box/decrypt | 328.4 µs | 317.5 µs | — |
| salsa-sealed-box/encrypt | 1.19 s | 1.34 s | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 245.7 µs | 303.1 µs |
| ecies/encrypt/P-256 | 1.18 s | 1.33 s |
| ecies/encrypt/P-384 | 1.23 s | 1.36 s |
| rsa-aes-kwp/decrypt/4096 | 243.91 ms | 246.74 ms |
| rsa-aes-kwp/encrypt/4096 | 1.24 s | 1.37 s |
| rsa-oaep/decrypt/4096 | 241.63 ms | 242.95 ms |
| rsa-oaep/encrypt/4096 | 1.25 s | 1.36 s |
| rsa-pkcs1v15/decrypt/4096 | 245.36 ms | 246.34 ms |
| rsa-pkcs1v15/encrypt/4096 | 1.21 s | 1.33 s |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-512 | 287.5 µs | 360.8 µs |
| pqc/encapsulate/ML-KEM-512 | 1.20 s | 1.32 s |
| pqc/encapsulate/ML-KEM-768 | 1.20 s | 1.34 s |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 1.10 ms |
| ec/ed448 | 1.19 ms |
| ec/p256 | 1.11 ms |
| ec/p384 | 2.13 ms |
| ec/p521 | 2.79 ms |
| ec/secp256k1 | 1.32 ms |
| pqc/ML-DSA-44 | 1.55 ms |
| pqc/ML-DSA-65 | 1.75 ms |
| pqc/ML-DSA-87 | 2.12 ms |
| pqc/ML-KEM-1024 | 1.60 ms |
| pqc/ML-KEM-512 | 1.31 ms |
| pqc/ML-KEM-768 | 1.39 ms |
| rsa/rsa-4096 | 691.40 ms |
| symmetric/aes-128 | 536.8 µs |
| symmetric/aes-192 | 548.2 µs |
| symmetric/aes-256 | 504.0 µs |
| symmetric/chacha20-256 | 528.4 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 881.5 µs | 905.3 µs | 846.4 µs |
| ecdsa-p256/verify | 1.32 s | 1.53 s | 1.53 s |
| ecdsa-p384/sign | 1.61 ms | 2.00 ms | 1.58 ms |
| ecdsa-p384/verify | 1.36 s | 1.49 s | 1.50 s |
| ecdsa-p521/sign | 3.79 ms | 3.67 ms | — |
| ecdsa-p521/verify | 1.32 s | 1.49 s | — |
| ecdsa-secp256k1/sign | 897.6 µs | 866.0 µs | — |
| ecdsa-secp256k1/verify | 1.32 s | 1.55 s | — |
| eddsa-ed25519/sign | 232.1 µs | 259.2 µs | 178.2 µs |
| eddsa-ed25519/verify | 1.36 s | 1.50 s | 1.51 s |
| eddsa-ed448/sign | 564.4 µs | 711.3 µs | — |
| eddsa-ed448/verify | 1.35 s | 1.49 s | — |
| ml-dsa/sign/44 | 949.7 µs | 1.05 ms | — |
| ml-dsa/sign/65 | 1.73 ms | 1.33 ms | — |
| ml-dsa/verify/44 | 1.32 s | 1.51 s | — |
| ml-dsa/verify/65 | 1.36 s | 1.49 s | — |
| rsa-pkcs1v15/sign | — | — | 36.16 ms |
| rsa-pkcs1v15/verify | — | — | 1.49 s |
| rsa-pss/sign | — | — | 35.98 ms |
| rsa-pss/sign/4096 | 245.76 ms | 245.43 ms | — |
| rsa-pss/verify | — | — | 1.50 s |
| rsa-pss/verify/4096 | 1.32 s | 1.53 s | — |
| slh-dsa/sign/SHA2-128f | 14.30 ms | 13.90 ms | — |
| slh-dsa/sign/SHA2-256f | 53.01 ms | 53.07 ms | — |
| slh-dsa/verify/SHA2-128f | 1.35 s | 1.51 s | — |
| slh-dsa/verify/SHA2-256f | 1.33 s | — | — |

---

# KMS Performance Comparison

**Versions**: `v5.27.0`
**Generated**: 2026-09-08

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-08 11:26:26 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 801 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.4 LTS |
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
CPU(s) scaling MHz:                      40%
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
| 1 | 1,778 | 2,438 | 11,495 |
| 2 | 3,124 | 4,440 | 19,985 |
| 4 | 6,118 | 7,548 | 32,781 |
| 8 | 10,366 | 12,322 | 52,733 |
| 16 | 15,497 | 18,441 | 74,344 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 1,510 | 1,478 | 1,611 |
| 2 | 2,700 | 2,673 | 2,942 |
| 4 | 4,704 | 4,776 | 5,084 |
| 8 | 8,048 | 7,995 | 8,575 |
| 16 | 12,606 | 12,504 | 13,315 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 6,139 | 5,643 | 7,270 |
| 2 | 10,420 | 10,840 | 12,803 |
| 4 | 18,322 | 18,436 | 22,142 |
| 8 | 30,487 | 30,684 | 37,417 |
| 16 | 45,346 | 44,640 | 55,108 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 2,714 |
| 2 | 3,177 |
| 4 | 3,618 |
| 8 | 5,092 |
| 16 | 4,668 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 247 |
| 2 | 452 |
| 4 | 774 |
| 8 | 1,286 |
| 16 | 1,918 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 179.4 µs | 190.4 µs | — |
| aes-gcm-siv/decrypt/256 | 182.2 µs | 181.8 µs | — |
| aes-gcm-siv/encrypt/128 | 175.0 µs | 197.2 µs | — |
| aes-gcm-siv/encrypt/256 | 192.3 µs | 180.4 µs | — |
| aes-gcm/decrypt/128 | 174.3 µs | 146.8 µs | 127.7 µs |
| aes-gcm/decrypt/192 | 182.6 µs | 149.8 µs | 128.3 µs |
| aes-gcm/decrypt/256 | 166.5 µs | 160.5 µs | 122.8 µs |
| aes-gcm/encrypt/128 | 168.0 µs | 163.3 µs | 120.5 µs |
| aes-gcm/encrypt/192 | 182.1 µs | 204.8 µs | 125.1 µs |
| aes-gcm/encrypt/256 | 218.0 µs | 183.3 µs | 108.6 µs |
| aes-xts/decrypt/128 | 188.7 µs | 158.4 µs | — |
| aes-xts/decrypt/256 | 172.7 µs | 145.8 µs | — |
| aes-xts/encrypt/128 | 154.5 µs | 160.4 µs | — |
| aes-xts/encrypt/256 | 164.3 µs | 185.6 µs | — |
| chacha20-poly1305/decrypt/256 | 170.3 µs | 177.7 µs | — |
| chacha20-poly1305/encrypt/256 | 198.9 µs | 187.9 µs | — |
| salsa-sealed-box/decrypt | 328.1 µs | 321.9 µs | — |
| salsa-sealed-box/encrypt | 1.12 s | 1.33 s | — |

---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 298.5 µs | 352.8 µs |
| ecies/encrypt/P-256 | 1.12 s | 1.32 s |
| ecies/encrypt/P-384 | 1.20 s | 1.29 s |
| rsa-aes-kwp/decrypt/4096 | 249.94 ms | 248.72 ms |
| rsa-aes-kwp/encrypt/4096 | 1.22 s | 1.26 s |
| rsa-oaep/decrypt/4096 | 227.37 ms | 252.40 ms |
| rsa-oaep/encrypt/4096 | 1.21 s | 1.36 s |
| rsa-pkcs1v15/decrypt/4096 | 259.11 ms | 245.29 ms |
| rsa-pkcs1v15/encrypt/4096 | 1.14 s | 1.31 s |

---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-512 | 364.9 µs | 267.1 µs |
| pqc/encapsulate/ML-KEM-512 | 1.15 s | 1.30 s |
| pqc/encapsulate/ML-KEM-768 | 1.20 s | 1.29 s |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 1.03 ms |
| ec/ed448 | 1.31 ms |
| ec/p256 | 1.05 ms |
| ec/p384 | 1.93 ms |
| ec/p521 | 3.25 ms |
| ec/secp256k1 | 1.43 ms |
| pqc/ML-DSA-44 | 1.42 ms |
| pqc/ML-DSA-65 | 2.02 ms |
| pqc/ML-DSA-87 | 2.07 ms |
| pqc/ML-KEM-1024 | 1.53 ms |
| pqc/ML-KEM-512 | 1.31 ms |
| pqc/ML-KEM-768 | 1.34 ms |
| rsa/rsa-4096 | 336.83 ms |
| symmetric/aes-128 | 547.7 µs |
| symmetric/aes-192 | 531.4 µs |
| symmetric/aes-256 | 505.6 µs |
| symmetric/chacha20-256 | 503.1 µs |

---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 861.2 µs | 832.8 µs | 762.2 µs |
| ecdsa-p256/verify | 1.30 s | 1.44 s | 1.46 s |
| ecdsa-p384/sign | 2.01 ms | 2.16 ms | 1.93 ms |
| ecdsa-p384/verify | 1.23 s | 1.43 s | 1.51 s |
| ecdsa-p521/sign | 3.77 ms | 3.77 ms | — |
| ecdsa-p521/verify | 1.25 s | 1.48 s | — |
| ecdsa-secp256k1/sign | 890.1 µs | 901.2 µs | — |
| ecdsa-secp256k1/verify | 1.33 s | 1.46 s | — |
| eddsa-ed25519/sign | 246.4 µs | 260.2 µs | 197.4 µs |
| eddsa-ed25519/verify | 1.28 s | 1.53 s | 1.47 s |
| eddsa-ed448/sign | 716.5 µs | 748.4 µs | — |
| eddsa-ed448/verify | 1.28 s | 1.50 s | — |
| ml-dsa/sign/44 | 961.8 µs | 1.10 ms | — |
| ml-dsa/sign/65 | 1.61 ms | 1.44 ms | — |
| ml-dsa/verify/44 | 1.27 s | 1.47 s | — |
| ml-dsa/verify/65 | 1.27 s | 1.46 s | — |
| rsa-pkcs1v15/sign | — | — | 38.16 ms |
| rsa-pkcs1v15/verify | — | — | 1.50 s |
| rsa-pss/sign | — | — | 36.63 ms |
| rsa-pss/sign/4096 | 247.44 ms | 249.45 ms | — |
| rsa-pss/verify | — | — | 1.47 s |
| rsa-pss/verify/4096 | 1.29 s | 1.49 s | — |
| slh-dsa/sign/SHA2-128f | 14.26 ms | 14.26 ms | — |
| slh-dsa/sign/SHA2-256f | 53.31 ms | 52.62 ms | — |
| slh-dsa/verify/SHA2-128f | 1.32 s | 1.52 s | — |
| slh-dsa/verify/SHA2-256f | 1.32 s | — | — |

---

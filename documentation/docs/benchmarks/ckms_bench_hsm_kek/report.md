# KMS Performance Comparison

**Versions**: `v5.27.1`  
**Generated**: 2026-09-22

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-22 16:43:19 UTC |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 2,677 MHz |
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
CPU(s) scaling MHz:                      25%
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
| 1 | 2,985 | 3,598 | 18,229 |
| 2 | 5,431 | 6,488 | 31,726 |
| 4 | 8,681 | 10,537 | 49,772 |
| 8 | 12,697 | 15,000 | 64,965 |
| 16 | 17,187 | 20,314 | 81,886 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 2,246 | 2,221 | 2,361 |
| 2 | 3,982 | 3,975 | 4,319 |
| 4 | 6,420 | 6,595 | 6,986 |
| 8 | 9,635 | 9,744 | 10,397 |
| 16 | 13,958 | 13,965 | 14,899 |

![Throughput — sign-verify/ecdsa-p256](load/sign-verify_ecdsa-p256.svg)

---

### sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) | jose (req/s) |
|---|---|---|---|
| 1 | 9,388 | 8,760 | 11,935 |
| 2 | 15,737 | 15,423 | 20,107 |
| 4 | 26,242 | 25,845 | 33,306 |
| 8 | 37,267 | 35,107 | 45,980 |
| 16 | 51,524 | 49,802 | 64,367 |

![Throughput — sign-verify/eddsa-ed25519](load/sign-verify_eddsa-ed25519.svg)

---

### sign-verify/ecdsa-secp256k1

| Concurrency | ttlv-json (req/s) | ttlv-bytes (req/s) |
|---|---|---|
| 1 | 2,452 | 2,505 |
| 2 | 4,447 | 4,100 |
| 4 | 7,292 | 7,203 |
| 8 | 10,420 | 10,325 |
| 16 | 14,050 | 13,923 |

![Throughput — sign-verify/ecdsa-secp256k1](load/sign-verify_ecdsa-secp256k1.svg)

---

### key-creation/aes-sym

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 4,107 |
| 2 | 2,058 |
| 4 | 3,030 |
| 8 | 5,425 |
| 16 | 4,066 |

![Throughput — key-creation/aes-sym](load/key-creation_aes-sym.svg)

---

### batch/aes-gcm-10

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 352 |
| 2 | 558 |
| 4 | 1,027 |
| 8 | 1,561 |
| 16 | 2,089 |

![Throughput — batch/aes-gcm-10](load/batch_aes-gcm-10.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| aes-gcm-siv/decrypt/128 | 96.9 µs | 80.1 µs | — |
| aes-gcm-siv/decrypt/256 | 89.4 µs | 85.1 µs | — |
| aes-gcm-siv/encrypt/128 | 82.7 µs | 88.2 µs | — |
| aes-gcm-siv/encrypt/256 | 78.9 µs | 91.4 µs | — |
| aes-gcm/decrypt/128 | 82.0 µs | 80.1 µs | 46.4 µs |
| aes-gcm/decrypt/192 | 82.2 µs | 103.8 µs | 50.2 µs |
| aes-gcm/decrypt/256 | 90.6 µs | 85.0 µs | 49.3 µs |
| aes-gcm/encrypt/128 | 82.9 µs | 86.1 µs | 54.6 µs |
| aes-gcm/encrypt/192 | 86.5 µs | 84.6 µs | 48.1 µs |
| aes-gcm/encrypt/256 | 107.3 µs | 105.6 µs | 47.3 µs |
| aes-xts/decrypt/128 | 80.5 µs | 76.9 µs | — |
| aes-xts/decrypt/256 | 76.8 µs | 84.3 µs | — |
| aes-xts/encrypt/128 | 83.9 µs | 83.7 µs | — |
| aes-xts/encrypt/256 | 89.0 µs | 93.2 µs | — |
| chacha20-poly1305/decrypt/256 | 79.7 µs | 79.1 µs | — |
| chacha20-poly1305/encrypt/256 | 85.8 µs | 86.9 µs | — |
| salsa-sealed-box/decrypt | 162.3 µs | 160.7 µs | — |
| salsa-sealed-box/encrypt | 680.00 ms | 851.75 ms | — |


---

### Asymmetric Encryption

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| ecies/decrypt/P-256 | 157.7 µs | 164.1 µs |
| ecies/decrypt/P-384 | 1.05 ms | 990.4 µs |
| ecies/encrypt/P-256 | 680.81 ms | 804.18 ms |
| ecies/encrypt/P-384 | 710.84 ms | 857.04 ms |
| rsa-aes-kwp/decrypt/4096 | 176.30 ms | 170.99 ms |
| rsa-aes-kwp/encrypt/4096 | 735.02 ms | 857.43 ms |
| rsa-oaep/decrypt/4096 | 178.55 ms | 166.14 ms |
| rsa-oaep/encrypt/4096 | 723.89 ms | 851.88 ms |
| rsa-pkcs1v15/decrypt/4096 | 179.48 ms | 168.14 ms |
| rsa-pkcs1v15/encrypt/4096 | 698.48 ms | 832.89 ms |


---

### Key Encapsulation (KEM)

| Benchmark | ttlv-json | ttlv-bytes |
|---|---|---|
| pqc/decapsulate/ML-KEM-512 | 169.8 µs | 165.7 µs |
| pqc/decapsulate/ML-KEM-768 | 209.1 µs | 195.5 µs |
| pqc/encapsulate/ML-KEM-512 | 705.64 ms | 814.39 ms |
| pqc/encapsulate/ML-KEM-768 | 701.92 ms | 812.20 ms |


---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| EC/ES256 | — |
| EC/ES384 | — |
| RSA/2048 | — |
| aes-gcm/oct/128 | — |
| aes-gcm/oct/256 | — |
| ec/ed25519 | 581.3 µs |
| ec/ed448 | 905.4 µs |
| ec/p256 | 621.1 µs |
| ec/p384 | 1.28 ms |
| ec/p521 | 1.60 ms |
| ec/secp256k1 | 789.3 µs |
| pqc/ML-DSA-44 | 876.2 µs |
| pqc/ML-DSA-65 | 1.04 ms |
| pqc/ML-DSA-87 | 1.42 ms |
| pqc/ML-KEM-1024 | 879.1 µs |
| pqc/ML-KEM-512 | 993.6 µs |
| pqc/ML-KEM-768 | 883.2 µs |
| pqc/SLH-DSA-SHA2-128f | 1.07 ms |
| pqc/SLH-DSA-SHA2-256f | 2.54 ms |
| rsa/rsa-4096 | 291.06 ms |
| symmetric/aes-128 | 414.4 µs |
| symmetric/aes-192 | 432.0 µs |
| symmetric/aes-256 | 478.0 µs |
| symmetric/chacha20-256 | 335.2 µs |


---

### Sign / Verify

| Benchmark | ttlv-json | ttlv-bytes | jose |
|---|---|---|---|
| ecdsa-p256/sign | 511.8 µs | 562.3 µs | 434.4 µs |
| ecdsa-p256/verify | 816.00 ms | 1.02 s | 953.37 ms |
| ecdsa-p384/sign | 1.06 ms | 1.04 ms | 1.02 ms |
| ecdsa-p384/verify | 879.20 ms | 1.02 s | 1.02 s |
| ecdsa-p521/sign | 2.55 ms | 2.29 ms | — |
| ecdsa-p521/verify | 823.70 ms | 974.74 ms | — |
| ecdsa-secp256k1/sign | 432.1 µs | 426.0 µs | — |
| ecdsa-secp256k1/verify | 846.43 ms | 953.09 ms | — |
| eddsa-ed25519/sign | 127.4 µs | 124.2 µs | 114.5 µs |
| eddsa-ed25519/verify | 869.62 ms | 1.02 s | 985.71 ms |
| eddsa-ed448/sign | 289.9 µs | 306.5 µs | — |
| eddsa-ed448/verify | 832.07 ms | 957.84 ms | — |
| ml-dsa/sign/44 | 624.5 µs | 522.5 µs | — |
| ml-dsa/sign/65 | 1.15 ms | 826.8 µs | — |
| ml-dsa/verify/44 | 869.12 ms | 995.55 ms | — |
| ml-dsa/verify/65 | 855.11 ms | 950.38 ms | — |
| rsa-pkcs1v15/sign | — | — | 23.66 ms |
| rsa-pkcs1v15/verify | — | — | 952.65 ms |
| rsa-pss/sign | — | — | 24.73 ms |
| rsa-pss/sign/4096 | 177.12 ms | 175.45 ms | — |
| rsa-pss/verify | — | — | 1.01 s |
| rsa-pss/verify/4096 | 819.92 ms | 993.95 ms | — |
| slh-dsa/sign/SHA2-128f | 10.19 ms | 9.46 ms | — |
| slh-dsa/sign/SHA2-256f | 35.61 ms | 35.23 ms | — |
| slh-dsa/verify/SHA2-128f | 863.49 ms | 1.01 s | — |
| slh-dsa/verify/SHA2-256f | 813.88 ms | 974.18 ms | — |


---


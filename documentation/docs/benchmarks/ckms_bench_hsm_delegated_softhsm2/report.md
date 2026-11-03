# KMS Performance Comparison

**Versions**: `v5.29.0`
**Generated**: 2026-10-29

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-29 14:38:42 UTC |
| HSM backend | SoftHSM2 |
| Command | `mise run bench:hsm --delegated --hsm-model softhsm2` |
| Build | release / non-fips |
| HTTP workers (Actix-web) | 32 |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 2,446 MHz |
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
CPU(s) scaling MHz:                      29%
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
        ckms["<b>ckms bench --hsm</b>"]
    end

    subgraph srv["Local KMS Server"]
        kmip["KMIP 2.1<br/>(HTTP)"]
        oracle["CryptoOracle<br/>(HSM Router)"]
    end

    subgraph hsm["SoftHSM2"]
        pkcs11["PKCS#11 Slot"]
        hsm_keys["RSA<br/>ECDSA<br/>EdDSA<br/>AES<br/>(HSM-resident)"]
    end

    ckms -->|HTTP| kmip
    kmip --> oracle
    oracle -->|C_Sign/C_Encrypt/C_GenerateKey| pkcs11
    pkcs11 --> hsm_keys

    style ckms fill:#4A90E2
    style kmip fill:#7ED321
    style oracle fill:#FF6B6B
    style pkcs11 fill:#BD10E0
```

**Components**:

- **ckms**: Concurrent load generator (`mise run bench:hsm --delegated --hsm-model softhsm2`)
- **KMIP Endpoint**: HTTP protocol handler
- **CryptoOracle**: Routes crypto ops directly to SoftHSM2 (no software fallback)
- **PKCS#11 Slot**: SoftHSM2 engine for C_Sign/C_Encrypt/C_GenerateKey operations
- **HSM-Resident Keys**: Keys generated on and never leave hardware

---

## Protocols

This report benchmarks cryptographic operations delegated to an HSM (SoftHSM2) via the KMS `CryptoOracle`, exercised over a single wire protocol: **ttlv-json**.

| Protocol | Transport | Encoding | Endpoint | Description |
|---|---|---|---|---|
| **ttlv-json** | HTTP/1.1 | KMIP 2.1 JSON-TTLV | `POST /kmip/2_1` | Primary interoperability protocol — any KMIP 2.1 compliant client can use it |

**KMIP TTLV** (Tag-Type-Length-Value) is the native encoding of the KMIP 2.1 standard (OASIS KMIP Spec v2.1, §9.1). The **JSON** variant wraps every field in a `{"tag": …, "type": …, "value": …}` JSON object and base64-encodes binary values.

**ttlv-bytes is not benchmarked here.** Measuring it would require running it either against the same HSM-resident key/token as the ttlv-json sweep (strictly after it completes) or on a fresh token started specifically for that purpose. The former was tried first and rejected: cumulative SoftHSM2 token load from the preceding ttlv-json sweep contaminated every ttlv-bytes measurement, making ttlv-json appear *faster* than ttlv-bytes in every single operation — the opposite of the software baseline (where ttlv-bytes is consistently faster, as expected, since it skips JSON parsing). Rather than publish numbers that are measurement artefacts of test ordering, ttlv-bytes is omitted from this report until the harness can measure both protocols under equivalent conditions (e.g. independent tokens per protocol).

**JOSE is not benchmarked here.** The JOSE REST key-creation endpoint (`POST /v1/crypto/keys`) has no parameter to request a caller-chosen `kid`, and HSM-resident key delegation requires the client to choose the `hsm::<slot>::<uuid>` unique identifier up front (the HSM has no server-assigned ID scheme) — so an HSM-resident key cannot be created through the JOSE endpoints at all.

---

## Benchmark Methodology

### HSM delegation model

Every operation in this report is executed against an `hsm::<slot>::<uuid>` unique identifier. The KMS server routes both key generation (`Create`/`CreateKeyPair`) and cryptographic operations (`Encrypt`/`Sign`) for such keys to the HSM's `CryptoOracle` (PKCS#11) on SoftHSM2 instead of executing them in KMS software — the benchmarked latency/throughput is therefore dominated by the PKCS#11 round-trip to the HSM, not by in-process OpenSSL.

> **HSM Backend:** SoftHSM2 (software PKCS#11 simulator). A hardware HSM will exhibit different absolute numbers bound by hardware crypto acceleration and transport latency.

### Algorithm coverage and SoftHSM2 constraints

Operations benchmarked in this scenario:

| Category | Algorithms covered | Notes |
|---|---|---|
| Encrypt | AES-GCM, AES-CBC, RSA-OAEP, RSA-PKCS1v15 | 2048-bit RSA, 256-bit AES |
| Sign | RSA-PSS, RSA-PKCS1v15 (SHA1/256/384/512) | 2048-bit RSA |
| Sign | ECDSA P-256 | Prehashed message digest |
| Sign | EdDSA Ed25519 / Ed448 | Non-FIPS pure un-hashed CKM_EDDSA |
| Key creation | AES-256, RSA-2048 | Dynamic unique identifiers per iteration |

### Payload sizes

All encrypt benchmarks use a **64-byte** fixed-size random payload (128 bytes for AES-CBC/PKCS1v15, which pad to a whole block); all sign benchmarks use a **32-byte** fixed-size message (or, for prehashed ECDSA, a 32-byte SHA-256 digest of that same message).

### SoftHSM2 per-token degradation (key creation only)

Concurrent/cumulative key generation against a single SoftHSM2 token progressively degrades that token in simulators. Key-creation concurrency is capped and mode isolation is applied.

### Why ttlv-json only (no ttlv-bytes)

An earlier version of this report benchmarked both `ttlv-json` and `ttlv-bytes` for every HSM-delegated operation, sharing one HSM-resident key between the two protocol variants and measuring `ttlv-json`'s full concurrency sweep before `ttlv-bytes`'s. Every single result inverted the expected direction — `ttlv-json` appeared *faster* than `ttlv-bytes`, the opposite of the software baseline (where binary TTLV is consistently faster, since it skips JSON parsing). This report therefore benchmarks `ttlv-json` only, until the harness can measure both protocols under equivalent conditions.

### Load test (`mise run bench:hsm --delegated --hsm-model softhsm2`)

The load test sweeps a configurable list of concurrency levels. At each level *N* concurrent async tasks send pre-serialised requests in tight loops for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase** (default: 5 s) that is excluded from measurements. Pre-serialisation happens once at setup time and the same bytes are reused on every iteration, isolating server-side (and HSM-side) latency from client-side encoding overhead. Recorded metrics per *(protocol, operation, concurrency)* triple:

- **Throughput** — requests per second (req/s)
- **p50 / p95 / p99** — round-trip latency percentiles (ms)

### Criterion micro-benchmarks (`ckms bench --hsm`)

Criterion (Rust, v0.5) measures the **round-trip latency of a single request** from the ckms client library through the KMS server (and onward to the HSM) and back over a loopback TCP connection.
 The reported value is the **mean ± 95 % confidence interval** over a configurable number of samples.

> **Infrastructure note:** The load test and criterion benchmarks both use a **local SQLite** backend (temporary, discarded after the run) for the KMS server metadata store — key material resides on SoftHSM2.

---

## Load Tests

### hsm/key-creation/aes-256

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 53 |
| 2 | 40 |
| 4 | 27 |

![Throughput — hsm/key-creation/aes-256](load/hsm_key-creation_aes-256.svg)

---

### hsm/key-creation/rsa-2048

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 4 |
| 2 | 7 |
| 4 | 7 |

![Throughput — hsm/key-creation/rsa-2048](load/hsm_key-creation_rsa-2048.svg)

---

### hsm/encrypt/aes-gcm

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 6,578 |
| 2 | 11,350 |
| 4 | 17,493 |
| 8 | 22,556 |
| 16 | 13,298 |

![Throughput — hsm/encrypt/aes-gcm](load/hsm_encrypt_aes-gcm.svg)

---

### hsm/encrypt/rsa-oaep

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 11,855 |
| 2 | 18,049 |
| 4 | 24,058 |
| 8 | 31,074 |
| 16 | 13,811 |

![Throughput — hsm/encrypt/rsa-oaep](load/hsm_encrypt_rsa-oaep.svg)

---

### hsm/encrypt/rsa-oaep-sha1

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 11,585 |
| 2 | 17,992 |
| 4 | 24,096 |
| 8 | 30,625 |
| 16 | 12,411 |

![Throughput — hsm/encrypt/rsa-oaep-sha1](load/hsm_encrypt_rsa-oaep-sha1.svg)

---

### hsm/encrypt/rsa-pkcs1v15

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 8,813 |
| 2 | 14,894 |
| 4 | 20,175 |
| 8 | 23,538 |
| 16 | 9,516 |

![Throughput — hsm/encrypt/rsa-pkcs1v15](load/hsm_encrypt_rsa-pkcs1v15.svg)

---

### hsm/encrypt/aes-cbc

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 6,723 |
| 2 | 11,434 |
| 4 | 17,820 |
| 8 | 22,942 |
| 16 | 15,559 |

![Throughput — hsm/encrypt/aes-cbc](load/hsm_encrypt_aes-cbc.svg)

---

### hsm/sign-verify/rsa-pss

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,503 |
| 2 | 2,581 |
| 4 | 4,171 |
| 8 | 6,019 |
| 16 | 7,270 |

![Throughput — hsm/sign-verify/rsa-pss](load/hsm_sign-verify_rsa-pss.svg)

---

### hsm/sign-verify/rsa-pkcs1v15-sha1

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,469 |
| 2 | 2,578 |
| 4 | 4,057 |
| 8 | 6,012 |
| 16 | 7,355 |

![Throughput — hsm/sign-verify/rsa-pkcs1v15-sha1](load/hsm_sign-verify_rsa-pkcs1v15-sha1.svg)

---

### hsm/sign-verify/rsa-pkcs1v15-sha256

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,515 |
| 2 | 2,581 |
| 4 | 4,071 |
| 8 | 6,061 |
| 16 | 7,354 |

![Throughput — hsm/sign-verify/rsa-pkcs1v15-sha256](load/hsm_sign-verify_rsa-pkcs1v15-sha256.svg)

---

### hsm/sign-verify/rsa-pkcs1v15-sha384

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,466 |
| 2 | 2,586 |
| 4 | 4,166 |
| 8 | 5,765 |
| 16 | 7,359 |

![Throughput — hsm/sign-verify/rsa-pkcs1v15-sha384](load/hsm_sign-verify_rsa-pkcs1v15-sha384.svg)

---

### hsm/sign-verify/rsa-pkcs1v15-sha512

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 1,512 |
| 2 | 2,592 |
| 4 | 4,063 |
| 8 | 6,015 |
| 16 | 7,414 |

![Throughput — hsm/sign-verify/rsa-pkcs1v15-sha512](load/hsm_sign-verify_rsa-pkcs1v15-sha512.svg)

---

### hsm/sign-verify/ecdsa-p256

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 10,416 |
| 2 | 17,115 |
| 4 | 26,818 |
| 8 | 30,120 |
| 16 | 27,278 |

![Throughput — hsm/sign-verify/ecdsa-p256](load/hsm_sign-verify_ecdsa-p256.svg)

---

### hsm/sign-verify/eddsa-ed25519

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 8,743 |
| 2 | 13,332 |
| 4 | 21,401 |
| 8 | 26,546 |
| 16 | 25,530 |

![Throughput — hsm/sign-verify/eddsa-ed25519](load/hsm_sign-verify_eddsa-ed25519.svg)

---

### hsm/sign-verify/eddsa-ed448

| Concurrency | ttlv-json (req/s) |
|---|---|
| 1 | 3,475 |
| 2 | 5,990 |
| 4 | 9,688 |
| 8 | 12,742 |
| 16 | 16,910 |

![Throughput — hsm/sign-verify/eddsa-ed448](load/hsm_sign-verify_eddsa-ed448.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | ttlv-json |
|---|---|
| hsm-aes-cbc/encrypt/256 | 102.2 µs |
| hsm-aes-gcm/encrypt/256 | 73.1 µs |

---

### Asymmetric Encryption

| Benchmark | ttlv-json |
|---|---|
| hsm-rsa-oaep-sha1/encrypt/2048 | 97.8 µs |
| hsm-rsa-oaep/encrypt/2048 | 110.2 µs |
| hsm-rsa-pkcs1v15/encrypt/2048 | 208.8 µs |

---

### Key Creation

| Benchmark | ttlv-json |
|---|---|
| hsm-aes-256/create | 71.70 ms |
| hsm-ec-p256/create | 204.80 ms |
| hsm-ed25519/create | 206.16 ms |
| hsm-ed448/create | 209.92 ms |
| hsm-rsa-2048/create | 261.41 ms |

---

### Sign / Verify

| Benchmark | ttlv-json |
|---|---|
| hsm-ecdsa-p256/sign | 140.9 µs |
| hsm-ecdsa-p384/sign | 622.0 µs |
| hsm-eddsa-ed25519/sign | 128.1 µs |
| hsm-eddsa-ed448/sign | 312.7 µs |
| hsm-rsa-pkcs1v15-sha1/sign/2048 | 697.0 µs |
| hsm-rsa-pkcs1v15-sha256/sign/2048 | 669.8 µs |
| hsm-rsa-pkcs1v15-sha384/sign/2048 | 664.3 µs |
| hsm-rsa-pkcs1v15-sha512/sign/2048 | 692.8 µs |
| hsm-rsa-pss/sign/2048 | 639.8 µs |

---

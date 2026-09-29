# KMS Performance Comparison

**Versions**: `v5.27.1`
**Generated**: 2026-09-25

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-25 01:12:50 UTC |
| Build | bench / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 3,732 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-142-generic |

### Load test parameters

| Parameter | Value |
|---|---|
| Mode | all |
| Protocols | pkcs11 |
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
CPU(s) scaling MHz:                      35%
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
    subgraph cli["Local Machine"]
        ckms["<b>ckms pkcs11 bench</b>"]
        lib["<b>cosmian_pkcs11.so</b><br/>(PKCS#11 Provider)"]
    end

    subgraph srv["KMS Server"]
        kmip["KMIP 2.1<br/>(HTTP/TLS)"]
        crypto["Software Crypto<br/>(OpenSSL 3.6.2)"]
    end

    subgraph hsm["SoftHSM2"]
        slot["PKCS#11 Slot"]
        keys["Test Keys"]
    end

    ckms -->|C_Initialize/C_Sign| lib
    lib -->|HTTP| kmip
    lib -->|PKCS#11| slot
    kmip --> crypto
    slot --> keys

    style ckms fill:#4A90E2
    style lib fill:#FF6B6B
    style kmip fill:#7ED321
    style crypto fill:#F5A623
    style slot fill:#BD10E0
```

**Components**:

- **ckms**: PKCS#11 load test generator
- **cosmian_pkcs11.so**: Bridge between PKCS#11 callers and KMIP server
- **KMIP Endpoint**: Server-side request/response marshaling
- **Software Crypto**: AES/RSA/ECDSA operations via OpenSSL
- **PKCS#11 Slot**: HSM backend for key storage

---

## Protocols

The caller-facing protocol benchmarked here is the `cosmian_pkcs11` provider's real PKCS#11 v3.1 Cryptoki C ABI: the benchmark `dlopen()`s the built shared library (`libcosmian_pkcs11.{so,dylib}`) and resolves its standard interface through `C_GetInterface` — the same call path v3-aware PKCS#11 consumers (Oracle TDE, OpenSSH, disk-encryption tools) use. For remote Sign, the provider wraps the KMIP operation in a KMIP 2.1 `RequestMessage`, serializes binary TTLV, and sends `application/octet-stream` to `POST /kmip`; the binary TTLV response is fully deserialized before `C_SignMessage` returns.

| Interface | Transport | Description |
|---|---|---|
| **PKCS#11 (Cryptoki v3.1)** | `C_GetInterface` + C ABI | `C_Initialize`, `C_OpenSession`, `C_EncryptInit`/`C_Encrypt`, `C_DecryptInit`/`C_Decrypt`, `C_MessageSignInit`/`C_SignMessage`, `C_VerifyInit`/`C_Verify`, `C_GenerateKey` |
| **Provider → KMS Sign** | KMIP 2.1 binary TTLV over HTTP | `POST /kmip`, `application/octet-stream` |

---

## Benchmark Methodology

### Real Cryptoki C ABI, one session per worker

The benchmark subcommand `ckms pkcs11 bench` (driven by `mise bench:load-pkcs11`) `dlopen()`s the built `cosmian_pkcs11` shared library, resolves the v3.1 function table through `C_GetInterface`, and calls it directly — the same code path a real PKCS#11 consumer application uses, as opposed to `mise bench:load`, which drives the KMIP REST API directly through the `ckms` client library.

By default each worker thread owns a dedicated `C_OpenSession` handle. The provider looks the handle up in its session map and serializes only access to that individual session with a per-session lock, so unrelated worker sessions can progress independently. `--shared-session` is an opt-in comparison mode that reproduces the former single-session contention model; it is not the default methodology.

For the Ed25519 Sign path measured in this report, `C_MessageSignInit` runs once during setup and each `C_SignMessage` crosses the synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`, serializes it as binary TTLV, sends it to the `/kmip` octet-stream endpoint, and parses the binary TTLV response before copying the signature into the caller-owned buffer.

### Independent operations

Unlike the software/HSM reports above, where `encrypt` and `sign-verify` each measure a single named request, this report measures every Cryptoki operation **independently**: `encrypt` (`C_EncryptInit`/`C_Encrypt`), `decrypt` (`C_DecryptInit`/`C_Decrypt`, against ciphertext produced once during setup — not timed), Ed25519 `sign` (`C_MessageSignInit` once + `C_SignMessage` per message), RSA `sign` (`C_SignInit`/`C_Sign`), `verify` (`C_VerifyInit`/`C_Verify`), and `key-creation` (`C_GenerateKey`+`C_DestroyObject`, ephemeral AES key per iteration) each get their own concurrency sweep and their own row/chart below.

`C_VerifyInit`/`C_Verify` are implemented and benchmarked through the same real Cryptoki function table. Verify rows are therefore ordinary measured operations, not placeholders or unsupported-operation probes.

`C_GenerateKeyPair` is not implemented either (asymmetric keys are always created through the KMS REST API, not PKCS#11), so `key-creation` only covers the one Cryptoki key-creation path the provider does support: symmetric `C_GenerateKey`.

### Load test (`mise bench:load-pkcs11`)

The load test sweeps a configurable list of concurrency levels, mirroring `mise bench:load`'s own sweep mechanics exactly: at each level *N* concurrent OS threads call the target Cryptoki function in a tight loop for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase** (default: 5 s) that is excluded from measurements, followed by a **cooldown** (default: 2 s) before the next level.
Recorded metrics per *(operation, concurrency)* pair:

- **Throughput** — Cryptoki calls per second
- **p50 / p95 / p99** — per-call latency percentiles (ms)

> **Infrastructure note:** The benchmark server uses a **local SQLite** backend (temporary, discarded after the run). Throughput figures will differ on a production deployment backed by PostgreSQL or Redis-Findex.

---

## Load Tests

### encrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,299 |
| 2 | 3,256 |
| 4 | 3,207 |
| 8 | 8,368 |
| 16 | 12,649 |

![Throughput — encrypt/aes-cbc](load/encrypt_aes-cbc.svg)

---

### encrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,363 |
| 2 | 3,322 |
| 4 | 3,570 |
| 8 | 8,093 |
| 16 | 12,620 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### encrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 12,683 |
| 2 | 10,363 |
| 4 | 6,314 |
| 8 | 40,169 |
| 16 | 55,882 |

![Throughput — encrypt/rsa-pkcs](load/encrypt_rsa-pkcs.svg)

---

### decrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,345 |
| 2 | 3,002 |
| 4 | 2,630 |
| 8 | 8,636 |
| 16 | 12,565 |

![Throughput — decrypt/aes-cbc](load/decrypt_aes-cbc.svg)

---

### decrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,353 |
| 2 | 2,825 |
| 4 | 3,488 |
| 8 | 8,394 |
| 16 | 12,560 |

![Throughput — decrypt/aes-gcm](load/decrypt_aes-gcm.svg)

---

### decrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 41 |
| 2 | 75 |
| 4 | 126 |
| 8 | 186 |
| 16 | 220 |

![Throughput — decrypt/rsa-pkcs](load/decrypt_rsa-pkcs.svg)

---

### sign/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 42 |
| 2 | 75 |
| 4 | 125 |
| 8 | 190 |
| 16 | 224 |

![Throughput — sign/rsa-pkcs-sha256](load/sign_rsa-pkcs-sha256.svg)

---

### sign/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 41 |
| 2 | 71 |
| 4 | 125 |
| 8 | 183 |
| 16 | 219 |

![Throughput — sign/rsa-pss-sha256](load/sign_rsa-pss-sha256.svg)

---

### sign/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 3,772 |
| 2 | 5,795 |
| 4 | 4,660 |
| 8 | 12,981 |
| 16 | 18,867 |

![Throughput — sign/ecdsa-p256](load/sign_ecdsa-p256.svg)

---

### sign/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,680 |
| 2 | 4,241 |
| 4 | 3,711 |
| 8 | 8,636 |
| 16 | 13,464 |

![Throughput — sign/ecdsa-secp256k1](load/sign_ecdsa-secp256k1.svg)

---

### sign/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 8,423 |
| 2 | 9,890 |
| 4 | 5,270 |
| 8 | 30,652 |
| 16 | 41,570 |

![Throughput — sign/eddsa-ed25519](load/sign_eddsa-ed25519.svg)

---

### verify/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 12,864 |
| 2 | 12,365 |
| 4 | 6,228 |
| 8 | 40,184 |
| 16 | 56,218 |

![Throughput — verify/rsa-pkcs-sha256](load/verify_rsa-pkcs-sha256.svg)

---

### verify/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 12,064 |
| 2 | 10,369 |
| 4 | 6,195 |
| 8 | 37,871 |
| 16 | 51,134 |

![Throughput — verify/rsa-pss-sha256](load/verify_rsa-pss-sha256.svg)

---

### verify/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,517 |
| 2 | 7,475 |
| 4 | 4,262 |
| 8 | 15,457 |
| 16 | 23,415 |

![Throughput — verify/ecdsa-p256](load/verify_ecdsa-p256.svg)

---

### verify/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 7,849 |
| 2 | 10,167 |
| 4 | 4,595 |
| 8 | 22,731 |
| 16 | 34,134 |

![Throughput — verify/ecdsa-secp256k1](load/verify_ecdsa-secp256k1.svg)

---

### verify/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,103 |
| 2 | 11,599 |
| 4 | 6,084 |
| 8 | 34,273 |
| 16 | 48,003 |

![Throughput — verify/eddsa-ed25519](load/verify_eddsa-ed25519.svg)

---

### key-creation/aes

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 951 |
| 2 | 769 |
| 4 | 798 |
| 8 | 704 |
| 16 | 636 |

![Throughput — key-creation/aes](load/key-creation_aes.svg)

---

### batch/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 236 |
| 2 | 310 |
| 4 | 345 |
| 8 | 838 |
| 16 | 1,264 |

![Throughput — batch/aes-cbc](load/batch_aes-cbc.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| aes-cbc | 433.8 µs |
| aes-gcm | 486.0 µs |

---

### Asymmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| rsa-pkcs | 95.3 µs |

---

### Sign / Verify

| Benchmark | pkcs11 |
|---|---|
| ecdsa-p256/sign | 258.4 µs |
| ecdsa-p256/verify | 216.1 µs |
| ecdsa-secp256k1/sign | 376.8 µs |
| ecdsa-secp256k1/verify | 137.3 µs |
| eddsa-ed25519/sign | 122.3 µs |
| eddsa-ed25519/verify | 116.9 µs |
| rsa-pkcs-sha256/sign | 24.13 ms |
| rsa-pkcs-sha256/verify | 76.8 µs |
| rsa-pss-sha256/sign | 25.16 ms |
| rsa-pss-sha256/verify | 82.9 µs |

---

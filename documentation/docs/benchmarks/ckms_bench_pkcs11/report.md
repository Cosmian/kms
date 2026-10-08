# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-07

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-07 21:33:38 UTC |
| Build | bench / non-fips |
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
CPU(s) scaling MHz:                      38%
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

The benchmark subcommand `ckms pkcs11 bench` (driven by `mise bench:pkcs11`) `dlopen()`s the built `cosmian_pkcs11` shared library, resolves the v3.1 function table through `C_GetInterface`, and calls it directly — the same code path a real PKCS#11 consumer application uses, as opposed to `mise bench:load`, which drives the KMIP REST API directly through the `ckms` client library.

By default each worker thread owns a dedicated `C_OpenSession` handle. The provider looks the handle up in its session map and serializes only access to that individual session with a per-session lock, so unrelated worker sessions can progress independently. `--shared-session` is an opt-in comparison mode that reproduces the former single-session contention model; it is not the default methodology.

For the Ed25519 Sign path measured in this report, `C_MessageSignInit` runs once during setup and each `C_SignMessage` crosses the synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`, serializes it as binary TTLV, sends it to the `/kmip` octet-stream endpoint, and parses the binary TTLV response before copying the signature into the caller-owned buffer.

### Independent operations

Unlike the software/HSM reports above, where `encrypt` and `sign-verify` each measure a single named request, this report measures every Cryptoki operation **independently**: `encrypt` (`C_EncryptInit`/`C_Encrypt`), `decrypt` (`C_DecryptInit`/`C_Decrypt`, against ciphertext produced once during setup — not timed), Ed25519 `sign` (`C_MessageSignInit` once + `C_SignMessage` per message), RSA `sign` (`C_SignInit`/`C_Sign`), `verify` (`C_VerifyInit`/`C_Verify`), and `key-creation` (`C_GenerateKey`+`C_DestroyObject`, ephemeral AES key per iteration) each get their own concurrency sweep and their own row/chart below.

`C_VerifyInit`/`C_Verify` are implemented and benchmarked through the same real Cryptoki function table. Verify rows are therefore ordinary measured operations, not placeholders or unsupported-operation probes.

`C_GenerateKeyPair` is not implemented either (asymmetric keys are always created through the KMS REST API, not PKCS#11), so `key-creation` only covers the one Cryptoki key-creation path the provider does support: symmetric `C_GenerateKey`.

### Load test (`mise bench:pkcs11`)

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
| 1 | 1,164 |
| 2 | 1,498 |
| 4 | 1,788 |
| 8 | 4,163 |
| 16 | 6,444 |

![Throughput — encrypt/aes-cbc](load/encrypt_aes-cbc.svg)

---

### encrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,132 |
| 2 | 1,614 |
| 4 | 1,439 |
| 8 | 4,450 |
| 16 | 6,437 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### encrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,656 |
| 2 | 2,381 |
| 4 | 2,678 |
| 8 | 17,514 |
| 16 | 22,873 |

![Throughput — encrypt/rsa-pkcs](load/encrypt_rsa-pkcs.svg)

---

### encrypt/rsa-oaep

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,521 |
| 2 | 2,361 |
| 4 | 2,723 |
| 8 | 16,981 |
| 16 | 22,047 |

![Throughput — encrypt/rsa-oaep](load/encrypt_rsa-oaep.svg)

---

### decrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,364 |
| 2 | 2,925 |
| 4 | 3,522 |
| 8 | 8,450 |
| 16 | 13,073 |

![Throughput — decrypt/aes-cbc](load/decrypt_aes-cbc.svg)

---

### decrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,313 |
| 2 | 3,144 |
| 4 | 3,233 |
| 8 | 8,633 |
| 16 | 12,771 |

![Throughput — decrypt/aes-gcm](load/decrypt_aes-gcm.svg)

---

### decrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 42 |
| 2 | 75 |
| 4 | 128 |
| 8 | 189 |
| 16 | 225 |

![Throughput — decrypt/rsa-pkcs](load/decrypt_rsa-pkcs.svg)

---

### decrypt/rsa-oaep

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 41 |
| 2 | 75 |
| 4 | 128 |
| 8 | 185 |
| 16 | 223 |

![Throughput — decrypt/rsa-oaep](load/decrypt_rsa-oaep.svg)

---

### sign/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 42 |
| 2 | 72 |
| 4 | 125 |
| 8 | 184 |
| 16 | 218 |

![Throughput — sign/rsa-pkcs-sha256](load/sign_rsa-pkcs-sha256.svg)

---

### sign/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 41 |
| 2 | 67 |
| 4 | 126 |
| 8 | 182 |
| 16 | 217 |

![Throughput — sign/rsa-pss-sha256](load/sign_rsa-pss-sha256.svg)

---

### sign/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 3,816 |
| 2 | 5,996 |
| 4 | 3,377 |
| 8 | 14,483 |
| 16 | 21,077 |

![Throughput — sign/ecdsa-p256](load/sign_ecdsa-p256.svg)

---

### sign/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 983 |
| 2 | 1,629 |
| 4 | 2,259 |
| 8 | 3,621 |
| 16 | 5,697 |

![Throughput — sign/ecdsa-p384](load/sign_ecdsa-p384.svg)

---

### sign/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,514 |
| 2 | 4,117 |
| 4 | 3,234 |
| 8 | 9,205 |
| 16 | 14,112 |

![Throughput — sign/ecdsa-secp256k1](load/sign_ecdsa-secp256k1.svg)

---

### sign/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 8,832 |
| 2 | 11,159 |
| 4 | 5,312 |
| 8 | 31,750 |
| 16 | 43,367 |

![Throughput — sign/eddsa-ed25519](load/sign_eddsa-ed25519.svg)

---

### verify/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,713 |
| 2 | 5,928 |
| 4 | 5,519 |
| 8 | 34,986 |
| 16 | 45,735 |

![Throughput — verify/rsa-pkcs-sha256](load/verify_rsa-pkcs-sha256.svg)

---

### verify/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,066 |
| 2 | 6,041 |
| 4 | 5,977 |
| 8 | 32,932 |
| 16 | 43,216 |

![Throughput — verify/rsa-pss-sha256](load/verify_rsa-pss-sha256.svg)

---

### verify/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 3,839 |
| 2 | 4,796 |
| 4 | 2,641 |
| 8 | 13,641 |
| 16 | 20,837 |

![Throughput — verify/ecdsa-p256](load/verify_ecdsa-p256.svg)

---

### verify/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,725 |
| 2 | 2,915 |
| 4 | 2,241 |
| 8 | 7,383 |
| 16 | 10,307 |

![Throughput — verify/ecdsa-p384](load/verify_ecdsa-p384.svg)

---

### verify/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,711 |
| 2 | 5,469 |
| 4 | 3,044 |
| 8 | 20,059 |
| 16 | 28,242 |

![Throughput — verify/ecdsa-secp256k1](load/verify_ecdsa-secp256k1.svg)

---

### verify/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 7,392 |
| 2 | 6,057 |
| 4 | 4,666 |
| 8 | 31,497 |
| 16 | 41,930 |

![Throughput — verify/eddsa-ed25519](load/verify_eddsa-ed25519.svg)

---

### key-creation/aes

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 734 |
| 2 | 702 |
| 4 | 382 |
| 8 | 416 |
| 16 | 458 |

![Throughput — key-creation/aes](load/key-creation_aes.svg)

---

### batch/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 117 |
| 2 | 155 |
| 4 | 141 |
| 8 | 442 |
| 16 | 647 |

![Throughput — batch/aes-cbc](load/batch_aes-cbc.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| aes-cbc | 845.5 µs |
| aes-gcm | 803.0 µs |

---

### Asymmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| rsa-oaep | 287.3 µs |
| rsa-pkcs | 238.1 µs |

---

### Sign / Verify

| Benchmark | pkcs11 |
|---|---|
| ecdsa-p256/sign | 259.3 µs |
| ecdsa-p256/verify | 289.6 µs |
| ecdsa-p384/sign | 965.6 µs |
| ecdsa-p384/verify | 496.7 µs |
| ecdsa-secp256k1/sign | 378.3 µs |
| ecdsa-secp256k1/verify | 153.3 µs |
| eddsa-ed25519/sign | 118.5 µs |
| eddsa-ed25519/verify | 167.7 µs |
| rsa-pkcs-sha256/sign | 24.32 ms |
| rsa-pkcs-sha256/verify | 129.2 µs |
| rsa-pss-sha256/sign | 23.03 ms |
| rsa-pss-sha256/verify | 102.0 µs |

---

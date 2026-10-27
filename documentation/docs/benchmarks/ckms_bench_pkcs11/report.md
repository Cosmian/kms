# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-20

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-20 21:38:30 UTC |
| HSM backend | None (Software) |
| Command | `mise run bench:pkcs11` |
| Build | bench / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 4,181 MHz |
| CPU cores | 24 physical / 32 logical (HT) |
| RAM | 31.1 GB |
| OS | Ubuntu 24.04.5 LTS |
| Kernel | 6.8.0-147-generic |

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
CPU(s) scaling MHz:                      34%
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

The benchmark subcommand `ckms pkcs11 bench` (driven by `mise run bench:pkcs11`) `dlopen()`s the built `cosmian_pkcs11` shared library, resolves the v3.1 function table through `C_GetInterface`, and calls it directly — the same code path a real PKCS#11 consumer application uses, as opposed to `mise bench:load`, which drives the KMIP REST API directly through the `ckms` client library.

By default each worker thread owns a dedicated `C_OpenSession` handle. The provider looks the handle up in its session map and serializes only access to that individual session with a per-session lock, so unrelated worker sessions can progress independently. `--shared-session` is an opt-in comparison mode that reproduces the former single-session contention model; it is not the default methodology.

For the Ed25519 Sign path measured in this report, `C_MessageSignInit` runs once during setup and each `C_SignMessage` crosses the synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`, serializes it as binary TTLV, sends it to the `/kmip` octet-stream endpoint, and parses the binary TTLV response before copying the signature into the caller-owned buffer.

### Independent operations

Unlike the software/HSM reports where requests may be bundled, this report measures each Cryptoki operation **independently**:

- **Encryption/Decryption**: `C_EncryptInit`/`C_Encrypt` and `C_DecryptInit`/`C_Decrypt` against pre-generated ciphertext
- **Sign**: `C_SignInit`/`C_Sign` (or `C_MessageSignInit`/`C_SignMessage` for Ed25519) crossing the synchronous PKCS#11 boundary
- **Verify**: `C_VerifyInit`/`C_Verify` implemented and benchmarked through the real Cryptoki function table
- **Key Creation**: symmetric `C_GenerateKey` with immediate `C_DestroyObject` per iteration

### Load test (`mise run bench:pkcs11`)

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
| 1 | 3,371 |
| 2 | 3,339 |
| 4 | 6,035 |
| 8 | 12,070 |
| 16 | 18,888 |

![Throughput — encrypt/aes-cbc](load/encrypt_aes-cbc.svg)

---

### encrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 3,357 |
| 2 | 3,711 |
| 4 | 4,786 |
| 8 | 12,646 |
| 16 | 18,993 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### encrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,716 |
| 2 | 3,441 |
| 4 | 3,769 |
| 8 | 17,911 |
| 16 | 24,822 |

![Throughput — encrypt/rsa-pkcs](load/encrypt_rsa-pkcs.svg)

---

### encrypt/rsa-oaep

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,349 |
| 2 | 3,209 |
| 4 | 3,891 |
| 8 | 16,947 |
| 16 | 23,368 |

![Throughput — encrypt/rsa-oaep](load/encrypt_rsa-oaep.svg)

---

### decrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 8,277 |
| 2 | 6,591 |
| 4 | 6,946 |
| 8 | 28,088 |
| 16 | 39,928 |

![Throughput — decrypt/aes-cbc](load/decrypt_aes-cbc.svg)

---

### decrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 8,006 |
| 2 | 8,532 |
| 4 | 7,757 |
| 8 | 27,456 |
| 16 | 39,818 |

![Throughput — decrypt/aes-gcm](load/decrypt_aes-gcm.svg)

---

### decrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 39 |
| 2 | 71 |
| 4 | 96 |
| 8 | 173 |
| 16 | 215 |

![Throughput — decrypt/rsa-pkcs](load/decrypt_rsa-pkcs.svg)

---

### decrypt/rsa-oaep

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 40 |
| 2 | 73 |
| 4 | 118 |
| 8 | 180 |
| 16 | 214 |

![Throughput — decrypt/rsa-oaep](load/decrypt_rsa-oaep.svg)

---

### sign/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 38 |
| 2 | 72 |
| 4 | 119 |
| 8 | 180 |
| 16 | 215 |

![Throughput — sign/rsa-pkcs-sha256](load/sign_rsa-pkcs-sha256.svg)

---

### sign/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 39 |
| 2 | 71 |
| 4 | 118 |
| 8 | 180 |
| 16 | 216 |

![Throughput — sign/rsa-pss-sha256](load/sign_rsa-pss-sha256.svg)

---

### sign/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,335 |
| 2 | 11,013 |
| 4 | 10,520 |
| 8 | 29,174 |
| 16 | 44,650 |

![Throughput — sign/ecdsa-p256](load/sign_ecdsa-p256.svg)

---

### sign/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 963 |
| 2 | 1,562 |
| 4 | 2,209 |
| 8 | 3,622 |
| 16 | 5,715 |

![Throughput — sign/ecdsa-p384](load/sign_ecdsa-p384.svg)

---

### sign/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,999 |
| 2 | 4,772 |
| 4 | 4,483 |
| 8 | 10,110 |
| 16 | 15,111 |

![Throughput — sign/ecdsa-secp256k1](load/sign_ecdsa-secp256k1.svg)

---

### sign/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 10,190 |
| 2 | 13,249 |
| 4 | 14,281 |
| 8 | 31,518 |
| 16 | 49,737 |

![Throughput — sign/eddsa-ed25519](load/sign_eddsa-ed25519.svg)

---

### verify/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 11,011 |
| 2 | 6,579 |
| 4 | 8,346 |
| 8 | 35,040 |
| 16 | 49,396 |

![Throughput — verify/rsa-pkcs-sha256](load/verify_rsa-pkcs-sha256.svg)

---

### verify/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,997 |
| 2 | 6,283 |
| 4 | 7,789 |
| 8 | 32,890 |
| 16 | 46,850 |

![Throughput — verify/rsa-pss-sha256](load/verify_rsa-pss-sha256.svg)

---

### verify/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 6,671 |
| 2 | 5,841 |
| 4 | 5,163 |
| 8 | 24,145 |
| 16 | 33,350 |

![Throughput — verify/ecdsa-p256](load/verify_ecdsa-p256.svg)

---

### verify/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,809 |
| 2 | 2,711 |
| 4 | 3,225 |
| 8 | 6,369 |
| 16 | 10,424 |

![Throughput — verify/ecdsa-p384](load/verify_ecdsa-p384.svg)

---

### verify/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 6,552 |
| 2 | 6,215 |
| 4 | 4,699 |
| 8 | 19,920 |
| 16 | 29,845 |

![Throughput — verify/ecdsa-secp256k1](load/verify_ecdsa-secp256k1.svg)

---

### verify/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 6,866 |
| 2 | 6,963 |
| 4 | 7,340 |
| 8 | 27,750 |
| 16 | 40,889 |

![Throughput — verify/eddsa-ed25519](load/verify_eddsa-ed25519.svg)

---

### key-creation/aes

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 891 |
| 2 | 934 |
| 4 | 910 |
| 8 | 908 |
| 16 | 714 |

![Throughput — key-creation/aes](load/key-creation_aes.svg)

---

### batch/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 365 |
| 2 | 330 |
| 4 | 446 |
| 8 | 1,241 |
| 16 | 1,868 |

![Throughput — batch/aes-cbc](load/batch_aes-cbc.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| aes-cbc | 448.4 µs |
| aes-gcm | 249.5 µs |

---

### Asymmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| rsa-oaep | 187.2 µs |
| rsa-pkcs | 271.2 µs |

---

### Sign / Verify

| Benchmark | pkcs11 |
|---|---|
| ecdsa-p256/sign | 96.1 µs |
| ecdsa-p256/verify | 151.4 µs |
| ecdsa-p384/sign | 1.95 ms |
| ecdsa-p384/verify | 553.4 µs |
| ecdsa-secp256k1/sign | 305.1 µs |
| ecdsa-secp256k1/verify | 173.2 µs |
| eddsa-ed25519/sign | 96.4 µs |
| eddsa-ed25519/verify | 140.6 µs |
| rsa-pkcs-sha256/sign | 23.57 ms |
| rsa-pkcs-sha256/verify | 119.0 µs |
| rsa-pss-sha256/sign | 24.06 ms |
| rsa-pss-sha256/verify | 88.5 µs |

---

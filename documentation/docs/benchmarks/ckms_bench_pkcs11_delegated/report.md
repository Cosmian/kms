# KMS Performance Comparison

**Versions**: `v5.27.1`
**Generated**: 2026-09-25

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-09-25 01:52:21 UTC |
| Build | bench / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 800 MHz |
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
CPU(s) scaling MHz:                      22%
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
        lib["<b>cosmian_pkcs11.so</b>"]
    end

    subgraph srv["KMS Server"]
        kmip["KMIP 2.1"]
        oracle["CryptoOracle"]
    end

    subgraph hsm["SoftHSM2"]
        slot["PKCS#11 Slot"]
        keys["HSM Keys<br/>(Resident)"]
    end

    ckms -->|C_Sign/C_Encrypt| lib
    lib -->|HTTP| kmip
    kmip --> oracle
    oracle -->|PKCS#11| slot
    slot --> keys

    style ckms fill:#4A90E2
    style lib fill:#FF6B6B
    style kmip fill:#7ED321
    style oracle fill:#F5A623
    style slot fill:#BD10E0
```

**Components**:

- **ckms**: PKCS#11 load test driver
- **cosmian_pkcs11.so**: PKCS#11 provider bridge
- **KMIP Endpoint**: Server-side protocol handler
- **CryptoOracle**: Routes operations to HSM-resident keys (C_Sign, C_Encrypt directly on hardware)
- **PKCS#11 Slot**: HSM backend for key storage and cryptographic ops

---

## Protocols

The caller-facing protocol benchmarked here is the `cosmian_pkcs11` provider's real PKCS#11 v3.1 Cryptoki C ABI: the benchmark `dlopen()`s the built shared library (`libcosmian_pkcs11.{so,dylib}`) and resolves its standard interface through `C_GetInterface` — the same call path v3-aware PKCS#11 consumers (Oracle TDE, OpenSSH, disk-encryption tools) use. For remote Sign, the provider wraps the KMIP operation in a KMIP 2.1 `RequestMessage`, serializes binary TTLV, and sends `application/octet-stream` to `POST /kmip`; the binary TTLV response is fully deserialized before `C_SignMessage` returns.

This delegated variant provisions `hsm::<slot>::...` keys. After the provider sends each KMIP request, KMS routes the key to its `CryptoOracle`; the cryptographic operation executes through the server-side SoftHSM2 PKCS#11 backend rather than software crypto.

| Interface | Transport | Description |
|---|---|---|
| **PKCS#11 (Cryptoki v3.1)** | `C_GetInterface` + C ABI | `C_Initialize`, `C_OpenSession`, `C_EncryptInit`/`C_Encrypt`, `C_DecryptInit`/`C_Decrypt`, `C_MessageSignInit`/`C_SignMessage`, `C_VerifyInit`/`C_Verify`, `C_GenerateKey` |
| **Provider → KMS Sign** | KMIP 2.1 binary TTLV over HTTP | `POST /kmip`, `application/octet-stream` |
| **KMS → HSM** | PKCS#11 via `CryptoOracle` | HSM-resident key generation and cryptographic operations |

---

## Benchmark Methodology

### Real Cryptoki C ABI, one session per worker

The benchmark subcommand `ckms pkcs11 bench` (driven by `mise bench:load-pkcs11 --delegated`) `dlopen()`s the built `cosmian_pkcs11` shared library, resolves the v3.1 function table through `C_GetInterface`, and calls it directly — the same code path a real PKCS#11 consumer application uses, as opposed to `mise bench:load`, which drives the KMIP REST API directly through the `ckms` client library.

By default each worker thread owns a dedicated `C_OpenSession` handle. The provider looks the handle up in its session map and serializes only access to that individual session with a per-session lock, so unrelated worker sessions can progress independently. `--shared-session` is an opt-in comparison mode that reproduces the former single-session contention model; it is not the default methodology.

For the Ed25519 Sign path measured in this report, `C_MessageSignInit` runs once during setup and each `C_SignMessage` crosses the synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`, serializes it as binary TTLV, sends it to the `/kmip` octet-stream endpoint, and parses the binary TTLV response before copying the signature into the caller-owned buffer.

### HSM-resident key execution

With `--delegated`, provisioning assigns `hsm::<slot>::...` UIDs and persists discovery tags in a versioned PKCS#11 `CKA_LABEL` envelope while retaining the raw key ID in `CKA_ID`. The provider locates those tagged keys through KMS, while Encrypt, Decrypt, Sign, Verify, and key generation are executed by the KMS `CryptoOracle` on the SoftHSM2 token. For `--mode all`, key-creation, encrypt, sign, and verify run against separate fresh tokens so cumulative SoftHSM2 key generation does not contaminate later measurements.

### Independent operations

Unlike the software/HSM reports above, where `encrypt` and `sign-verify` each measure a single named request, this report measures every Cryptoki operation **independently**: `encrypt` (`C_EncryptInit`/`C_Encrypt`), `decrypt` (`C_DecryptInit`/`C_Decrypt`, against ciphertext produced once during setup — not timed), Ed25519 `sign` (`C_MessageSignInit` once + `C_SignMessage` per message), RSA `sign` (`C_SignInit`/`C_Sign`), `verify` (`C_VerifyInit`/`C_Verify`), and `key-creation` (`C_GenerateKey`+`C_DestroyObject`, ephemeral AES key per iteration) each get their own concurrency sweep and their own row/chart below.

`C_VerifyInit`/`C_Verify` are implemented and benchmarked through the same real Cryptoki function table. Verify rows are therefore ordinary measured operations, not placeholders or unsupported-operation probes.

`C_GenerateKeyPair` is not implemented either (asymmetric keys are always created through the KMS REST API, not PKCS#11), so `key-creation` only covers the one Cryptoki key-creation path the provider does support: symmetric `C_GenerateKey`.

### Load test (`mise bench:load-pkcs11 --delegated`)

The load test sweeps a configurable list of concurrency levels, mirroring `mise bench:load`'s own sweep mechanics exactly: at each level *N* concurrent OS threads call the target Cryptoki function in a tight loop for a fixed **measurement window** (default: 20 s), preceded by a **warm-up phase** (default: 5 s) that is excluded from measurements, followed by a **cooldown** (default: 2 s) before the next level.
Recorded metrics per *(operation, concurrency)* pair:

- **Throughput** — Cryptoki calls per second
- **p50 / p95 / p99** — per-call latency percentiles (ms)

> **Infrastructure note:** The benchmark server uses a **local SQLite** backend (temporary, discarded after the run). Throughput figures will differ on a production deployment backed by PostgreSQL or Redis-Findex.

---

## Load Tests

### key-creation/aes

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 617 |
| 2 | 606 |
| 4 | 616 |
| 8 | 605 |
| 16 | 607 |

![Throughput — key-creation/aes](load/key-creation_aes.svg)

---

### encrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,947 |
| 2 | 2,108 |
| 4 | 2,077 |
| 8 | 8,324 |
| 16 | 11,274 |

![Throughput — encrypt/aes-cbc](load/encrypt_aes-cbc.svg)

---

### encrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,843 |
| 2 | 1,766 |
| 4 | 2,257 |
| 8 | 8,301 |
| 16 | 11,159 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### encrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,545 |
| 2 | 5,173 |
| 4 | 6,087 |
| 8 | 34,502 |
| 16 | 25,143 |

![Throughput — encrypt/rsa-pkcs](load/encrypt_rsa-pkcs.svg)

---

### decrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,111 |
| 2 | 1,925 |
| 4 | 2,209 |
| 8 | 8,367 |
| 16 | 10,544 |

![Throughput — decrypt/aes-cbc](load/decrypt_aes-cbc.svg)

---

### decrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,089 |
| 2 | 2,205 |
| 4 | 2,209 |
| 8 | 8,236 |
| 16 | 11,169 |

![Throughput — decrypt/aes-gcm](load/decrypt_aes-gcm.svg)

---

### decrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,404 |
| 2 | 2,414 |
| 4 | 3,773 |
| 8 | 5,332 |
| 16 | 6,705 |

![Throughput — decrypt/rsa-pkcs](load/decrypt_rsa-pkcs.svg)

---

### sign/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,236 |
| 2 | 2,075 |
| 4 | 3,214 |
| 8 | 4,273 |
| 16 | 4,582 |

![Throughput — sign/rsa-pkcs-sha256](load/sign_rsa-pkcs-sha256.svg)

---

### sign/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,201 |
| 2 | 2,010 |
| 4 | 3,201 |
| 8 | 4,219 |
| 16 | 4,387 |

![Throughput — sign/rsa-pss-sha256](load/sign_rsa-pss-sha256.svg)

---

### sign/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,463 |
| 2 | 5,789 |
| 4 | 5,361 |
| 8 | 3,705 |
| 16 | 2,257 |

![Throughput — sign/ecdsa-p256](load/sign_ecdsa-p256.svg)

---

### sign/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,408 |
| 2 | 3,649 |
| 4 | 4,867 |
| 8 | 5,701 |
| 16 | 4,632 |

![Throughput — sign/ecdsa-secp256k1](load/sign_ecdsa-secp256k1.svg)

---

### sign/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,883 |
| 2 | 5,016 |
| 4 | 5,940 |
| 8 | 5,463 |
| 16 | 2,185 |

![Throughput — sign/eddsa-ed25519](load/sign_eddsa-ed25519.svg)

---

### verify/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,908 |
| 2 | 4,416 |
| 4 | 5,737 |
| 8 | 8,403 |
| 16 | 5,411 |

![Throughput — verify/rsa-pkcs-sha256](load/verify_rsa-pkcs-sha256.svg)

---

### verify/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,790 |
| 2 | 3,609 |
| 4 | 3,916 |
| 8 | 6,810 |
| 16 | 5,451 |

![Throughput — verify/rsa-pss-sha256](load/verify_rsa-pss-sha256.svg)

---

### verify/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,058 |
| 2 | 7,756 |
| 4 | 7,487 |
| 8 | 8,927 |
| 16 | 2,882 |

![Throughput — verify/ecdsa-p256](load/verify_ecdsa-p256.svg)

---

### verify/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,684 |
| 2 | 4,399 |
| 4 | 5,982 |
| 8 | 7,467 |
| 16 | 5,879 |

![Throughput — verify/ecdsa-secp256k1](load/verify_ecdsa-secp256k1.svg)

---

### verify/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 3,897 |
| 2 | 4,363 |
| 4 | 7,241 |
| 8 | 8,407 |
| 16 | 7,605 |

![Throughput — verify/eddsa-ed25519](load/verify_eddsa-ed25519.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| aes-cbc | 605.6 µs |
| aes-gcm | 441.1 µs |

---

### Asymmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| rsa-pkcs | 143.8 µs |

---

### Sign / Verify

| Benchmark | pkcs11 |
|---|---|
| ecdsa-p256/sign | 206.8 µs |
| ecdsa-p256/verify | 200.6 µs |
| ecdsa-secp256k1/sign | 459.6 µs |
| ecdsa-secp256k1/verify | 376.7 µs |
| eddsa-ed25519/sign | 285.7 µs |
| eddsa-ed25519/verify | 318.2 µs |
| rsa-pkcs-sha256/sign | 991.6 µs |
| rsa-pkcs-sha256/verify | 149.2 µs |
| rsa-pss-sha256/sign | 881.1 µs |
| rsa-pss-sha256/verify | 156.6 µs |

---

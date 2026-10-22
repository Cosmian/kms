# KMS Performance Comparison

**Versions**: `v5.28.0`
**Generated**: 2026-10-20

---

## Benchmark Environment

| Field | Value |
|---|---|
| Date | 2026-10-20 04:18:42 UTC |
| HSM backend | SoftHSM2 |
| Command | `mise run bench:pkcs11 --delegated --hsm-model softhsm2` |
| Build | bench / non-fips |
| Database | SQLite (temporary, single benchmark run) |
| CPU | Intel(R) Core(TM) i9-14900T @ 1,215 MHz |
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
CPU(s) scaling MHz:                      23%
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
        keys["ECDSA<br/>RSA<br/>EdDSA<br/>AES<br/>(Resident)"]
    end

    ckms -->|C_Sign/C_Verify/C_Encrypt/C_Decrypt/C_GenerateKey| lib
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

- **ckms**: PKCS#11 load test driver (`mise run bench:pkcs11 --delegated --hsm-model softhsm2`)
- **cosmian_pkcs11.so**: PKCS#11 provider bridge
- **KMIP Endpoint**: Server-side protocol handler
- **CryptoOracle**: Routes operations to HSM-resident keys (C_Sign/C_Verify/C_Encrypt/C_Decrypt/C_GenerateKey on SoftHSM2)
- **PKCS#11 Slot**: SoftHSM2 backend for key storage and cryptographic ops

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

The benchmark subcommand `ckms pkcs11 bench` (driven by `mise run bench:pkcs11 --delegated --hsm-model softhsm2`) `dlopen()`s the built `cosmian_pkcs11` shared library, resolves the v3.1 function table through `C_GetInterface`, and calls it directly — the same code path a real PKCS#11 consumer application uses, as opposed to `mise bench:load`, which drives the KMIP REST API directly through the `ckms` client library.

By default each worker thread owns a dedicated `C_OpenSession` handle. The provider looks the handle up in its session map and serializes only access to that individual session with a per-session lock, so unrelated worker sessions can progress independently. `--shared-session` is an opt-in comparison mode that reproduces the former single-session contention model; it is not the default methodology.

For the Ed25519 Sign path measured in this report, `C_MessageSignInit` runs once during setup and each `C_SignMessage` crosses the synchronous PKCS#11 boundary, builds a KMIP 2.1 `RequestMessage`, serializes it as binary TTLV, sends it to the `/kmip` octet-stream endpoint, and parses the binary TTLV response before copying the signature into the caller-owned buffer.

### HSM-resident key execution

With `--delegated`, provisioning assigns `hsm::<slot>::...` UIDs and persists discovery tags in a versioned PKCS#11 `CKA_LABEL` envelope while retaining the raw key ID in `CKA_ID`. The provider locates those tagged keys through KMS, while operations are executed by the KMS `CryptoOracle` on the SoftHSM2 backend. For full test suites on simulator tokens, submodes run against separate fresh tokens so cumulative key generation does not contaminate later measurements.

### Independent operations

Unlike the software/HSM reports where requests may be bundled, this report measures each Cryptoki operation **independently**:

- **Encryption/Decryption**: `C_EncryptInit`/`C_Encrypt` and `C_DecryptInit`/`C_Decrypt` against pre-generated ciphertext
- **Sign**: `C_SignInit`/`C_Sign` (or `C_MessageSignInit`/`C_SignMessage` for Ed25519) crossing the synchronous PKCS#11 boundary
- **Verify**: `C_VerifyInit`/`C_Verify` implemented and benchmarked through the real Cryptoki function table
- **Key Creation**: symmetric `C_GenerateKey` with immediate `C_DestroyObject` per iteration

### Load test (`mise run bench:pkcs11 --delegated --hsm-model softhsm2`)

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
| 1 | 593 |
| 2 | 611 |
| 4 | 581 |
| 8 | 576 |
| 16 | 558 |

![Throughput — key-creation/aes](load/key-creation_aes.svg)

---

### encrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,351 |
| 2 | 3,271 |
| 4 | 5,036 |
| 8 | 8,154 |
| 16 | 11,824 |

![Throughput — encrypt/aes-cbc](load/encrypt_aes-cbc.svg)

---

### encrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,644 |
| 2 | 6,638 |
| 4 | 10,150 |
| 8 | 16,391 |
| 16 | 22,742 |

![Throughput — encrypt/aes-gcm](load/encrypt_aes-gcm.svg)

---

### encrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,228 |
| 2 | 5,617 |
| 4 | 8,262 |
| 8 | 12,483 |
| 16 | 12,997 |

![Throughput — encrypt/rsa-pkcs](load/encrypt_rsa-pkcs.svg)

---

### decrypt/aes-cbc

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,064 |
| 2 | 6,492 |
| 4 | 10,208 |
| 8 | 16,422 |
| 16 | 23,114 |

![Throughput — decrypt/aes-cbc](load/decrypt_aes-cbc.svg)

---

### decrypt/aes-gcm

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 4,870 |
| 2 | 6,492 |
| 4 | 10,231 |
| 8 | 15,801 |
| 16 | 22,516 |

![Throughput — decrypt/aes-gcm](load/decrypt_aes-gcm.svg)

---

### decrypt/rsa-pkcs

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,203 |
| 2 | 1,996 |
| 4 | 3,309 |
| 8 | 4,759 |
| 16 | 6,426 |

![Throughput — decrypt/rsa-pkcs](load/decrypt_rsa-pkcs.svg)

---

### sign/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,170 |
| 2 | 1,974 |
| 4 | 3,267 |
| 8 | 4,584 |
| 16 | 6,263 |

![Throughput — sign/rsa-pkcs-sha256](load/sign_rsa-pkcs-sha256.svg)

---

### sign/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,165 |
| 2 | 1,941 |
| 4 | 3,188 |
| 8 | 4,571 |
| 16 | 6,200 |

![Throughput — sign/rsa-pss-sha256](load/sign_rsa-pss-sha256.svg)

---

### sign/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 7,052 |
| 2 | 9,997 |
| 4 | 15,111 |
| 8 | 21,920 |
| 16 | 22,710 |

![Throughput — sign/ecdsa-p256](load/sign_ecdsa-p256.svg)

---

### sign/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,491 |
| 2 | 2,443 |
| 4 | 3,952 |
| 8 | 6,029 |
| 16 | 9,005 |

![Throughput — sign/ecdsa-p384](load/sign_ecdsa-p384.svg)

---

### sign/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,540 |
| 2 | 3,955 |
| 4 | 6,179 |
| 8 | 9,757 |
| 16 | 14,211 |

![Throughput — sign/ecdsa-secp256k1](load/sign_ecdsa-secp256k1.svg)

---

### sign/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 6,618 |
| 2 | 8,810 |
| 4 | 13,243 |
| 8 | 20,091 |
| 16 | 21,717 |

![Throughput — sign/eddsa-ed25519](load/sign_eddsa-ed25519.svg)

---

### verify/rsa-pkcs-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,545 |
| 2 | 12,392 |
| 4 | 18,374 |
| 8 | 25,336 |
| 16 | 26,865 |

![Throughput — verify/rsa-pkcs-sha256](load/verify_rsa-pkcs-sha256.svg)

---

### verify/rsa-pss-sha256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 9,296 |
| 2 | 12,267 |
| 4 | 17,773 |
| 8 | 25,801 |
| 16 | 27,013 |

![Throughput — verify/rsa-pss-sha256](load/verify_rsa-pss-sha256.svg)

---

### verify/ecdsa-p256

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,184 |
| 2 | 7,172 |
| 4 | 9,317 |
| 8 | 6,710 |
| 16 | 10,113 |

![Throughput — verify/ecdsa-p256](load/verify_ecdsa-p256.svg)

---

### verify/ecdsa-p384

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 1,639 |
| 2 | 2,776 |
| 4 | 4,534 |
| 8 | 6,511 |
| 16 | 8,636 |

![Throughput — verify/ecdsa-p384](load/verify_ecdsa-p384.svg)

---

### verify/ecdsa-secp256k1

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 2,587 |
| 2 | 4,065 |
| 4 | 6,240 |
| 8 | 8,772 |
| 16 | 9,730 |

![Throughput — verify/ecdsa-secp256k1](load/verify_ecdsa-secp256k1.svg)

---

### verify/eddsa-ed25519

| Concurrency | pkcs11 (req/s) |
|---|---|
| 1 | 5,992 |
| 2 | 8,583 |
| 4 | 13,473 |
| 8 | 20,617 |
| 16 | 21,006 |

![Throughput — verify/eddsa-ed25519](load/verify_eddsa-ed25519.svg)

---

## Criterion Benchmarks

### Symmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| aes-cbc | 501.0 µs |
| aes-gcm | 198.9 µs |

---

### Asymmetric Encryption

| Benchmark | pkcs11 |
|---|---|
| rsa-pkcs | 236.2 µs |

---

### Sign / Verify

| Benchmark | pkcs11 |
|---|---|
| ecdsa-p256/sign | 127.2 µs |
| ecdsa-p256/verify | 183.8 µs |
| ecdsa-p384/sign | 752.6 µs |
| ecdsa-p384/verify | 614.8 µs |
| ecdsa-secp256k1/sign | 400.5 µs |
| ecdsa-secp256k1/verify | 380.3 µs |
| eddsa-ed25519/sign | 172.0 µs |
| eddsa-ed25519/verify | 156.2 µs |
| rsa-pkcs-sha256/sign | 974.9 µs |
| rsa-pkcs-sha256/verify | 99.6 µs |
| rsa-pss-sha256/sign | 901.6 µs |
| rsa-pss-sha256/verify | 112.6 µs |

---

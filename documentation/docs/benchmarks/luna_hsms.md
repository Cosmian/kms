# Thales Luna HSMs used in the benchmarks

Hardware and partition characteristics of the two Thales Luna Network HSMs (model `LunaSA`)
benchmarked from the KMS host. Values were read on 2026-10-13 with `lunacm` (`slot info`,
`partition showinfo`, `partition showpolicies`) on slot 0, without logging in. Addresses, serial
numbers and host names are anonymized.

| | Luna 1 | Luna 2 |
| --- | --- | --- |
| Benchmark reports | [ckms_bench_hsm_delegated_luna](ckms_bench_hsm_delegated_luna/report.md) (ECDSA) | [ckms_bench_hsm_delegated_luna_pqc](ckms_bench_hsm_delegated_luna_pqc/report.md) (ECDSA, EdDSA), [ckms_bench_hsm_delegated_luna2_ed25519](ckms_bench_hsm_delegated_luna2_ed25519/report.md) (EdDSA), [ckms_bench_hsm_delegated_luna2_aesgcm](ckms_bench_hsm_delegated_luna2_aesgcm/report.md) (AES-GCM) |
| IP address / NTLS port | `<luna-1-ip>:5656` | `<luna-2-ip>:5656` |
| Model | LunaSA (Luna Network HSM) | LunaSA (Luna Network HSM) |
| HSM part number | 808-000073-001 | 808-000073-001 |
| HSM serial number | `<hsm-serial>` | `<hsm-serial>` |
| Firmware version | 7.8.5 | 7.9.1 |
| Rollback firmware version | 7.8.4 | 7.8.4 |
| Bootloader version | 1.1.5 | 1.1.5 |
| Slot configuration | Luna User Partition With SO (PED) Key Export With Cloning Mode | Luna User Partition With SO (PED) Key Export With Cloning Mode |
| FIPS approved mode | No | No |
| Partitions (slots 0–4) | `Sandbox_1`, `Other_1`, `QA_1`, `Export_1`, `ModeV1_1` | `Sandbox`, `QA`, `Other`, `Export`, `ModeV1` |
| Benchmarked partition (slot 0) | `Sandbox_1` | `Sandbox` |
| Partition authentication | Crypto Officer: PED (primary) + PIN (secondary), activated | Crypto Officer: PED (primary) + PIN (secondary), activated |
| Partition total storage | 688,558 bytes | 6,627,739 bytes |
| Server certificate (client side) | `/usr/safenet/lunaclient/cert/server/lunasa7rd.pem` | `/usr/safenet/lunaclient/cert/server/<luna-2-ip>.pem` |
| Network round-trip from the KMS host (`ping`, avg of 10) | 0.33 ms | 0.38 ms |

## Partition policies (slot 0)

Policies relevant to the KMS benchmarks, identical on both HSMs:

| Policy | Value | Effect on the benchmark |
| --- | --- | --- |
| 1: Allow private key wrapping | 0 | |
| 20: Max failed user logins allowed | 10 | Partition locks after 10 wrong PINs |
| 22: Allow activation | 1 | |
| 23: Allow auto-activation | 1 | |
| 37: Force Secure Trusted Channel | 0 | |
| 43: Allow non-FIPS algorithms | 1 | Ed25519/Ed448 available |

Policies that differ:

| Policy | Luna 1 | Luna 2 |
| --- | --- | --- |
| 15: Ignore failed challenge responses | 0 | 1 |
| 42: Allow CPv1 | 0 | 1 |
| 45: Allow ECDSA/RSA Prehash SigVer | not present (firmware 7.8.5) | 1 |

## Ed25519 signature ceiling (Luna 2)

Delegated Ed25519 signing levels off at about 1,020 signatures/s from 16 concurrent clients,
while ECDSA P-256 scales to about 10,300/s on the same partition. The limit is the HSM's: a
minimal PKCS#11 program calling `libCryptoki2_64.so` directly (one session per thread,
`C_SignInit` + `C_Sign` on 32 bytes, session key pair, 10 s per point, run on 2026-10-14) hits the
same ceiling without the KMS:

| Threads | Ed25519 (`CKM_EDDSA`), direct PKCS#11 | Ed25519, through the KMS | ECDSA P-256 (`CKM_ECDSA`), direct PKCS#11 | ECDSA P-256, through the KMS |
| --- | ---: | ---: | ---: | ---: |
| 1 | 691/s | 541/s | 1,343/s | 847/s |
| 16 | 1,009/s | 1,017/s | 9,626/s | 7,935/s |
| 32 | 1,007/s | 1,021/s | 10,337/s | 9,513/s |
| 64 | 1,000/s | 1,028/s | 10,323/s | 10,262/s |

Luna 2 completes about 1,000 Ed25519 signatures per second whatever the number of sessions, so
adding clients only adds latency. At one client the gap between direct and KMS figures is the
KMS per-request overhead.

## Client host

| Field | Value |
| --- | --- |
| Host | `<kms-host>`, Debian GNU/Linux 13 (trixie), 8 vCPU (VMware) |
| Luna Client | 10.9.3 (`lunacm` v10.9.3-43) |
| PKCS#11 library | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| KMS configuration | `/etc/cosmian_kms/config.toml.luna1` / `config.toml.luna2`: `hsm_model = "luna"`, `hsm_slot = [0]` |
| HSM selection | Luna client configuration: `/etc/Chrystoki.conf.luna1` (Luna 1) or `/etc/Chrystoki.conf` (Luna 2), selected with `ChrystokiConfigurationPath` |

# Trustway Proteccio HSM used in the benchmarks

Characteristics of the Trustway Proteccio HSM ("Proteccio 4") benchmarked from the KMS host.
Values were read on 2026-10-13 with `nethsmstatus` and the client configuration in
`/etc/proteccio/`, without logging in. Addresses, serial numbers and host names are anonymized.

| Field | Value |
| --- | --- |
| Benchmark report | [ckms_bench_hsm_delegated_proteccio](ckms_bench_hsm_delegated_proteccio/report.md) |
| IP address | `<proteccio-ip>` (TLS enabled) |
| Manufacturer ID | Bull Trustway Proteccio HSM |
| Model flags | `0X80000007 PROTECCIO HR` |
| Serial number | `<hsm-serial>` |
| Firmware version | 194 |
| MCS version | 65539 |
| Token state | `0X40 OPERATIONAL` |
| Virtual HSMs (slots 1–8) | `Sandbox`, `Dev`, `QA`, `Other`, `Automate`, `Benchmark`, `RGS`, `Demo` (all `OPERATIONAL`) |
| Benchmarked virtual HSM | Slot 4, `Other` |
| Server certificate | self-signed, issued by the HSM owner, valid until 2042-03-10 |
| Network round-trip from the KMS host (`ping`, avg of 10) | 0.26 ms |

## Client host

| Field | Value |
| --- | --- |
| Host | `<kms-host>`, Debian GNU/Linux 13 (trixie), 8 vCPU (VMware) |
| PKCS#11 library | `/lib/libnethsm.so` (nethsm PKCS#11 RPC, library version 4.5) |
| Client configuration | `/etc/proteccio/proteccio.rc`: `SSL=1`, `Mode=0`, `LoggingLevel=0`, `namedCurve=1`, mutual TLS with `proteccio_client.crt` / `proteccio_client.key` |
| KMS configuration | `/etc/cosmian_kms/config_proteccio.toml`: `hsm_model = "proteccio"`, `hsm_slot = [4]` |
| Benchmark credentials | `~/.cosmian/proteccio.sh` (`PROTECCIO_IP`, `PROTECCIO_SLOT=4`, `PROTECCIO_PASSWORD`, `PROTECCIO_PKCS11_LIB`) |

## Algorithm support observed

| Algorithm | Key generation on the HSM |
| --- | --- |
| RSA 2048 | Supported |
| ECDSA P-256 | Supported |
| Ed25519 / Ed448 | Rejected with `CKR_UNKNOWN` (`0x70`) |

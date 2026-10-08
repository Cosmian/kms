# PKCS#11 Performance Testing with p11perftest

`p11perftest` is a vendor-neutral PKCS#11 benchmarking utility (Mastercard, v3.16.0+) that measures cryptographic operation performance directly at the Cryptoki C API level. This page documents the command syntax for running p11perftest against each HSM backend supported by Eviden KMS.

## Prerequisites

- `p11perftest` binary installed and in `$PATH` (from vendor or `apt install opensc-pkcs11` family)
- HSM library installed at the path specified in `documentation/docs/hsm_support/<backend>.md`
- Token initialized with at least one slot and corresponding PIN
- Network access to HSM (for remote HSMs: AWS CloudHSM, GCP Cloud HSM, Proteccio)

## Command Format

p11perftest accepts library path, slot, and password either as command-line flags or environment variables:

```bash
# Via flags:
p11perftest -l /lib/libnethsm.so -s 4 -p <password> --coverage ecdsa --keysizes ecnistp256 --threads 64 --iterations 200

# Via environment variables (cleaner for shells with secrets):
export PKCS11LIB=/lib/libnethsm.so
export PKCS11SLOT=4
export PKCS11PASSWORD=<password>
p11perftest --coverage ecdsa --keysizes ecnistp256 --threads 64 --iterations 200
```

## Common Flags

| Flag | Env Var | Purpose |
|------|---------|---------|
| `--library`, `-l` | `PKCS11LIB` | Path to PKCS#11 library |
| `--slot`, `-s` | `PKCS11SLOT` | Slot index (numeric, backend-specific) |
| `--password`, `-p` | `PKCS11PASSWORD` | Slot password/PIN |
| `--threads`, `-t` | — | Number of concurrent threads (default: 1) |
| `--iterations`, `-i` | — | Iterations per test (default: 200) |
| `--skip` | — | Skip N iterations before recording (for warmup) |
| `--coverage`, `-c` | — | Test cases: `ecdsa`, `rsa`, `aes`, `hmac`, `des` |
| `--keysizes`, `-k` | — | Key sizes/curves: `ecnistp256`, `ecnistp384`, `rsa2048`, `aes128`, etc. |
| `--json`, `-j` | — | Output JSON |
| `--jsonfile`, `-o` | — | Write JSON to file |

## Per-Backend Commands

### SoftHSMv2

**Library path**: `/usr/lib/softhsm/libsofthsm2.so`
**Slot convention**: Numeric (0-based)
**Credentials**: PIN (default `000000` if initialized with softhsm2-util)

```bash
p11perftest \
  -l /usr/lib/softhsm/libsofthsm2.so \
  -s 0 \
  -p 000000 \
  -t 1 \
  -i 200
```

**Multi-threaded sweep** (1 and 4 concurrent threads):

```bash
p11perftest \
  -l /usr/lib/softhsm/libsofthsm2.so \
  -s 0 \
  -p 000000 \
  -t 1 \
  -i 200 \
  -j -o softhsm2_t1.json

p11perftest \
  -l /usr/lib/softhsm/libsofthsm2.so \
  -s 0 \
  -p 000000 \
  -t 4 \
  -i 200 \
  -j -o softhsm2_t4.json
```

### AWS CloudHSM

**Library path**: `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`
**Slot convention**: Numeric; determined by `cloudhsm-client` configuration
**Credentials**: Customer CA certificate + HSM credentials (setup per AWS documentation)

**Configuration required**: Verify slot via `aws-cloudhsm` CLI or `p11tool` before running benchmarks.

```bash
p11perftest \
  -l /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
  -s <result> \
  -p <result> \
  -t 1 \
  -i 200
```

*Note: Exact slot and PIN depend on AWS CloudHSM customer account setup. See [AWS CloudHSM PKCS#11 documentation](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html).*

### GCP Cloud HSM

**Library path**: `/usr/lib/x86_64-linux-gnu/libkmsp11.so` (default; may vary by installation)
**Slot convention**: Numeric; mapped to GCP Cloud KMS key resources
**Credentials**: `PKCS11_KMS_APIKEY` environment variable (GCP service account JSON key path)

```bash
export PKCS11_KMS_APIKEY="/path/to/service-account-key.json"

p11perftest \
  -l /usr/lib/x86_64-linux-gnu/libkmsp11.so \
  -s <result> \
  -p <result> \
  -t 1 \
  -i 200
```

*Note: Slot and PIN mapping to GCP KMS resources is library-specific. Consult [Google Cloud KMS PKCS#11 provider documentation](https://github.com/GoogleCloudPlatform/kms-integrations).*

### Trustway Proteccio

**Library path**: `/lib/libnethsm.so`
**Slot convention**: Numeric (configured in `/etc/proteccio/proteccio.rc`)
**Credentials**: Slot password set at HSM initialization

```bash
export PKCS11LIB=/lib/libnethsm.so
export PKCS11SLOT=4
export PKCS11PASSWORD=<hsm_slot_password>

# Single thread (latency baseline)
p11perftest --coverage ecdsa --keysizes ecnistp256 --threads 1 --iterations 200 --skip 10 -j -o proteccio_t1.json

# 4 threads (low concurrency)
p11perftest --coverage ecdsa --keysizes ecnistp256 --threads 4 --iterations 200 --skip 10 -j -o proteccio_t4.json

# 64 threads (high concurrency; diagnose session pool limits)
p11perftest --coverage ecdsa --keysizes ecnistp256 --threads 64 --iterations 200 --skip 10 -j -o proteccio_t64.json
```

### Utimaco

**Library path**: `/lib/libcs_pkcs11_R3.so`
**Environment variable**: `CS_PKCS11_R3_CF` (points to Utimaco configuration)
**Slot convention**: Numeric
**Credentials**: PIN set at token initialization

```bash
export CS_PKCS11_R3_CF=/path/to/utimaco.conf

p11perftest \
  -l /lib/libcs_pkcs11_R3.so \
  -s <result> \
  -p <result> \
  -t 1 \
  -i 200
```

*Note: Exact slot and PIN are deployment-specific. See Utimaco SDK documentation for token initialization.*

### Crypt2Pay

**Library path**: `/lib/libpkcs11c2p.so`
**Slot convention**: Numeric (1-based); verify with `p11tool` before benchmarking
**Credentials**: PIN configured at device initialization

```bash
p11perftest \
  -l /lib/libpkcs11c2p.so \
  -s <result> \
  -p <result> \
  -t 1 \
  -i 200
```

*Note: Consult Crypt2Pay device manual for slot enumeration and PIN setup.*

### Kryoptic

**Library path**: Set via `KRYOPTIC_PKCS11_LIB` environment variable (default: `libkryoptic_pkcs11.so`)
**Configuration**: TOML file pointed to by `KRYOPTIC_CONF`
**Slot convention**: Numeric; defined in TOML config
**Credentials**: Software token (no physical HSM PIN required)

```bash
export KRYOPTIC_PKCS11_LIB=/path/to/libkryoptic_pkcs11.so
export KRYOPTIC_CONF=/path/to/kryoptic.toml

p11perftest \
  -l "${KRYOPTIC_PKCS11_LIB}" \
  -s <result> \
  -p <result> \
  -t 1 \
  -i 200
```

*Note: Kryoptic is a software PKCS#11 token; see [Kryoptic documentation](https://github.com/latchset/kryoptic) for TOML configuration.*

### SmartCard-HSM

**Library path**: `<result>`
**Slot convention**: <result>
**Credentials**: <result>

*Note: SmartCard-HSM support is documented in Eviden KMS but p11perftest command sourcing is unverified. Consult OpenSC project for SmartCard-HSM PKCS#11 library paths and initialization.*

---

## Common Flags Reference

| Flag | Default | Purpose |
|------|---------|---------|
| `-l, --library` | `PKCS11LIB` env var | Path to PKCS#11 shared library |
| `-s, --slot` | `PKCS11SLOT` env var | Slot index |
| `-p, --password` | `PKCS11PASSWORD` env var | Token PIN/password |
| `-t, --threads` | 1 | Concurrent threads |
| `-i, --iterations` | 200 | Iterations per test |
| `-c, --coverage` | `rsa,rsapss,ecdsa,ecdh,hmac,des,aes,xorder,rand,find,jwe,oaep,oaepenc,oaepunw` | Test operations |
| `-k, --keysizes` | `rsa2048,rsa3072,rsa4096,ecnistp256,ecnistp384,ecnistp521,hmac160,hmac256,hmac512,des128,des192,aes128,aes192,aes256` | Key sizes/curves |
| `-j, --json` | — | Output JSON |
| `-o, --jsonfile` | — | Write JSON to file |
| `-f, --flavour` | `generic` | Implementation flavour: `generic`, `luna`, `utimaco`, `entrust`, `marvell` |

## Notes

- **Unverified backends** (marked `<result>`): AWS CloudHSM, GCP Cloud HSM, Utimaco, Crypt2Pay, Kryoptic (TOML config), SmartCard-HSM. Exact slot and PIN values are deployment-specific; consult vendor documentation and `p11tool` introspection before running benchmarks.
- **SoftHSMv2 and Proteccio** commands are sourced from tested library paths in `documentation/docs/hsm_support/*.md`.
- For remote HSMs, ensure network connectivity and TLS certificates are correctly configured per vendor docs before running p11perftest.

# Synology DSM — NAS Volume Encryption with Cosmian KMS

Synology DiskStation Manager (DSM) 7.x supports delegating NAS volume encryption
key management to an external KMIP-compliant Key Management Server.  By
connecting a Synology NAS to Cosmian KMS, you ensure that volume encryption keys
are never stored on the NAS itself: they live in a centrally managed, audited,
and optionally HSM-backed key store.

---

## Overview

| Item | Details |
|------|---------|
| **Protocol** | KMIP 1.x over TCP/TLS with mutual certificate authentication |
| **Port** | 5696 (IANA-registered KMIP port) |
| **Key type** | AES-256 symmetric key |
| **DSM version** | DSM 7.1 and above |
| **Cosmian KMS feature** | Requires non-FIPS build (PKCS#12 TLS + AES-CBC key wrapping) |

### What Synology DSM does

When you configure an external KMS in DSM, the NAS performs the following KMIP
operations on every volume creation and every subsequent volume mount:

| Step | KMIP Operation | Purpose |
|------|---------------|---------|
| 1 | `DiscoverVersions` | Negotiate KMIP protocol version |
| 2 | `Query` | Enumerate server capabilities (6 query functions) |
| 3 | `Locate` | Check whether the volume key already exists |
| 4 | `Register` | Register a `SecretData` object (opaque 32-byte key material, KMIP 1.x `OperationPolicyName="default"` attribute included) |
| 5 | `Activate` | Transition the key from *PreActive* to *Active* state |
| 6 | `ModifyAttribute` | Rename the key to the volume UUID |
| 7 | `GetAttributes` | Verify key attributes (state, object type) |
| 8 | `Get` | Retrieve key material to mount the encrypted volume |
| 9 | `Locate` | Find the key by name after a NAS reboot |
| 10 | `Revoke` | Revoke the key during volume deletion or key rotation |
| 11 | `Destroy` | Delete the key from the KMS |

!!! note "Compatibility fixes"
    Two fixes were required for full Synology DSM 7.2.2 compatibility:

    - **`OperationPolicyName` (issue #796)**: DSM includes this KMIP 1.x attribute
      (deprecated in 1.3, removed in 2.0) in every `Register` request. The server
      now silently ignores it instead of emitting a confusing `WARN` log entry.
    - **`ModifyAttribute` (issue #760)**: DSM calls `ModifyAttribute` immediately after
      `Register` to rename the key to the volume UUID. This operation was not fully
      implemented and caused DSM to report "cannot create keys". It is now fully
      supported.

---

## Prerequisites

- Cosmian KMS server running in **non-FIPS** mode
- TLS enabled on the KMS server with a valid PKCS#12 certificate
- Client certificate and CA certificate for mutual TLS authentication
- DSM 7.1 or later with the **Encryption Key Manager** feature enabled
  (see *Control Panel → Security → Encryption Key Manager*)

---

## Server-Side Setup

### 1. Configure TLS

Synology DSM requires mutual certificate authentication over TLS.  Edit your
`kms.toml`:

```toml
[tls]
tls_p12_file    = "/etc/cosmian/kms/server.p12"
tls_p12_password = "your-p12-password"
clients_ca_cert_file = "/etc/cosmian/kms/clients-ca.crt"

[socket_server]
socket_server_start    = true
socket_server_port     = 5696        # standard KMIP port
socket_server_hostname = "0.0.0.0"
```

### 2. Issue a client certificate for the NAS

The NAS identifies itself to the KMS using a client TLS certificate signed by
the `clients_ca_cert_file` CA.  Use OpenSSL or the `cosmian` CLI to generate
the certificate:

```bash
# Generate a CA and a client certificate (example using OpenSSL)
openssl genrsa -out clients-ca.key 4096
openssl req -new -x509 -days 3650 -key clients-ca.key \
  -subj "/CN=KMS Clients CA" -out clients-ca.crt

openssl genrsa -out synology-nas.key 2048
openssl req -new -key synology-nas.key \
  -subj "/CN=synology-nas-01" -out synology-nas.csr
openssl x509 -req -days 3650 -in synology-nas.csr \
  -CA clients-ca.crt -CAkey clients-ca.key -CAcreateserial \
  -out synology-nas.crt
```

### 3. Start Cosmian KMS

```bash
cosmian_kms --config /etc/cosmian/kms/kms.toml
```

Or via Docker:

```bash
docker run -p 9998:9998 -p 5696:5696 \
  -v /etc/cosmian/kms:/etc/cosmian/kms:ro \
  -e COSMIAN_KMS_CONF=/etc/cosmian/kms/kms.toml \
  ghcr.io/cosmian/kms:latest
```

---

## DSM-Side Configuration

1. Log in to Synology DSM as an administrator.
2. Go to **Control Panel → Security → Encryption Key Manager**.
3. Click **Add KMS Server**.
4. Fill in the connection details:

| Field | Value |
|-------|-------|
| KMS Server Address | IP or hostname of the Cosmian KMS host |
| Port | 5696 |
| Client Certificate | PEM or PKCS#12 file you issued for the NAS |
| Private Key | Matching private key (if not bundled in PKCS#12) |
| CA Certificate | `clients-ca.crt` (the CA that signed the KMS server cert) |

1. Click **Test Connection** — DSM will run a `DiscoverVersions` + `Query` probe.
2. Click **Save**.

### Encrypting a volume

1. Open **Storage Manager**.
2. Select the volume you want to encrypt.
3. Click **Encrypt** and choose the KMS server you just configured.
4. DSM will call `Create → Activate → Get → GetAttributes` and mount the
   encrypted volume.

---

## Automated CI Testing

Because Synology DSM is proprietary hardware/software, there is no official
Docker image available for automated testing.  Instead, the Cosmian KMS test
suite includes a **Python simulation client** (`scripts/synology_dsm_client.py`)
that replays the exact KMIP operation sequence performed by DSM.

### Running the simulation locally

```bash
# Build KMS server (non-FIPS required)
cargo build --bin cosmian_kms --features non-fips

# Start the KMS server with KMIP socket enabled (uses scripts/kms.toml)
COSMIAN_KMS_CONF=scripts/kms.toml \
  cargo run --bin cosmian_kms --features non-fips &

# Wait until both ports are ready (HTTP: 9998, KMIP: 15696)
# Then run the DSM simulation
python3.11 scripts/synology_dsm_client.py \
  --configuration scripts/pykmip.conf \
  --verbose
```

Or use the convenience test runner:

```bash
bash scripts/test_synology_dsm.sh simulate
```

### Running via nix-shell (recommended for CI parity)

```bash
bash .github/scripts/nix.sh --variant non-fips test synology_dsm
```

### GitHub Actions CI

The Synology DSM simulation is included in the CI matrix in
`.github/workflows/test_all.yml` under the `synology_dsm` job (non-FIPS only):

```yaml
matrix:
  type:
    - ...
    - synology_dsm
  features: [fips, non-fips]
  exclude:
    - type: synology_dsm
      features: fips
```

The CI job:

1. Builds Cosmian KMS with `--features non-fips`.
2. Starts the server with TLS and the KMIP socket enabled.
3. Runs `scripts/synology_dsm_client.py` against it.
4. Asserts that all 10 steps (DiscoverVersions → Destroy) succeed.

---

## Simulation Script Reference

| Script | Purpose |
|--------|---------|
| `scripts/synology_dsm_client.py` | Python KMIP client replicating DSM's operation sequence |
| `scripts/test_synology_dsm.sh` | Local test runner (prereq checks + venv activation) |
| `.github/scripts/test_synology_dsm.sh` | CI entry point (builds server, starts it, runs test) |
| `scripts/pykmip.conf` | Shared PyKMIP TLS configuration (host, port, certs) |
| `scripts/kms.toml` | KMS server configuration used by KMIP tests |

---

## Troubleshooting

### DSM reports "Connection failed"

- Verify that port 5696 is reachable from the NAS (firewall rules).
- Confirm `socket_server_start = true` and `tls_p12_file` is set in `kms.toml`.
- Check KMS logs: `RUST_LOG=cosmian_kms_server=debug cargo run …`

### DSM reports "Certificate verification failed"

- The NAS client certificate must be signed by the CA listed in
  `clients_ca_cert_file` in `kms.toml`.
- The KMS server certificate must be trusted by the NAS.  Upload the server's CA
  certificate to DSM under **Control Panel → Security → Certificate**.

### ModifyAttribute returns an error

- Ensure you are running Cosmian KMS ≥ 5.17 which includes the `ModifyAttribute`
  fix for Synology DSM compatibility (issue #760).
- The operation requires the key to be in *Active* state.  Call `Activate` before
  `ModifyAttribute`.

### Key not found after NAS reboot

- DSM uses `Locate` with the key name to reconnect.  Ensure the key name is
  unique and consistent across reboots.
- Check that the client certificate presented on reconnect is the same one used
  at creation time (or that both have access rights granted in the KMS access
  policy).

### `OperationPolicyName` warning in server logs

Older DSM versions (using the KMIP 1.0 protocol) include an `OperationPolicyName`
attribute in their Register/Create requests.  This attribute was deprecated in
KMIP 1.3 and removed in KMIP 2.0+.  Cosmian KMS ≥ 5.18 silently ignores it
(issue [#796](https://github.com/Cosmian/kms/issues/796)).  Earlier versions log
a harmless `WARN` entry; the key operation still succeeds.

---

## Security Considerations

- **Mutual TLS**: Always require client certificate authentication
  (`clients_ca_cert_file` set in `kms.toml`) so that only authorised NAS
  devices can access keys.
- **Key access policy**: Use the Cosmian KMS
  [policy](../../documentation/docs/kmip_policy.md) to restrict each NAS to
  its own keys.
- **Key rotation**: Revoke and re-create keys periodically.  DSM will
  re-encrypt the volume DEK with the new KMS key on the next mount.
- **Audit logging**: Enable KMS access logs (`RUST_LOG=info`) and forward them
  to a SIEM for compliance.

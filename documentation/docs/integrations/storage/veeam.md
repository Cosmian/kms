# Veeam Backup & Replication — KMS Encryption Key Management

Veeam Backup & Replication supports delegating backup encryption key management
to an external KMIP-compliant Key Management Server.  By connecting Veeam to
Cosmian KMS, encryption keys for backup jobs are never stored on the Veeam
infrastructure itself: they are managed in a centrally audited, optionally
HSM-backed key store.

---

## Overview

| Item | Details |
|------|---------|
| **Protocol** | KMIP 1.4 over TCP/TLS with mutual certificate authentication |
| **Port** | 5696 (IANA-registered KMIP port) |
| **Key type** | RSA-2048 asymmetric key pair |
| **Veeam version** | Veeam Backup & Replication 12 and above |
| **Cosmian KMS feature** | Works with both FIPS and non-FIPS builds |

### What Veeam does

When you configure an external KMS in Veeam, the Veeam server performs the
following KMIP operations for each protected backup job:

| Step | KMIP Operation | Purpose |
|------|---------------|---------|
| 1 | `Locate` | Find an existing key by name / identifier |
| 2 | `Get` (PublicKey) | Retrieve the RSA public key to encrypt backup metadata |
| 3 | `CreateKeyPair` | Create a new RSA-2048 key pair when none exists |
| 4 | `Activate` | Transition the key pair from *PreActive* to *Active* state |
| 5 | `Get` (PrivateKey) | Retrieve the RSA private key for decryption during restore |
| 6 | `Destroy` | Delete the key pair on job removal or rotation |

!!! note "Compatibility fixes in Cosmian KMS"
    Two fixes were required for full Veeam Backup & Replication compatibility.
    Both are included in Cosmian KMS as of the version that introduced this
    documentation:

    - **`KeyValue` attributes in `Get` response (bug fix)**: Veeam's KMIP 1.4
      decoder for `PublicKey` and `PrivateKey` expects the `KeyValue` structure
      to contain only key material — it does not support any `Attribute`
      elements inside `KeyValue`.  Previous versions of Cosmian KMS embedded
      all object metadata attributes (state, identifiers, links, etc.) inside
      `KeyValue` when converting from the internal KMIP-2.1 representation to
      KMIP-1.4 wire format.  This caused Veeam to throw
      `KmipUnexpectedTagException: Unexpected Tag 66, expected Attribute` and
      abort the key retrieval.  The server now strips all attributes from
      `KeyValue` for asymmetric keys when responding to KMIP 1.x clients.

    - **TLS session ID context (bug fix)**: Veeam reuses KMIP connections via
      TLS session resumption.  When both `SSL_VERIFY_PEER` and OpenSSL session
      caching are active, OpenSSL requires a session-ID context to be set on
      the server acceptor.  Without it, session-resumption attempts fail with
      `ssl_get_prev_session:session id context uninitialized`, causing each
      reconnect to produce an SSPI authentication error on the Veeam side.
      The server now calls `SSL_CTX_set_session_id_context` during TLS acceptor
      initialisation.

---

## Prerequisites

- Cosmian KMS server **4.x or later** (both FIPS and non-FIPS builds are
  supported)
- TLS enabled on the KMS **socket server** (port 5696) with mutual certificate
  authentication
- A server TLS certificate and the corresponding CA to be trusted by Veeam
- A client certificate (signed by a CA known to the KMS) to authenticate Veeam

---

## Server-Side Setup

### 1. Configure TLS and the KMIP socket server

Edit your `kms.toml`:

```toml
[tls]
tls_p12_file     = "/etc/cosmian/kms/server.p12"
tls_p12_password = "your-p12-password"
clients_ca_cert_file = "/etc/cosmian/kms/clients-ca.crt"

[socket_server]
socket_server_start    = true
socket_server_port     = 5696
socket_server_hostname = "0.0.0.0"
```

### 2. Issue a client certificate for Veeam

Veeam identifies itself to the KMS using a client TLS certificate signed by
the `clients_ca_cert_file` CA:

```bash
# Generate a CA and a client certificate
openssl genrsa -out clients-ca.key 4096
openssl req -new -x509 -days 3650 -key clients-ca.key \
  -subj "/CN=KMS Clients CA" -out clients-ca.crt

openssl genrsa -out veeam-client.key 2048
openssl req -new -key veeam-client.key \
  -subj "/CN=veeam-backup-server" -out veeam-client.csr
openssl x509 -req -days 3650 -in veeam-client.csr \
  -CA clients-ca.crt -CAkey clients-ca.key -CAcreateserial \
  -out veeam-client.crt
```

Bundle the client certificate and key as a PKCS#12 file for import into Veeam:

```bash
openssl pkcs12 -export \
  -in veeam-client.crt -inkey veeam-client.key \
  -certfile clients-ca.crt \
  -out veeam-client.p12 -passout pass:veeam-p12-password
```

### 3. Start Cosmian KMS

```bash
cosmian_kms --config /etc/cosmian/kms/kms.toml
```

Or via Docker (note the `-p 5696:5696` for the KMIP socket port):

```bash
docker run -p 9998:9998 -p 5696:5696 \
  -v /etc/cosmian/kms:/etc/cosmian/kms:ro \
  -e COSMIAN_KMS_CONF=/etc/cosmian/kms/kms.toml \
  ghcr.io/cosmian/kms:latest
```

---

## Veeam-Side Configuration

1. In the Veeam Backup & Replication console, open
   **Menu → Manage Credentials** (or **Encryption Manager** depending on your
   version).
2. Add a new **KMS Server** with the following parameters:

| Field | Value |
|-------|-------|
| **Server name / IP** | Hostname or IP of your Cosmian KMS host |
| **Port** | `5696` |
| **Certificate** | Upload the PKCS#12 file (`veeam-client.p12`) |
| **Password** | The PKCS#12 password |
| **KMS CA Certificate** | Upload the KMS server CA certificate (`ca.crt` or the CA that signed the server certificate) |

1. Click **Test Connection**.  Veeam will perform a `Locate` probe against the
   server.  A successful test shows a green check-mark.
2. Assign the KMS server to a backup job under **Job Properties → Storage →
   Advanced → Encryption**.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `KmipUnexpectedTagException: Unexpected Tag 66, expected Attribute` | Old Cosmian KMS version (pre-fix) embedding attributes inside `KeyValue` | Upgrade Cosmian KMS |
| `A call to SSPI failed` / `SSL_ERROR_SSL` on reconnect | TLS session-ID context not set | Upgrade Cosmian KMS |
| `Test Connection` fails with certificate error | CA mismatch or self-signed cert | Verify `clients_ca_cert_file` contains the CA that signed the Veeam client cert, and that Veeam trusts the KMS server certificate |
| Key not found after Veeam server migration | Unique identifier stored by Veeam differs from KMS | Re-configure the KMS server entry in Veeam; the keys remain in the KMS store |

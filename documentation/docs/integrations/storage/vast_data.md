# VAST Data — Storage Encryption with Cosmian KMS

VAST Data storage clusters use KMIP for external encryption key management
(EKM). By connecting a VAST Data cluster to Cosmian KMS, you ensure that
data encryption keys (DEKs) and key encryption keys (KEKs) are centrally
managed, audited, and never stored unprotected on the storage appliance.

---

## Overview

| Item | Details |
|------|---------|
| **Protocol** | KMIP 1.4 binary TTLV over TCP/TLS with mutual certificate authentication |
| **Port** | 5696 (IANA-registered KMIP port) |
| **Key types** | AES-256 symmetric keys (KEK and DEK) |
| **Key wrapping** | AES Key Wrap RFC 3394 (NISTKeyWrap) |
| **VAST version** | VAST Data Platform 5.x and above |
| **Cosmian KMS mode** | FIPS and non-FIPS builds supported |

### What VAST Data does

When you configure an external KMS in the VAST Data management console, the
storage cluster performs the following KMIP operations for encryption key
lifecycle management:

| Step | KMIP Operation | Purpose |
|------|---------------|---------|
| 1 | `Create` | Create an AES-256 key (`OperationPolicyName("default")` attribute silently ignored) |
| 2 | `AddAttribute` | Add key metadata (group name, usage mask, custom tags) — called 1–3× after Create |
| 3 | `Activate` | Transition the key from *Pre-Active* to *Active* state |
| 4 | `Locate` | Find a key by its VAST-assigned name (`VAST_EKM_KEY_2_<uuid>_<index>`) |
| 5 | `Get` | Retrieve key material (plaintext or wrapped by KEK) |
| 6 | `GetAttributes` | Verify key state (`Active`) and `ActivationDate` |
| 7 | `ReKey` | Rotate an active key — generates new key material while keeping the same identifier |
| 8 | `Check` | Validate that a key satisfies the required `CryptographicUsageMask` |
| 9 | `Revoke` | Revoke a key during decommissioning or rotation |
| 10 | `Destroy` | Permanently delete the key from the KMS |

### KEK / DEK wrapping workflow

VAST uses a two-tier key hierarchy:

1. **KEK** (Key Encryption Key) — a long-lived AES-256 key with `WrapKey | UnwrapKey` usage.
2. **DEK** (Data Encryption Key) — a short-lived AES-256 key with `Encrypt | Decrypt` usage.

When VAST retrieves a DEK, it includes a `KeyWrappingSpecification` pointing to
the KEK. The KMS wraps the DEK with the KEK using **AES Key Wrap (RFC 3394)**
and returns the wrapped bytes. VAST then unwraps locally using its PyKMIP client's
`aes_key_unwrap` function.

!!! important "RFC 3394 vs. RFC 5649"
    VAST's PyKMIP client uses `aes_key_unwrap` (RFC 3394, no padding), **not**
    `aes_key_unwrap_padded` (RFC 5649). The Cosmian KMS correctly defaults to
    `NISTKeyWrap` (RFC 3394) when no `CryptographicParameters` are supplied in
    the `KeyWrappingSpecification`.

---

## Prerequisites

- Cosmian KMS server running (FIPS or non-FIPS mode)
- TLS enabled on the KMS with mutual certificate authentication
- Client certificate and CA certificate configured for the VAST cluster
- VAST Data Platform 5.x or later with External Key Manager (EKM) feature enabled

---

## Server-Side Setup

### 1. Configure TLS and socket server

VAST Data connects via the standard KMIP port (5696) using binary TTLV with
mutual TLS authentication. Configure your `kms.toml`:

```toml
[tls]
tls_cert_file       = "/etc/cosmian/kms/server.crt"
tls_key_file        = "/etc/cosmian/kms/server.key"
clients_ca_cert_file = "/etc/cosmian/kms/clients-ca.crt"

[socket_server]
socket_server_start    = true
socket_server_port     = 5696
socket_server_hostname = "0.0.0.0"
```

### 2. Generate client certificates

Create a client certificate for the VAST cluster signed by the same CA
configured in `clients_ca_cert_file`:

```bash
# Generate VAST client key and CSR
openssl genrsa -out vast-client.key 2048
openssl req -new -key vast-client.key -out vast-client.csr \
    -subj "/CN=vast-cluster-01/O=VAST Data"

# Sign with CA
openssl x509 -req -in vast-client.csr \
    -CA clients-ca.crt -CAkey clients-ca.key -CAcreateserial \
    -out vast-client.crt -days 365

# Convert to PKCS#12 for VAST (if required by your VAST version)
openssl pkcs12 -export -in vast-client.crt -inkey vast-client.key \
    -out vast-client.p12 -name "vast-cluster-01"
```

---

## VAST-Side Configuration

### 1. Navigate to EKM settings

In the VAST Data management console:

1. Go to **Settings → Security → External Key Manager**
2. Click **Add External KMS**

### 2. Enter KMS connection details

| Field | Value |
|-------|-------|
| **KMS Address** | `<kms-server-hostname>` |
| **KMS Port** | `5696` |
| **Client Certificate** | Upload `vast-client.crt` |
| **Client Key** | Upload `vast-client.key` |
| **CA Certificate** | Upload the CA that signed the KMS server certificate |

### 3. Test connection

Use the **Test Connection** button in the VAST management console to verify
connectivity. A successful test performs a `Create` + `Get` + `Destroy` cycle.

---

## Compatibility Notes

### KMIP 1.x attributes

VAST sends the `OperationPolicyName("default")` attribute in some requests.
This is a KMIP 1.x attribute that was deprecated in KMIP 1.3 and removed in
KMIP 2.0. The Cosmian KMS silently ignores this attribute with a log warning:

```text
WARN KMIP 2.1 does not support the KMIP 1 attribute OperationPolicyName("default")
```

This warning is informational and does not affect functionality.

### Key naming convention

VAST creates keys with structured names following the pattern:

```text
VAST_EKM_KEY_2_<encryption_group_uuid>_<index>
```

These names are used for `Locate` operations to find keys associated with
specific encryption groups.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `unsupported KMIP 1 operation: ReKey` | KMS version < 4.21.0 missing ReKey support | Upgrade Cosmian KMS to 4.21.0+ |
| `InvalidUnwrap` in VAST logs | KMS wrapping with RFC 5649 instead of RFC 3394 | Upgrade Cosmian KMS to 4.21.0+ (defaults to RFC 3394) |
| `OperationPolicyName` warnings in KMS logs | Normal — VAST sends this deprecated KMIP 1.x attribute | No action required; informational warning only |
| Connection refused on port 5696 | Socket server not enabled | Add `socket_server_start = true` to `kms.toml` |
| TLS handshake failure | Certificate mismatch or missing CA | Verify `clients_ca_cert_file` matches the CA that signed VAST's client cert |
| `tlsv1 alert decrypt error` (SSL alert 51) in KMS logs | VAST background reconnection attempt with stale connection state | Transient; no action required — the KMIP workflow itself is unaffected |

---

## Verified Operations

The following KMIP operations have been validated with VAST Data production
environments:

| Operation | Status | Notes |
|-----------|--------|-------|
| `Create` | ✅ | AES-256 with Name attribute; confirmed in production logs (2026-05-10) |
| `AddAttribute` | ✅ | Called 1–3× after Create to set group metadata; confirmed in production logs |
| `Activate` | ✅ | Transitions key to Active state |
| `Locate` | ✅ | By Name (UninterpretedTextString) |
| `Get` | ✅ | Plaintext and KEK-wrapped (RFC 3394) |
| `GetAttributes` | ✅ | State, ActivationDate |
| `ReKey` | ✅ | In-place key material rotation; confirmed in production logs (2026-05-10) |
| `Check` | ✅ | CryptographicUsageMask validation |
| `Revoke` | ✅ | Key revocation |
| `Destroy` | ✅ | Permanent key deletion |
| `DeriveKey` | ✅ | Parsed correctly (may return operation-level error depending on derivation method) |

# VAST Data — Storage Encryption with Eviden KMS

VAST Data storage clusters use KMIP for external encryption key management
(EKM). By connecting a VAST Data cluster to Eviden KMS, you ensure that
data encryption keys (DEKs) and key encryption keys (KEKs) are centrally
managed, audited, and never stored unprotected on the storage appliance.

---

## Overview

| Item | Details |
|------|---------|
| **Protocol** | KMIP 1.4 binary TTLV over HTTP/TLS with mutual certificate authentication |
| **Endpoint** | `POST /kmip` on the KMS HTTP port (default 9998) |
| **Key types** | AES-256 symmetric keys |
| **Key creation** | In batches of 2–3 keys per encryption group |
| **VAST version** | VAST Data Platform 5.x and above |
| **Eviden KMS mode** | FIPS and non-FIPS builds supported |

### What VAST Data does

When you configure an external KMS in the VAST Data management console, the
storage cluster performs the following KMIP operations for encryption key
lifecycle management:

| Step | KMIP Operation | Purpose |
|------|---------------|---------|
| 1 | `DiscoverVersions` | Session initialization handshake (once per connection) |
| 2 | `Create` | Create an AES-256 symmetric key (CryptographicUsageMask = Encrypt\|Decrypt) |
| 3 | `AddAttribute` ×3 | Set Name, ObjectGroup, and OperationPolicyName (3 calls per key) |
| 4 | `Activate` | Transition the key from *Pre-Active* to *Active* state |
| 5 | `Locate` | Find a key by its VAST-assigned name (`VAST_EKM_KEY_2_<uuid>_<index>`) |
| 6 | `Get` | Retrieve plaintext key material |
| 7 | `GetAttributes` | Verify key State (`Active`) and ActivationDate (polled every ~61 seconds) |
| 8 | `ReKey` | Rotate an active key — generates new key material with a **new** Unique Identifier |
| 9 | `Revoke` | Revoke a key during decommissioning |
| 10 | `Destroy` | Permanently delete the key from the KMS |

### Key lifecycle workflow

The following sequence diagram shows the complete lifecycle as observed in
production logs (May 2026):

```mermaid
sequenceDiagram
    participant V as VAST Data
    participant K as Eviden KMS

    Note over V,K: Session Start
    V->>K: DiscoverVersions (KMIP 1.4)

    Note over V,K: Key Creation (per encrypted path, 2–3 keys)
    loop For each key in group
        V->>K: Create (AES-256 SymmetricKey)
        V->>K: AddAttribute (Name)
        V->>K: AddAttribute (ObjectGroup)
        V->>K: AddAttribute (OperationPolicyName)
        V->>K: Activate
    end

    Note over V,K: Initial Key Fetch
    loop For each key
        V->>K: Locate (by name)
        V->>K: Get (plaintext key material)
    end

    Note over V,K: Continuous Monitoring (~61s interval)
    loop Forever
        loop For each key
            V->>K: Locate (by name)
            V->>K: GetAttributes (State, ActivationDate)
        end
    end

    Note over V,K: Key Rotation (triggered externally)
    loop For each key to rotate
        V->>K: Locate (find current key by name)
        V->>K: ReKey (returns new UID; old key stays Active)
        V->>K: Locate (verify new key by name)
        V->>K: Get (fetch new key material)
    end

    Note over V,K: Key Decommissioning (later, on encrypted path deletion)
    loop For each key to retire
        V->>K: Locate (find key by name)
        V->>K: Revoke (Active → Deactivated)
        V->>K: Locate (confirm state)
        V->>K: Destroy (permanently delete)
    end
```

### Key naming convention

VAST creates keys with structured names following the pattern:

```text
VAST_EKM_KEY_2_<encryption_group_uuid>_<index>
```

- `VAST_EKM_KEY_2_` — static prefix (version 2 of VAST's naming scheme)
- `<encryption_group_uuid>` — UUID identifying the encrypted path/group
- `_<index>` — 0-based index within the group (typically 0 or 1)

These names are used in `Locate` operations to find keys associated with
specific encryption groups. After `ReKey`, the name is transferred to the
new replacement key.

---

## Prerequisites

- Eviden KMS server running (FIPS or non-FIPS mode)
- TLS enabled on the KMS with mutual certificate authentication
- Client certificate and CA certificate configured for the VAST cluster
- VAST Data Platform 5.x or later with External Key Manager (EKM) feature enabled

---

## Server-Side Setup

### 1. Configure TLS

VAST Data connects via HTTP POST to `/kmip` using KMIP 1.4 binary TTLV with
mutual TLS authentication. Configure your `kms.toml`:

```toml
[tls]
tls_cert_file        = "/etc/cosmian/kms/server.crt"
tls_key_file         = "/etc/cosmian/kms/server.key"
clients_ca_cert_file = "/etc/cosmian/kms/clients-ca.crt"
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
| **KMS Port** | `9998` (default KMS HTTP port) |
| **Client Certificate** | Upload `vast-client.crt` |
| **Client Key** | Upload `vast-client.key` |
| **CA Certificate** | Upload the CA that signed the KMS server certificate |

### 3. Test connection

Use the **Test Connection** button in the VAST management console to verify
connectivity. A successful test performs a `Create` + `Get` + `Destroy` cycle.

---

## Compatibility Notes

### KMIP 1.x attributes

VAST sends the `OperationPolicyName("default")` attribute via `AddAttribute`
after key creation. This is a KMIP 1.x attribute that was deprecated in KMIP 1.3
and removed in KMIP 2.0. The Eviden KMS silently ignores this attribute with a
log warning:

```text
WARN KMIP 2.1 does not support the KMIP 1 attribute OperationPolicyName("default")
```

This warning is informational and does not affect functionality.

### `ReKey` behavior

When VAST sends a `ReKey` request, the KMS implements KMIP 2.1 §6.1.46:

1. The KMS creates a **new** symmetric key with a **new** Unique Identifier
2. The Name attribute is transferred from the old key to the new key
3. Bidirectional links are set: `ReplacementObjectLink` on old → new,
   `ReplacedObjectLink` on new → old
4. The **old key's State is unchanged** (it remains `Active`) — the KMIP spec
   does not deactivate the existing key during ReKey
5. VAST can then `Locate` by name and finds the new key

!!! important "New UUID after ReKey — old key remains Active"
    VAST expects the `ReKey` response to return a **different** Unique Identifier
    from the original. After rotation, the old key remains `Active` in the database.
    Later, when VAST decommissions an encrypted path, it sends `Locate` → `Revoke` →
    `Locate` → `Destroy` for each key to retire.

### Monitoring interval

VAST polls the KMS every **~61 seconds** per key with `Locate` + `GetAttributes`
to verify keys remain in `Active` state with a valid `ActivationDate`. This is
normal health-check behavior and produces high-volume but lightweight traffic.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `unsupported KMIP 1 operation: ReKey` | KMS version < 5.22.0 missing ReKey support | Upgrade Eviden KMS to 5.22.0+ |
| `OperationPolicyName` warnings in KMS logs | Normal — VAST sends this deprecated KMIP 1.x attribute | No action required; informational warning only |
| TLS handshake failure | Certificate mismatch or missing CA | Verify `clients_ca_cert_file` matches the CA that signed VAST's client cert |
| `tlsv1 alert decrypt error` (SSL alert 51) in KMS logs | VAST background reconnection attempt with stale connection state | Transient; no action required — the KMIP workflow itself is unaffected |
| Connection reset by peer (os error 104) | Network instability | Transient; VAST will reconnect automatically |

---

## Verified Operations

The following KMIP operations have been validated with VAST Data production
environments (logs from May 2026):

| Operation | Status | Notes |
|-----------|--------|-------|
| `DiscoverVersions` | ✅ | Session initialization; confirms KMIP 1.4 support |
| `Create` | ✅ | AES-256 SymmetricKey; 76 keys created across 5 days |
| `AddAttribute` | ✅ | Called 3× per key: Name, ObjectGroup, OperationPolicyName |
| `Activate` | ✅ | Transitions key to Active state |
| `Locate` | ✅ | By Name (UninterpretedTextString); ~11,800 calls over 5 days |
| `Get` | ✅ | Plaintext key material retrieval; 182 calls |
| `GetAttributes` | ✅ | State + ActivationDate; ~11,500 calls (monitoring) |
| `ReKey` | ✅ | Key rotation with new UUID; 16 rotations observed |
| `Revoke` | ✅ | Key revocation before destruction; 69 calls |
| `Destroy` | ✅ | Permanent key deletion; 69 calls |

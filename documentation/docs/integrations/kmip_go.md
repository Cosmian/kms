# KMIP Compliance with ovh/kmip-go

The Eviden KMS server is validated against
**[ovh/kmip-go](https://github.com/ovh/kmip-go)**, an independent, production-grade Go
implementation of the KMIP 1.0–1.4 protocol developed and maintained by
[OVHcloud](https://www.ovhcloud.com). The library is production-tested against the
OVHcloud KMS, making it a meaningful independent reference for verifying Eviden KMS
protocol conformance.

## Client / server roles

```mermaid
graph TD
    subgraph "ovh/kmip-go (Go client)"
        KC["kmipclient.Client\nKMIP 1.0 · 1.1 · 1.2 · 1.3 · 1.4"]
    end

    subgraph "Eviden KMS (server)"
        SS["Socket — port 15696\nmTLS / binary TTLV"]
        CORE["KMIP Operations"]
        DB[("Key store")]
    end

    KC -- "KMIP TTLV over TLS" --> SS
    SS --> CORE
    CORE --> DB

    style KC fill:#e3f2fd,stroke:#1976D2
    style SS fill:#fff3e0,stroke:#FF9800
    style CORE fill:#fff3e0,stroke:#FF9800
    style DB fill:#fce4ec,stroke:#E91E63
```

| Component | Role |
|-----------|------|
| **Eviden KMS** | **KMIP Server** — socket on port 15696, mTLS |
| **ovh/kmip-go** | **KMIP Client** — sends requests, validates responses against the spec |

The client connects to a live KMS instance with a pinned protocol version
(`kmipclient.EnforceVersion`), so the same binary validates all five wire-format
versions in the same run.

## Relationship with PyKMIP

```mermaid
graph LR
    PY["PyKMIP 0.10.0\n(Python — KMIP 1.2)"]
    GO["ovh/kmip-go 0.9.2\n(Go — KMIP 1.0 → 1.4)"]
    KMS["Eviden KMS\nport 15696"]

    PY -- "Synology DSM scenario\nKMIP 1.2" --> KMS
    GO -- "Full-range compliance\nKMIP 1.0 – 1.4" --> KMS

    style PY fill:#fffde7,stroke:#FFC107
    style GO fill:#e3f2fd,stroke:#1976D2
    style KMS fill:#e8f5e9,stroke:#388E3C
```

Both suites exercise the server as independent KMIP clients. PyKMIP covers a specific
device integration scenario; ovh/kmip-go covers all supported protocol versions
systematically.

---

## KMIP operations supported

The table below lists the KMIP operations the server exposes, the protocol versions at
which they are exercised, and the key objects or algorithms involved.

```mermaid
graph LR
    subgraph "Key lifecycle"
        CR[Create] --> AC[Activate] --> RV[Revoke] --> DS[Destroy]
    end
    subgraph "Attributes"
        GA[GetAttributes]
        GAL[GetAttributeList]
        AA[AddAttribute]
        MA[ModifyAttribute]
        DA[DeleteAttribute]
    end
    subgraph "Discovery"
        DV[DiscoverVersions]
        QU[Query]
    end
    subgraph "Object access"
        GT[Get]
        LO[Locate]
        CKP[CreateKeyPair]
    end
    subgraph "Cryptographic"
        EN[Encrypt]
        DE[Decrypt]
        SN[Sign]
        SV[SignatureVerify]
    end
    subgraph "Batch"
        BA[Batch — multi-op]
    end
```

| Operation | KMIP versions | Key objects / algorithms |
|-----------|---------------|--------------------------|
| `Create` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | AES-256 symmetric key |
| `Activate` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Transitions Pre-Active → Active |
| `Revoke` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Key compromise reason |
| `Destroy` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Permanent deletion |
| `Get` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Returns the managed object |
| `GetAttributes` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Version-filtered attribute set |
| `GetAttributeList` | 1.0 · 1.1 · 1.2 · 1.3 · 1.4 | Version-filtered attribute names |
| `AddAttribute` | 1.4 | Standard and `x-` custom attributes |
| `ModifyAttribute` | 1.4 | Enforces read-only rules per spec |
| `DeleteAttribute` | 1.4 | Response carries the deleted attribute |
| `Locate` | 1.4 | By UniqueIdentifier, Name, Object Group, Algorithm |
| `CreateKeyPair` | 1.4 | RSA-2048, EC P-256 |
| `DiscoverVersions` | 1.4 | Enumerates supported versions |
| `Query` | 1.4 | Reports supported operations |
| `Encrypt` | 1.2 · 1.4 | AES-256-GCM |
| `Decrypt` | 1.2 · 1.4 | AES-256-GCM round-trip |
| `Sign` | 1.4 | RSA-2048-PSS / SHA-256 |
| `SignatureVerify` | 1.4 | RSA-2048-PSS / SHA-256 |
| Batch | 1.4 | Multiple operations in one KMIP message |

---

## Attribute version-gating

The OASIS KMIP specification introduces attributes progressively. The server returns
only the attributes defined for the client's declared protocol version — returning a
newer attribute to an older client would violate the spec and break real-world clients
that have no decoder for it.

```mermaid
timeline
    title Attribute introduction per KMIP version
    section KMIP 1.0
        Core set : Unique Identifier · Object Type
                 : Cryptographic Algorithm · Cryptographic Length
                 : State · Initial Date · Lease Time
    section KMIP 1.1
        Fresh : Marks freshly generated key material
    section KMIP 1.2
        Alternative Name        : Alternate key identifiers
        Original Creation Date  : When the key material originated
    section KMIP 1.3
        Random Number Generator : RNG parameters
    section KMIP 1.4
        Sensitive               : Key material sensitivity flag
        Always Sensitive        : Historical sensitivity latch
        Extractable             : Whether key material can be exported
        Never Extractable       : Historical extractability latch
```

```mermaid
sequenceDiagram
    participant C12 as Client (KMIP 1.2)
    participant C14 as Client (KMIP 1.4)
    participant KMS as Eviden KMS

    Note over C12,KMS: Same key — two protocol versions

    C12->>KMS: GetAttributeList(uid)  [v1.2 wire]
    KMS-->>C12: [Unique Identifier, Object Type, …, Fresh]
    Note right of C12: Always Sensitive absent ✅

    C14->>KMS: GetAttributeList(uid)  [v1.4 wire]
    KMS-->>C14: [… Fresh, Always Sensitive, Extractable, …]
    Note right of C14: Always Sensitive present ✅
```

| Attribute | Not returned before | Returned from |
|-----------|-------------------|---------------|
| `Fresh` | KMIP 1.0 | KMIP 1.1 |
| `Alternative Name`, `Original Creation Date` | KMIP 1.0–1.1 | KMIP 1.2 |
| `Random Number Generator` | KMIP 1.0–1.2 | KMIP 1.3 |
| `Sensitive`, `Always Sensitive`, `Extractable`, `Never Extractable` | KMIP 1.0–1.3 | KMIP 1.4 |

---

## Attribute mutability

The KMIP specification defines, for every attribute, whether a client may modify or
delete it. The server enforces these rules.

```mermaid
sequenceDiagram
    participant C as Client (KMIP 1.4)
    participant KMS as Eviden KMS

    Note over C,KMS: KMIP 1.4 §3.23 — Initial Date is not modifiable by the client

    C->>KMS: ModifyAttribute(uid, "Initial Date", any-value)
    KMS-->>C: OperationFailed · Attribute_Read_Only ✅

    Note over C,KMS: KMIP 1.4 §3.47 — Comment is modifiable by the client

    C->>KMS: AddAttribute(uid, "Comment", "my-comment")
    KMS-->>C: Success ✅
    C->>KMS: ModifyAttribute(uid, "Comment", "updated")
    KMS-->>C: Success ✅
    C->>KMS: DeleteAttribute(uid, "Comment")
    KMS-->>C: Success + {deleted Attribute} ✅
```

Server-managed attributes — `Always Sensitive`, `Initial Date`, `Cryptographic Length`,
and others — are protected from client writes.
Client-managed attributes — `Name`, `Comment`, `Description`, custom `x-` attributes,
and others — support the full add / modify / delete lifecycle.

---

## Key lifecycle

```mermaid
stateDiagram-v2
    [*] --> PreActive : Create / Register
    PreActive --> Active : Activate
    Active --> Deactivated : Revoke
    Deactivated --> Destroyed : Destroy
    Destroyed --> [*]

    Active --> Active : Get · GetAttributes · GetAttributeList\nLocate · Encrypt · Decrypt\nSign · SignatureVerify
```

---

## Cryptographic operations

### Symmetric — AES-256-GCM

```mermaid
sequenceDiagram
    participant C as Client (KMIP 1.4)
    participant KMS as Eviden KMS

    C->>KMS: Create(AES-256, Encrypt|Decrypt)
    KMS-->>C: UniqueIdentifier
    C->>KMS: Activate(uid)
    C->>KMS: Encrypt(uid, AES-GCM, plaintext)
    KMS-->>C: {ciphertext, IV, AuthTag}
    C->>KMS: Decrypt(uid, AES-GCM, ciphertext, IV, AuthTag)
    KMS-->>C: plaintext
```

### Asymmetric — RSA-2048-PSS and EC P-256

```mermaid
sequenceDiagram
    participant C as Client (KMIP 1.4)
    participant KMS as Eviden KMS

    C->>KMS: CreateKeyPair(RSA-2048, Sign|Verify)
    KMS-->>C: {PrivateKeyUID, PublicKeyUID}
    C->>KMS: Activate(PrivateKeyUID) · Activate(PublicKeyUID)
    C->>KMS: Sign(PrivateKeyUID, RSA-PSS-SHA256, data)
    KMS-->>C: signature
    C->>KMS: SignatureVerify(PublicKeyUID, RSA-PSS-SHA256, data, signature)
    KMS-->>C: ValidityIndicator = Valid
```

---

## Running

```bash
# MISE task — builds KMS, starts server, runs tests, cleans up
mise run test:kmip-go

# Manual (KMS already running on port 15696)
cd .mise/scripts/kmip-go
KMIP_GO_REPO_ROOT=$(git rev-parse --show-toplevel) \
  go test -v -count=1 -timeout 120s ./...
```

The tests share the KMS configuration and test certificates used by the PyKMIP suite
(`kms.toml` and `test_data/certificates/client_server/`).

# Threat Model Diagram Conventions

Mermaid DFD conventions for the Eviden KMS threat model. Follow these rules exactly for every diagram to ensure visual consistency across analyses.

## Shape Conventions (DFD Level 0/1)

| Element Type | Mermaid Shape | Example |
|---|---|---|
| External entity (user, browser, cloud) | `actor` or rectangle `[name]` | `Browser["Browser / API Client"]` |
| Process (server component) | rounded rectangle `(name)` | `Auth("Auth Middleware")` |
| Data store (database, file) | cylinder `[(name)]` | `DB[("SQLite / PostgreSQL")]` |
| HSM / external hardware | hexagon `{{name}}` | `HSM{{"HSM (PKCS#11)"}}` |
| Trust boundary | subgraph with dashed border | `subgraph Internet["--- Internet ---"]` |

## Color Conventions

| Zone | Fill | Border | Meaning |
|------|------|--------|---------|
| Untrusted / Internet | `#ffd6d6` | `#cc0000` | External actors, internet |
| Semi-trusted | `#fff3cd` | `#cc8800` | Auth boundary |
| Trusted (internal) | `#d4edda` | `#008800` | Server internals |
| Data store | `#cce5ff` | `#0066cc` | Persistent storage |
| HSM / hardware | `#e2ccff` | `#6600cc` | Hardware trust anchor |

Apply colors using `style` or `classDef`:

```mermaid
classDef untrusted fill:#ffd6d6,stroke:#cc0000
classDef trusted fill:#d4edda,stroke:#008800
classDef datastore fill:#cce5ff,stroke:#0066cc
classDef hsm fill:#e2ccff,stroke:#6600cc
```

## Data Flow Arrow Conventions

| Arrow type | Mermaid syntax | Meaning |
|---|---|---|
| Normal data flow | `A --\|HTTPS/TLS\| B` | Standard request/response |
| Encrypted channel | `A ==\|mTLS\| B` | Mutually authenticated, encrypted |
| Trust boundary crossing | `A -.-\|JSON/TTLV\| B` | Crossing a trust boundary |
| Destructive/sensitive | `A --\|key material\| B` | Carry sensitive data |

## Level 0 — System Context Template

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc
    classDef hsm fill:#e2ccff,stroke:#6600cc

    subgraph Internet["Internet (Untrusted)"]
        Browser["Browser / ckms CLI"]:::untrusted
        CloudProvider["Cloud Provider<br/>(AWS XKS / Azure EKM)"]:::untrusted
    end

    subgraph KMSServer["KMS Server (Trusted)"]
        HTTP["Actix-web<br/>HTTP Layer"]:::trusted
        Auth["Auth Middleware<br/>(JWT / mTLS / API token)"]:::trusted
        Dispatcher["KMIP Dispatcher"]:::trusted
        Core["KMS Core<br/>(Operations)"]:::trusted
        Crypto["Crypto Oracles<br/>(OpenSSL 3.1.2 FIPS)"]:::trusted
    end

    DB[("Database<br/>(SQLite / PostgreSQL)")]:::datastore
    HSM{{"HSM<br/>(PKCS#11)"}}:::hsm

    Browser -.->|"HTTPS + KMIP/JSON"| HTTP
    CloudProvider -.->|"HTTPS + provider auth"| HTTP
    HTTP --> Auth
    Auth --> Dispatcher
    Dispatcher --> Core
    Core --> Crypto
    Core -->|"key blobs"| DB
    Core ==>|"PKCS#11 / mTLS"| HSM
```

## Level 1 — KMIP Request Flow Template

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    Client["Client<br/>(TTLV request)"]:::untrusted
    TLS["TLS & HTTP Route<br/>routes/kmip/handlers.rs"]:::trusted
    AuthMW["Middleware Stack (LIFO)<br/>Cors → AuditMiddleware<br/>→ wrap_native_auth<br/>→ ensure_auth_middleware"]:::trusted
    Deser["TTLV Deserializer<br/>crate/kmip/src/"]:::trusted
    Dispatch["Dispatcher<br/>dispatch.rs"]:::trusted
    OpHandler["Operation Handler<br/>core/operations/"]:::trusted
    ACL["Access Control Check<br/>crate/access/"]:::trusted
    CryptoOp["Crypto Operation<br/>crate/crypto/src/"]:::trusted
    DB[("Database")]:::datastore

    Client -->|"POST /kmip/2_1"| TLS
    TLS --> AuthMW
    AuthMW -->|"authenticated request"| Deser
    Deser --> Dispatch
    Dispatch --> OpHandler
    OpHandler --> ACL
    ACL -->|"allowed"| CryptoOp
    ACL -->|"denied → 403"| Client
    CryptoOp --> DB
    DB -->|"key blob"| CryptoOp
    CryptoOp -->|"KMIP response"| Client
```

KMIP HTTP handlers live in `crate/server/src/routes/kmip/handlers.rs` (`kmip_2_1_json`, `kmip`) and are mounted on `default_scope` in `crate/server/src/start_kms_server.rs`:

- Outer `.wrap()` (runs first on ingress, LIFO): `Cors` → `AuditMiddleware`.
- Inner `wrap_native_auth` (ingress execution order): `vault_token_optional_middleware` → `tls_auth_fn` → `jwt_auth_middleware` → `AuthVerifier` → `api_token_middleware` → `SessionAuth` → `ensure_auth_middleware`.

## Pre-Render Checklist

Before including any diagram in an output file:

- [ ] All nodes have correct shape for their element type
- [ ] All nodes have correct `classDef` color applied
- [ ] Trust boundary crossings use `-.->` arrows
- [ ] Sensitive data flows (key material) are labeled
- [ ] No orphaned nodes (every node has at least one edge)
- [ ] Diagram does not exceed 25 nodes (split into sub-diagrams if needed)
- [ ] Mermaid syntax is valid (no unmatched quotes or brackets)

## Common Mistakes

❌ Using `graph` instead of `flowchart` (prefer `flowchart` for DFDs)
❌ Forgetting to apply `classDef` to nodes
❌ Showing trust boundaries without `subgraph`
❌ Not labeling data flow arrows (unlabeled arrows hide what data flows)
❌ Combining architecture style and DFD style in the same diagram

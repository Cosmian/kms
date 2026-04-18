# Runtime Network Security Audit

!!! abstract "Scope"
    This report documents the **live runtime security assessment** methodology and expected results for the Cosmian KMS server.
    The analysis targets the running server process over the network — complementing [static source analysis](owasp_security_audit.md)
    and [multi-framework compliance](multi_framework_security_audit.md) reports.

    Run the analyser with:
    ```bash
    bash .github/scripts/audit/runtime_security.sh \
        --server-url https://HOST:PORT \
        [--cert client.pem] [--key client.key] [--ca ca.pem]
    ```

---

## Assessment Architecture

```mermaid
graph TD
    A([Security Analyst]) -->|"runtime_security.sh"| B[Runtime Analyser]
    B --> C[Reachability Probe]
    B --> D[TLS Inspector]
    B --> E[Certificate Chain]
    B --> F[HTTP Headers]
    B --> G[mTLS Verifier]
    B --> H[KMIP Protocol Probes]
    B --> I[Optional: nmap / sslyze / nuclei]

    C --> J[(cbom/runtime/)]
    D --> J
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J

    J --> K[runtime_results.json]
    J --> L[tls_analysis.txt]
    J --> M[certificate.pem]
    J --> N[http_headers.txt]
    J --> O[kmip_probes.json]
```

---

## Network & Attack Surface Map

```mermaid
graph LR
    subgraph Internet ["Public Internet / Zero-trust network"]
        C1([CLI client])
        C2([Web UI])
        C3([Enterprise app])
        A([Attacker])
    end

    subgraph DMZ ["DMZ / Load Balancer"]
        LB["TLS Termination or passthrough"]
    end

    subgraph KMS ["KMS Server Process"]
        direction TB
        P9998["Port 9998 — HTTPS/KMIP\n(main)"]
        AUTH["Auth middleware\n(JWT / mTLS / API-key)"]
        KMIP_ROUTE["KMIP 2.1 routes"]
        UI_ROUTE["Web UI routes\n/ui/"]
        HEALTH["Health — /version"]
    end

    subgraph DB ["Persistent Storage"]
        SQL[(SQLite / PostgreSQL\nRedis-findex)]
    end

    C1 -- "HTTPS + mTLS / JWT" --> LB
    C2 -- "HTTPS + auth cookie" --> LB
    C3 -- "HTTPS + API key" --> LB
    A -. "scan / probe" .-> LB

    LB --> P9998
    P9998 --> AUTH
    AUTH --> KMIP_ROUTE
    AUTH --> UI_ROUTE
    AUTH --> HEALTH
    KMIP_ROUTE --> SQL
```

!!! tip "Key attack surfaces"
    | Surface | Exposure | Mitigation |
    |---|---|---|
    | Port 9998 / KMIP endpoint | External | mTLS or JWT, TLS 1.2+ only |
    | Web UI | External | Cookie auth, CSP header |
    | `/version` health endpoint | External | Read-only, no secrets |
    | Server certificate | Public | Auto-renew, SHA-256+, RSA-2048+ |
    | Database | Internal only | Not exposed to network |

---

## TLS Security Scorecard

=== "Protocol Versions"

    ```mermaid
    graph LR
        S3("SSLv3") -- REJECT --> N1["POODLE — CVE-2014-3566"]
        T10("TLS 1.0") -- REJECT --> N2["BEAST / PCI-DSS deprecated"]
        T11("TLS 1.1") -- REJECT --> N3["Deprecated — RFC 8996"]
        T12("TLS 1.2") -- ACCEPT --> Y1["FIPS 140-3 minimum"]
        T13("TLS 1.3") -- ACCEPT --> Y2["Preferred — PFS enforced"]
        style S3  fill:#ef4444,color:#fff,stroke:#dc2626
        style T10 fill:#ef4444,color:#fff,stroke:#dc2626
        style T11 fill:#f97316,color:#fff,stroke:#ea580c
        style T12 fill:#22c55e,color:#fff,stroke:#16a34a
        style T13 fill:#16a34a,color:#fff,stroke:#15803d
        style N1  fill:#fee2e2,color:#991b1b,stroke:#fca5a5
        style N2  fill:#fee2e2,color:#991b1b,stroke:#fca5a5
        style N3  fill:#ffedd5,color:#9a3412,stroke:#fdba74
        style Y1  fill:#dcfce7,color:#166534,stroke:#86efac
        style Y2  fill:#dcfce7,color:#166534,stroke:#86efac
    ```

    | Protocol | Expected | Reason |
    |---|---|---|
    | **SSLv3** | ❌ Rejected | POODLE attack (CVE-2014-3566) |
    | **TLS 1.0** | ❌ Rejected | BEAST, POODLE, deprecated PCI-DSS 3.2 |
    | **TLS 1.1** | ❌ Rejected | Deprecated per RFC 8996 |
    | **TLS 1.2** | ✅ Accepted | Minimum for FIPS 140-3 |
    | **TLS 1.3** | ✅ Accepted | Preferred — mandatory for new deployments |

=== "Cipher Suites"

    ```mermaid
    pie title Accepted Cipher Suites by Category
        "ECDHE-AESGCM (strong)" : 4
        "DHE-AESGCM (PFS)" : 2
        "AES256-SHA256 (compat)" : 1
        "Weak / rejected" : 0
    ```

    | Category | Example Cipher | Status | FIPS 140-3 | Forward Secrecy |
    |---|---|---|---|---|
    | ECDHE-RSA-AES256-GCM-SHA384 | TLS 1.2 ECDHE | ✅ Allowed | ✅ | ✅ |
    | ECDHE-RSA-AES128-GCM-SHA256 | TLS 1.2 ECDHE | ✅ Allowed | ✅ | ✅ |
    | TLS_AES_256_GCM_SHA384 | TLS 1.3 | ✅ Allowed | ✅ | ✅ |
    | TLS_CHACHA20_POLY1305_SHA256 | TLS 1.3 | ✅ Allowed | ⚠️ non-FIPS only | ✅ |
    | NULL / aNULL | Export | ❌ Rejected | ❌ | ❌ |
    | RC4 / DES / 3DES | Legacy | ❌ Rejected | ❌ | ❌ |
    | MD5-based | Legacy | ❌ Rejected | ❌ | ❌ |
    | EXPORT-grade | Legacy | ❌ Rejected | ❌ | ❌ |

=== "TLS Handshake Flow"

    ```mermaid
    sequenceDiagram
        participant C as Client
        participant S as KMS Server (TLS 1.3)
        C->>S: ClientHello (supported protocols, ciphers)
        S-->>C: ServerHello (TLS 1.3, TLS_AES_256_GCM_SHA384)
        S-->>C: Certificate (RSA-2048 / ECDSA-256, SHA-256 signed)
        S-->>C: CertificateVerify
        S-->>C: Finished
        C->>S: [Optional] Certificate (mTLS)
        C->>S: Finished
        Note over C,S: Symmetric keys derived from ephemeral ECDHE<br/>(Perfect Forward Secrecy)
        C->>S: POST /kmip/2_1 (encrypted)
        S-->>C: KMIP ResponseMessage (encrypted)
    ```

---

## Certificate Chain Analysis

```mermaid
graph TB
    ROOT["Root CA\nself-signed or public CA\nKey: RSA-4096 or EC-384\nSig: SHA-256"]
    INTER["Intermediate CA optional\nKey: RSA-2048 or EC-256\nSig: SHA-256 Valid: 3 years"]
    LEAF["KMS Server Certificate\nSAN: kms.example.com\nKey: RSA-2048 or EC-256\nSig: SHA-256 Valid: 1 year max"]
    ROOT --> INTER
    INTER --> LEAF
```

!!! check "Certificate requirements"
    - Key algorithm: RSA ≥ 2048 bits **or** EC ≥ P-256
    - Signature: SHA-256 minimum (SHA-1 rejected by modern browsers and RFC 9155)
    - SAN: must match server hostname — bare CN no longer sufficient (RFC 2818)
    - Expiry: warning at 30 days; auto-renewal recommended (ACME/Let's Encrypt)
    - OCSP stapling: recommended for client-side revocation checking

---

## HTTP Security Headers

```mermaid
graph LR
    subgraph Required ["Required Headers"]
        HSTS["Strict-Transport-Security\nmax-age=31536000 includeSubDomains"]
        XCTO["X-Content-Type-Options: nosniff"]
    end
    subgraph Recommended ["Recommended Headers"]
        XFO["X-Frame-Options: DENY"]
        CSP["Content-Security-Policy\ndefault-src self"]
        CC["Cache-Control: no-store"]
    end
    subgraph Avoid ["Must not disclose"]
        SRV["Server: omit or generic"]
        CORS_W["CORS wildcard forbidden on KMIP"]
    end
```

| Header | Expected Value | Importance | OWASP |
|---|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | **Required** | A05 |
| `X-Content-Type-Options` | `nosniff` | **Required** | A05 |
| `X-Frame-Options` | `DENY` | Recommended | A05 |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'` | Recommended | A03 |
| `Cache-Control` | `no-store` on API routes | Recommended | A02 |
| `Server` | Empty or generic | Avoid disclosure | A05 |
| `CORS` on `/kmip/*` | None or restricted origin | **Required** | A01 |

---

## mTLS Authentication Model

=== "Architecture"

    ```mermaid
    sequenceDiagram
        participant CLI as ckms CLI
        participant KMS as KMS Server
        participant DB as Database

        CLI->>KMS: TLS ClientHello
        KMS-->>CLI: ServerHello + Certificate
        KMS-->>CLI: CertificateRequest (if mTLS mode)
        CLI->>KMS: Certificate (client cert, signed by trusted CA)
        CLI->>KMS: CertificateVerify
        Note over CLI,KMS: TLS session established
        CLI->>KMS: POST /kmip/2_1 (encrypted TTLV)
        KMS->>KMS: Extract CN from client cert → username
        KMS->>DB: Look up access control for user
        KMS-->>CLI: KMIP Response
    ```

=== "Auth modes"

    | Mode | How it works | When to use |
    |---|---|---|
    | **mTLS** | Client presents X.509 certificate signed by trusted CA | Internal services, CLI tooling |
    | **JWT (OAuth2)** | Bearer token from Auth0 / Keycloak / OIDC provider | Web UI, end-user access |
    | **API key** | Shared secret in header | Machine-to-machine, simple integrations |
    | **No auth** | Disabled — dev/test only (`--auth-type none`) | Local development only |

    !!! warning
        Never deploy with `--auth-type none` in production.
        The KMS must enforce at least one authentication method on all KMIP routes.

=== "mTLS test"

    ```bash
    # Test mTLS with ckms-generated certs
    bash .github/scripts/audit/runtime_security.sh \
        --server-url https://localhost:9998 \
        --cert test_data/certs/client.crt \
        --key  test_data/certs/client.key \
        --ca   test_data/certs/server_ca.crt
    ```

---

## KMIP Protocol Security Probes

```mermaid
flowchart TD
    P1["Empty payload probe\nPOST /kmip/2_1 {}"] -->|"Expected: 400/422"| OK1([PASS])
    P2["Oversized BatchCount\nBatchCount: 99999"] -->|"Expected: 400/422/413"| OK2([PASS])
    P3["SQL injection in UID\n'OR 1=1; DROP TABLE"] -->|"Expected: 400/422/401"| OK3([PASS])
    P4["70 MiB payload\nAbove 64 MiB limit"] -->|"Expected: 400/413"| OK4([PASS])
    P5["Rate limit probe\n10 rapid requests"] -->|"429 expected for excess"| OK5([PASS / INFO])

    style OK1 fill:#22c55e,color:#fff
    style OK2 fill:#22c55e,color:#fff
    style OK3 fill:#22c55e,color:#fff
    style OK4 fill:#22c55e,color:#fff
    style OK5 fill:#84cc16,color:#fff
```

| Probe | Payload | Expected HTTP | Risk if wrong |
|---|---|---|---|
| Empty KMIP request | `{}` | 400 or 422 | Server crash / 500 |
| OversizedBatchCount | `BatchCount: 99999` | 400, 422, or 413 | DoS / OOM |
| SQL injection in UID | `' OR '1'='1'; DROP ...` | 400, 422, 401 | SQL injection |
| 70 MiB payload | Random bytes | 400 or 413 | DoS / memory exhaustion |
| Rapid 10 requests | Empty KMIP | 422 (or 429 if rate-limit active) | Brute-force |

---

## Threat Model (STRIDE)

```mermaid
mindmap
  root((KMS Server\nAttack Surface))
    Spoofing
      Fake client certificate
      JWT token forgery
      MITM on HTTP
    Tampering
      Replay KMIP request
      Key ID enumeration
      Packet injection
    Repudiation
      Missing audit log
      Log injection
    Information Disclosure
      TLS version downgrade
      Server header leaks version
      Error message leaks DB schema
    Denial of Service
      OversizedBatchCount
      Large payload flood
      TLS session exhaustion
    Elevation of Privilege
      CORS wildcard on KMIP
      JWT scope confusion
      Insecure object ownership
```

| Threat | STRIDE | Mitigation | Status |
|---|---|---|---|
| MITM — weak TLS version | Tampering | TLS 1.2+ enforced; SSLv3/TLS1.0/1.1 rejected | ✅ Mitigated |
| Weak cipher negotiation | Tampering | NULL/RC4/DES/EXPORT rejected by server | ✅ Mitigated |
| Certificate spoofing | Spoofing | mTLS or JWT required; CA pinning optional | ✅ Mitigated |
| SQL injection via UID | Tampering | Parameterised queries in all DB backends | ✅ Mitigated |
| OOM via large batch | DoS | BatchCount validated; payload size limit 64 MiB | ✅ Mitigated |
| Rate-based brute-force | DoS | Rate limiting middleware (configurable) | ⚠️ Configurable |
| Server version disclosure | Info Disclosure | `Server` header suppressed | ✅ Mitigated |
| CORS wildcard on KMIP | Elevation of Privilege | No CORS header on `/kmip/*` | ✅ Mitigated |
| Expired certificate | Spoofing | 30-day expiry warning in checker | ✅ Monitored |
| Insecure direct object refs | Elevation of Privilege | Object ownership enforced in DB | ✅ Mitigated |

---

## Running the Analyser

### Prerequisites

```bash
# Required (always present on Linux)
openssl version   # ≥ 3.0
curl --version    # ≥ 7.68

# Optional — enable richer analysis when installed
apt-get install nmap                  # port scan + TLS NSE scripts
pip3 install sslyze                   # deep TLS / cert-transparency analysis
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  # template scanner
```

### Basic run (plain HTTPS)

```bash
bash .github/scripts/audit/runtime_security.sh \
    --server-url https://localhost:9998 \
    --insecure    # skip cert verification on self-signed cert
```

### Full run with mTLS

```bash
bash .github/scripts/audit/runtime_security.sh \
    --server-url https://kms.prod.example.com:9998 \
    --cert  certs/client.crt \
    --key   certs/client.key \
    --ca    certs/ca.crt \
    --report documentation/docs/certifications_and_compliance/audit/runtime_security_audit_latest.md
```

### Output files

```text
cbom/runtime/
├── runtime_results.json   ← machine-readable summary (all checks + status)
├── tls_analysis.txt       ← raw openssl s_client output
├── cert_details.txt       ← openssl x509 -text of server certificate
├── certificate.pem        ← server certificate in PEM format
├── http_headers.txt       ← HTTP response headers
├── mtls_analysis.txt      ← mTLS negotiation log
├── kmip_probes.json       ← KMIP protocol probe results
├── nmap.txt               ← nmap scan (if installed)
├── sslyze.json            ← sslyze report (if installed)
└── nuclei.txt             ← nuclei scan (if installed)
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All checks passed |
| `1` | One or more FAIL findings (critical) |
| `2` | Tool error (missing required utility or bad arguments) |

---

## Integration with CI

Add to `.github/workflows/main_base.yml` as a post-deploy smoke test:

```yaml
- name: Runtime Security Scan
  run: |
    bash .github/scripts/audit/runtime_security.sh \
      --server-url https://localhost:9998 \
      --insecure \
      --report cbom/runtime_security_report.md
  env:
    KMS_URL: https://localhost:9998
```

!!! note "Relation to other security reports"
    | Report | Layer | Tool |
    |---|---|---|
    | [OWASP Source Audit](owasp_security_audit.md) | Static — source code | `scan_source.py` + `risk_score.py` |
    | [Multi-framework Audit](multi_framework_security_audit.md) | Static — policy compliance | `multi_framework.sh` |
    | **Runtime Security Audit** (this file) | Dynamic — running server | `runtime_security.sh` |

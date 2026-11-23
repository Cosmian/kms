# Data Flow Diagram — Eviden KMS

**Analysis date**: 2026-11-14
**Scope**: Full repository, branch `rbac_rego` at commit `17926f40b` (PR #998, workspace version 5.29.0)
**Analyst**: AI Threat Model Analyst

The data flow diagrams are split by concern so that each one stays readable on a landscape page. Level 0 shows the system context. Level 1.1 to 1.3 follow a request from the network edge to the authorization chain. Levels 1.4 to 1.8 cover persistence, cloud provider routes, PKI routes, client-side components and the build pipeline. Trust boundary identifiers (TB1 to TB13) match `0-architecture.md`, and the last section maps every boundary to the diagrams and findings that concern it.

## Legend

| Element | Mermaid shape | Meaning |
| --- | --- | --- |
| Process | Rounded rectangle | Code that runs inside a trusted or semi-trusted component |
| External entity | Plain rectangle | A caller, a service or an actor outside the KMS process |
| Data store | Cylinder | Database, file, cache or secret store |
| HSM | Hexagon | PKCS#11 device or software token |
| Red fill, dashed red frame | Untrusted zone | Internet clients, tenants, third parties |
| Yellow fill | Semi-trusted | Identity and policy services, client-side components |
| Green fill | Trusted | KMS server process |
| Blue fill | Data store | Persistence |
| Purple fill | HSM | Hardware boundary |
| Dotted arrow | Trust boundary crossing | Data leaves one zone for another |
| Thick arrow | Key-bearing or mutually authenticated flow | HSM sessions, mTLS identity paths |

## Level 0 — System Context

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000
    classDef hsm fill:#e2ccff,stroke:#6600cc,color:#000

    subgraph ZU["Untrusted zone: clients and Internet"]
        KCL["KMIP clients: ckms CLI, WASM client,<br/>PKCS#11 module, Windows CNG KSP,<br/>Kubernetes CSI, operator, KMS plugin"]:::untrusted
        BRW["Web UI browser<br/>(SPA)"]:::untrusted
        CLD["Cloud callers: AWS XKS,<br/>Azure EKM, Google CSE, MS DKE"]:::untrusted
        PKI["PKI clients: EST, SCEP,<br/>OCSP, CRL"]:::untrusted
        WLD["Workload clients:<br/>SPIRE, Vault API"]:::untrusted
    end

    subgraph ZK["KMS server process (trusted)"]
        KMS("Cosmian KMS server<br/>HTTP/TLS edge, authentication,<br/>KMIP dispatcher, authorization,<br/>crypto (OpenSSL 3.6.5 FIPS provider)"):::trusted
    end

    subgraph ZS["Semi-trusted identity and policy services"]
        IDP["OIDC identity<br/>provider"]:::semi
        AVR["Auth Verifier<br/>(authentication server)"]:::semi
        OPA["OPA policy server"]:::semi
    end

    subgraph ZD["Persistence and hardware"]
        DB[("Database: SQLite, PostgreSQL,<br/>MySQL, Redis-Findex")]:::datastore
        AUD[("Audit log and<br/>OTLP collector")]:::datastore
        HSM{{"HSM via PKCS#11"}}:::hsm
    end

    EXT["External endpoints: CRL distribution<br/>points, legacy KACLS"]:::untrusted

    KCL -.->|"KMIP over HTTPS or mTLS"| KMS
    BRW -.->|"HTTPS and session cookie"| KMS
    CLD -.->|"HTTPS and SigV4 or JWT"| KMS
    PKI -.->|"public HTTP routes"| KMS
    WLD -.->|"SVID or Vault token"| KMS
    KMS -.->|"JWKS fetch, login"| IDP
    KMS -.->|"token verification"| AVR
    KMS -.->|"allow or deny query"| OPA
    KMS -->|"key blobs, permissions"| DB
    KMS ==>|"PKCS#11 session"| HSM
    KMS -.->|"audit events, traces"| AUD
    KMS -.->|"CRL fetch, KACLS rewrap"| EXT

    style ZU fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZK fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
    style ZS fill:#fffbee,stroke:#cc8800,stroke-dasharray:6 4
    style ZD fill:#f2f8ff,stroke:#0066cc,stroke-dasharray:6 4
```

## Level 1.1 — KMIP Request Flow: HTTP Edge and Authentication Pipeline

The HTTP listener applies the app-wide middleware, then the native authentication stack, then `ensure_auth`, then the optional audit middleware, and finally the KMIP handler. The KMIP socket server is a separate entry point: it requires mutual TLS, derives the identity from the certificate common name, and bypasses both the OPA scope and the audit middleware.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000

    CL["Client<br/>(KMIP over HTTPS, REST, browser)"]:::untrusted
    SCL["KMIP socket client"]:::untrusted

    subgraph ZE["KMS server process: HTTP edge (trusted)"]
        TLS("TLS termination<br/>TLS 1.2+, resumption off,<br/>client certificate optional"):::trusted
        APP("App-wide middleware<br/>session cookie, identity, security headers,<br/>rate limiter (off by default), OTel"):::trusted
        AUTH("Native auth stack, first valid method wins<br/>vault token, mTLS CN, IdP JWT,<br/>Auth Verifier, API token, UI session cookie"):::trusted
        ENS("ensure_auth<br/>401 if any method is configured,<br/>otherwise identity is default_username"):::trusted
        AUD("Audit middleware<br/>opt-in, wraps only /v1/crypto<br/>and the default scope"):::trusted
        HND("KMIP handler<br/>get_user, OPA scope from token claims"):::trusted
        SSRV("KMIP socket server<br/>mTLS mandatory, identity is the CN,<br/>no OPA scope, not audited"):::trusted
    end

    IDP["IdP JWKS endpoint"]:::semi
    AVS["Auth Verifier<br/>JWKS and whoami liveness"]:::semi
    SPI["SPIRE or Vault<br/>lookup-self"]:::semi
    DB[("Database<br/>API token key")]:::datastore
    ASINK[("Audit sink")]:::datastore
    DSP("Dispatcher<br/>see Level 1.2"):::trusted

    CL -.->|"HTTPS"| TLS
    TLS --> APP
    APP --> AUTH
    AUTH --> ENS
    ENS --> AUD
    AUD --> HND
    HND -->|"UserId, roles, domain"| DSP
    AUTH -.->|"JWKS fetch"| IDP
    AUTH -.->|"signature, liveness"| AVS
    AUTH -.->|"token lookup"| SPI
    AUTH -->|"token compare"| DB
    AUD -->|"audit events"| ASINK
    SCL -.->|"mTLS, KMIP binary"| SSRV
    SSRV -->|"UserId from CN"| DSP

    style ZE fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
```

## Level 1.2 — KMIP Request Flow: Dispatcher, Authorization and Core

The dispatcher enforces the role gate and the Create gate, but only the KMIP entry points reach it. JOSE, tokenize, SPIRE transit, Google CSE, AWS XKS, Microsoft DKE and Azure EKM call core operations directly, so the role gate, the algorithm policy and the OPA scope do not apply to them. OPA is consulted from object retrieval and from the Create gate and fails closed.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000
    classDef hsm fill:#e2ccff,stroke:#6600cc,color:#000

    HND("KMIP HTTP handler<br/>UserId, roles, domain"):::trusted
    SSRV("KMIP socket server<br/>UserId from CN, no roles"):::trusted
    NK("Non-KMIP routes: JOSE, tokenize, SPIRE transit,<br/>CSE, XKS, DKE, Azure EKM<br/>(call core operations directly, dispatcher not involved)"):::trusted

    subgraph ZC["KMS core (trusted)"]
        DSP("Dispatcher<br/>role gate (skipped when no Crypto Officer),<br/>Create gate, algorithm policy"):::trusted
        OPS("Operation handler<br/>one file per KMIP operation"):::trusted
        RET("Object retrieval<br/>owner or grant check,<br/>state check"):::trusted
        PERM("Permission engine<br/>Create gate, Crypto Officer ceremony,<br/>role decision"):::trusted
        STO("Object store facade<br/>at-rest KEK wrap"):::trusted
        CRY("Crypto oracle<br/>OpenSSL FIPS provider"):::trusted
    end

    OPA["OPA server<br/>5 s timeout, fail-closed,<br/>no authentication or TLS"]:::semi
    DB[("Database")]:::datastore
    HSM{{"HSM via PKCS#11"}}:::hsm

    HND -->|"TTLV request"| DSP
    SSRV -->|"TTLV request"| DSP
    NK --> OPS
    DSP -->|"Create, Import, Register"| PERM
    DSP --> OPS
    OPS --> RET
    RET -.->|"allow or deny, by mode"| OPA
    RET --> STO
    OPS --> CRY
    PERM -->|"grants, ceremony rows"| DB
    STO --> DB
    STO ==>|"HSM-backed keys"| HSM

    style ZC fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
```

## Level 1.3 — Authentication Methods and Identity Mapping

Every credential type converges on one flat `UserId` namespace: the identity string carries no issuer, realm or method prefix. A caller that can obtain a certificate, a JWT or a session whose identity string equals another user's identity string is that user. The last row of the authentication column is the fail-open fallback used when no method is configured.

```mermaid
flowchart TB
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000

    subgraph ZU["Credential holders (untrusted)"]
        BRW["Browser user"]:::untrusted
        API["API or CLI client"]:::untrusted
        CRT["Client with certificate"]:::untrusted
        WLD["SPIRE workload"]:::untrusted
        ANO["Caller without credential"]:::untrusted
    end

    subgraph ZE["KMS authentication layer (trusted)"]
        BFF("UI backend for frontend<br/>OIDC code flow, PKCE, nonce,<br/>issues the sealed session cookie"):::trusted
        SES("Session cookie check<br/>sealed, no server-side state,<br/>no revocation, 24 h Max-Age"):::trusted
        JWT("IdP JWT check<br/>alg allow-list, iss, exp,<br/>aud only if configured"):::trusted
        AVC("Auth Verifier token check<br/>JWKS signature, whoami liveness,<br/>bearer not realm-bound"):::trusted
        TOK("API token<br/>constant-time compare"):::trusted
        TLSA("mTLS identity<br/>CN mapping, EST certs refused,<br/>no CRL or OCSP check"):::trusted
        SVD("SPIRE or Vault token<br/>lookup-self, 30 s cache"):::trusted
        DEF("Fallback: no method configured<br/>identity is default_username"):::trusted
    end

    L1["OIDC provider<br/>token endpoint"]:::semi
    L2["Authentication server<br/>login_as"]:::semi
    L3[("Cookie sealing key<br/>process memory")]:::datastore
    L4["OIDC provider<br/>JWKS endpoint"]:::semi
    L5["Authentication server<br/>JWKS and whoami"]:::semi
    L6[("Database<br/>API token key")]:::datastore
    L7["Client CA bundle<br/>(server config)"]:::semi
    L8["SPIRE server or Vault"]:::semi
    L9["Server config<br/>default_username"]:::semi

    UID("UserId, roles, domain<br/>flat namespace, no issuer prefix"):::trusted
    CORE("KMS core<br/>authorization, see Level 1.2"):::trusted

    BRW -.->|"login redirect"| BFF
    BRW -.->|"auth_session cookie"| SES
    API -.->|"Bearer IdP JWT"| JWT
    API -.->|"Bearer session JWT or _ea_ cookie"| AVC
    API -.->|"API token header"| TOK
    CRT -.->|"client certificate"| TLSA
    WLD -.->|"SVID or Vault token"| SVD
    ANO -.->|"no credential"| DEF

    BFF -.->|"code exchange"| L1
    BFF -.->|"login_as"| L2
    SES -->|"unseal"| L3
    JWT -.->|"JWKS"| L4
    AVC -.->|"JWKS, whoami"| L5
    TOK -->|"read key"| L6
    TLSA -->|"verify chain"| L7
    SVD -.->|"lookup-self"| L8
    DEF -->|"read"| L9

    L1 ~~~ UID
    L2 ~~~ UID
    L3 ~~~ UID
    L4 ~~~ UID
    L5 ~~~ UID
    L6 ~~~ UID
    L7 ~~~ UID
    L8 ~~~ UID
    L9 ~~~ UID

    BFF --> UID
    SES --> UID
    JWT --> UID
    AVC --> UID
    TOK --> UID
    TLSA --> UID
    SVD --> UID
    DEF --> UID
    UID --> CORE

    style ZU fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZE fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
```

## Level 1.4 — Persistence, At-Rest Protection and HSM Store

Key blobs reach the database through the object store facade. Wrapping with a server KEK is optional and carries no additional authenticated data. SQL backends keep the owner, state and uid in clear columns, so a party with database write access can rewrite them. Redis-Findex encrypts each object with the uid as associated data.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000
    classDef hsm fill:#e2ccff,stroke:#6600cc,color:#000

    subgraph ZK["KMS server process (trusted)"]
        OPS("KMIP operations:<br/>Create, Get, Export, Wrap,<br/>Import, Revoke, Destroy"):::trusted
        FAC("Object store facade"):::trusted
        WRAP("At-rest wrap with server KEK<br/>(optional, no AAD)"):::trusted
        UWC("Unwrapped-key cache<br/>(in memory)"):::trusted
        CO("Crypto Officer ceremony<br/>(sealed record, AAD is the role)"):::trusted
        CONS("Constraint store<br/>(memory only)"):::trusted
        HSS("HSM store"):::trusted
        NCH("HSM negative cache<br/>(3600 s)"):::trusted
    end

    KEK["KEK and master secret source:<br/>file, environment, secret backend"]:::semi

    subgraph ZD["Persistence zone"]
        SQL[("SQLite, PostgreSQL, MySQL<br/>owner, state, uid in clear columns")]:::datastore
        RDS[("Redis with Findex<br/>AEAD per object, uid as AAD")]:::datastore
    end

    HSM{{"PKCS#11 HSM<br/>(software, network or cloud)"}}:::hsm
    DBA["Database administrator or<br/>stolen database credential"]:::untrusted

    OPS --> FAC
    FAC -->|"plain key blob"| WRAP
    KEK -.->|"key material at startup"| WRAP
    WRAP -->|"wrapped blob, plain columns"| SQL
    FAC -->|"AEAD blob, index entries"| RDS
    FAC --> UWC
    OPS -->|"activation check"| CO
    CO -->|"sealed ceremony rows"| SQL
    CO --> CONS
    OPS --> HSS
    HSS --> NCH
    HSS ==>|"PKCS#11 session, key export"| HSM
    DBA -.->|"direct row write"| SQL
    DBA -.->|"direct key write"| RDS

    style ZK fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
    style ZD fill:#f2f8ff,stroke:#0066cc,stroke-dasharray:6 4
```

## Level 1.5 — Cloud Provider Routes (Google CSE, AWS XKS, Azure EKM, Microsoft DKE)

Each provider scope has its own authentication, CORS and audit wiring, and none passes through the KMIP dispatcher. The scopes call core operations directly, so the permission model that protects the KMIP interface is applied only through the per-object owner and grant checks inside those operations.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000
    classDef hsm fill:#e2ccff,stroke:#6600cc,color:#000

    subgraph ZU["Cloud callers (untrusted)"]
        GWS["Google Workspace client<br/>and Google services"]:::untrusted
        ANY["Any caller holding a token<br/>from the configured IdP"]:::untrusted
        AWS["AWS KMS<br/>(XKS proxy caller)"]:::untrusted
        AZR["Azure EKM service"]:::untrusted
        MSD["Microsoft DKE client<br/>(Purview)"]:::untrusted
    end

    subgraph ZK["KMS server process: provider scopes (trusted)"]
        CSE("/google_cse scope<br/>no auth middleware, permissive CORS,<br/>JWT checked inside each handler,<br/>privilegedunwrap not restricted to KACLS,<br/>holds the CSE AES and RSA migration keys"):::trusted
        XKS("/aws scope<br/>SigV4 middleware, one static key,<br/>body fully buffered before the check,<br/>permissive CORS"):::trusted
        EKM("/azure_ekm scope<br/>mTLS client certificate required,<br/>skipped if client auth is disabled,<br/>default CORS"):::trusted
        DKE("/ms_dke scope<br/>ensure_auth with all native methods,<br/>permissive CORS with credentials"):::trusted
        OPS("Core operations called directly<br/>Get, Encrypt, Decrypt, Wrap, Unwrap<br/>no dispatcher role gate, no audit"):::trusted
    end

    GIDP["Google IdP and<br/>Workspace JWKS"]:::semi
    KACLS["Source KACLS endpoint<br/>(rewrap migration)"]:::untrusted
    DB[("Database")]:::datastore
    HSM{{"HSM via PKCS#11"}}:::hsm

    GWS -.->|"Bearer JWT"| CSE
    ANY -.->|"privilegedunwrap"| CSE
    AWS -.->|"SigV4 request"| XKS
    AZR -.->|"mTLS request"| EKM
    MSD -.->|"HTTPS and token"| DKE
    CSE -.->|"fetch JWKS"| GIDP
    CSE -.->|"rewrap POST"| KACLS
    CSE --> OPS
    XKS --> OPS
    EKM --> OPS
    DKE --> OPS
    OPS -->|"key blobs, permissions"| DB
    OPS ==>|"HSM-backed keys"| HSM

    style ZU fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZK fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
```

## Level 1.6 — PKI and Enrolment Routes (EST, SCEP, OCSP, CRL)

The OCSP responder and the CRL distribution point are public by design (RFC 6960 and RFC 5280). EST and SCEP are registered at application level and authenticate inside their handlers. The only outbound HTTP from the PKI code is the CRL fetch performed by Validate and Import.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000
    classDef hsm fill:#e2ccff,stroke:#6600cc,color:#000

    subgraph ZU["PKI callers (untrusted)"]
        DEV["Device or agent<br/>(EST and SCEP enrolment)"]:::untrusted
        RP["Relying party<br/>(OCSP request, CRL download)"]:::untrusted
        USR["Authenticated user<br/>(CRL generation, Validate, Import)"]:::untrusted
    end

    subgraph ZK["KMS server process: PKI routes (trusted)"]
        EST("EST and SCEP handlers<br/>registered at app level,<br/>client certificate, Basic or CMS signature"):::trusted
        GUARD("Enrolment guard<br/>first-enrolment trust, CPU semaphore,<br/>constant-time API token compare"):::trusted
        OCSP("OCSP responder<br/>public, opt-in, no authentication,<br/>signs every request"):::trusted
        CRLP("Public CRL distribution point<br/>serves the persisted CRL"):::trusted
        GEN("CRL generation<br/>user authenticated, validity_days not capped,<br/>signs with the CA key"):::trusted
        VAL("Validate and Import<br/>CRL fetch: body read before size cap,<br/>literal-IP SSRF guard only"):::trusted
        CACHE("CRL cache<br/>no entry limit"):::trusted
    end

    CADB[("Database<br/>certificates, CRLs, revocation state")]:::datastore
    HSM{{"HSM or software CA key"}}:::hsm
    CDP["CRL distribution points<br/>(external HTTP servers)"]:::untrusted

    DEV -.->|"enrolment request"| EST
    EST -->|"authorize caller"| GUARD
    GUARD -->|"issue certificate"| CADB
    RP -.->|"OCSP request"| OCSP
    RP -.->|"GET CRL"| CRLP
    OCSP -->|"status lookup, response signing"| CADB
    CRLP -->|"read stored CRL"| CADB
    USR -.->|"GET crl for issuer"| GEN
    GEN -->|"persist signed CRL"| CADB
    USR -.->|"Validate, Import"| VAL
    VAL -.->|"fetch CRL"| CDP
    VAL -->|"cache response"| CACHE
    CADB ==>|"CA private key use"| HSM

    style ZU fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZK fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
```

## Level 1.7 — Client-Side Components and Kubernetes Integrations

The Kubernetes components and the desktop clients are separate trust domains that hold KMS credentials. The CSI provider and the KMSSecret operator each use one global KMS identity for every tenant, so tenant isolation is only as strong as the Kubernetes-side checks in front of them. The `ckms` configuration file holds tokens and secrets in clear text.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000

    subgraph ZT["Tenant and application zone (untrusted)"]
        TEN["Namespace tenant: creates<br/>SecretProviderClass or KMSSecret,<br/>or supplies a KMS v2 key_id"]:::untrusted
        APP["Applications using<br/>PKCS#11 or Windows CNG"]:::untrusted
        USR["Operator or user<br/>running ckms and the SPA"]:::untrusted
    end

    subgraph ZC["Client-side components (semi-trusted)"]
        CSI("Secrets Store CSI provider<br/>one global KMS identity,<br/>kmsUID and object_name taken from the request"):::semi
        OPR("KMSSecret operator<br/>watches all namespaces,<br/>one global KMS identity"):::semi
        PLG("KMS v2 encryption plugin<br/>unix socket, decrypts under the<br/>key_id of the request"):::semi
        P11("PKCS#11 module<br/>advertises Sensitive, serves CKA_VALUE"):::semi
        CNG("Windows CNG KSP<br/>export policy hardcoded to allowed"):::semi
        CLI("ckms CLI and WASM client"):::semi
        CFG[("ckms.toml<br/>tokens and secrets in clear text,<br/>default file mode")]:::datastore
    end

    KAPI["Kubernetes API server,<br/>kubelet and etcd"]:::semi
    KMS("KMS server<br/>KMIP over HTTPS"):::trusted

    TEN -.->|"SecretProviderClass, KMSSecret"| KAPI
    KAPI -->|"mount request"| CSI
    KAPI -->|"watch events"| OPR
    KAPI -->|"Encrypt and Decrypt"| PLG
    OPR -->|"namespaced Secret writes,<br/>workload restarts"| KAPI
    APP -->|"PKCS#11 calls"| P11
    APP -->|"NCrypt calls"| CNG
    USR -->|"commands, login"| CLI
    CLI -->|"reads and saves"| CFG
    CSI ==>|"Get with the global identity"| KMS
    OPR ==>|"Get with the global identity"| KMS
    PLG ==>|"Encrypt and Decrypt"| KMS
    P11 -.->|"KMIP over HTTPS"| KMS
    CNG -.->|"KMIP over HTTPS"| KMS
    CLI -.->|"KMIP over HTTPS"| KMS

    style ZT fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZC fill:#fffbee,stroke:#cc8800,stroke-dasharray:6 4
```

## Level 1.8 — Build, Release and Supply Chain

Third-party code enters at build time through crates.io, pnpm and the OpenSSL tarball, and through GitHub Actions pinned to full commit SHAs. The release and publish jobs hold long-lived repository secrets, and eight jobs run on self-hosted runners with the host SSH key mounted.

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000,color:#000
    classDef semi fill:#fff3cd,stroke:#cc8800,color:#000
    classDef trusted fill:#d4edda,stroke:#008800,color:#000
    classDef datastore fill:#cce5ff,stroke:#0066cc,color:#000

    subgraph ZS["Source and third-party inputs"]
        DEVR["Contributor<br/>(fork or branch pull request)"]:::untrusted
        REPO[("Git repository and submodules<br/>authentication, kmip, test_data,<br/>reusable_scripts, theme")]:::datastore
        UPS["Third-party code at build time<br/>crates.io crates, pnpm packages,<br/>OpenSSL tarball (SHA-256 pinned),<br/>Actions pinned to a full SHA"]:::semi
    end

    subgraph ZR["CI jobs"]
        SECS[("Repository secrets<br/>PAT, crates.io token, GPG key,<br/>test and cloud credentials")]:::datastore
        RELJ("Release, publish and docs jobs<br/>hold the PAT and the crates.io token"):::trusted
        PKGJ("Package and image jobs<br/>8 jobs on self-hosted runners mount the<br/>host SSH key into a mutable root image"):::trusted
    end

    subgraph ZA["Released artifacts"]
        REG["crates.io"]:::semi
        REL["GitHub release assets<br/>deb, rpm, apk, tarballs,<br/>Windows installers"]:::semi
        IMG["Container images and<br/>Helm chart (cosign keyless)"]:::semi
        DOC["Generated docs and SBOM<br/>committed back to the repository"]:::semi
    end

    OPR["Operators and customers"]:::untrusted

    DEVR -.->|"pull request, no secrets for forks"| REPO
    REPO -->|"checkout"| ZR
    UPS -.->|"dependencies and tools"| ZR
    SECS -->|"PAT and crates.io token"| RELJ
    SECS -->|"GPG key, test credentials"| PKGJ
    RELJ -->|"cargo publish"| REG
    RELJ -->|"generate docs and SBOM"| DOC
    PKGJ -->|"build and sign packages"| REL
    PKGJ -->|"build images"| IMG
    DOC -->|"commit back"| REPO
    REG -.->|"cargo install"| OPR
    REL -.->|"download"| OPR
    IMG -.->|"pull"| OPR

    style ZS fill:#fff5f5,stroke:#cc0000,stroke-dasharray:6 4
    style ZR fill:#f4fbf5,stroke:#008800,stroke-dasharray:6 4
    style ZA fill:#fffbee,stroke:#cc8800,stroke-dasharray:6 4
```

## Notes

### Trust boundary crossings and where they appear

| Boundary | Crossing | Diagram | Findings that concern it |
| --- | --- | --- | --- |
| TB1 | Network edge to HTTPS listener | Level 0, 1.1, 1.5, 1.6 | F-003, F-005, F-006, F-026, F-029, F-030 |
| TB2 | Network edge to KMIP socket server | Level 1.1 | F-015, F-040 |
| TB3 | Credential to identity (native authentication stack) | Level 1.1, 1.3 | F-001, F-004, F-014, F-015, F-020, F-022, F-024, F-033, F-034, F-036, F-046 |
| TB4 | Identity to authorization (dispatcher, role gate, object permissions) | Level 1.2 | F-003, F-008, F-009, F-010, F-022, F-031, F-037, F-038, F-039 |
| TB5 | KMS core to OPA | Level 1.2 | F-049 |
| TB6 | KMS core to database | Level 1.4 | F-007, F-019, F-027 |
| TB7 | KMS core to HSM | Level 1.4 | F-011 |
| TB8 | KMS to identity infrastructure (IdP, Auth Verifier, SPIRE or Vault) | Level 1.1, 1.3 | F-001, F-004, F-034, F-036 |
| TB9 | Cloud service to provider routes | Level 1.5 | F-002, F-005, F-013, F-026, F-035 |
| TB10 | KMS to outbound networks (CRL distribution points, legacy KACLS) | Level 1.5, 1.6 | F-025, F-032, F-041 |
| TB11 | Kubernetes tenants to cluster components to KMS | Level 1.7 | F-021, F-023, F-044 |
| TB12 | User host to KMS (CLI, PKCS#11, CNG, configuration files) | Level 1.7 | F-017, F-028, F-043, F-045 |
| TB13 | Source to CI to released artifacts | Level 1.8 | F-012, F-016, F-047, F-048 |

### Unusual flows worth noting

- **The KMIP socket server is a second entry point with weaker policy coverage.** It maps the certificate common name to a `UserId` and calls `handle_ttlv_bytes` directly. The role gate applies, but no OPA scope is installed and the audit middleware is not involved.
- **Non-KMIP routes bypass the dispatcher.** JOSE, tokenize, SPIRE transit, Google CSE, AWS XKS, Microsoft DKE and Azure EKM call core operations directly, so the role gate and the algorithm policy (`kmip.policy_id`) do not run for them. Object-level owner and grant checks still apply inside the operations that have them.
- **A session cookie of the Auth Verifier is a bearer token for the KMS.** The signed JWT stored behind an Auth Verifier session is accepted by the KMS bearer path. That is what makes the unauthenticated `/sessions` API of the Auth Verifier a KMS-level risk (F-001).
- **The `/v1/auth/{tail}` route of the SPIRE and Vault scope is an unauthenticated proxy** to a fixed Auth Verifier host. The host is fixed and dot segments are filtered, so it is recorded as a clean control and not as a finding.
- **The only outbound HTTP originating from request handling** is the CRL fetch of Validate and Import, the legacy KACLS POST of the Google CSE rewrap, the JWKS and token-endpoint calls of the authentication layer, and the OPA query. The OPA query carries no authentication and no TLS.
- **Secrets that live in process memory or configuration:** the XKS SigV4 secret, the CSE AES key and RSA migration key, the session sealing key, the API token key (stored in the database) and the OIDC client secrets. They are not drawn as separate flows.

### Not drawn

The deb and rpm packaging assets, the HSM vendor loaders under `crate/hsm/` and the Vault-compatible transit and PKI facade are listed in `0-architecture.md` but are not drawn separately. The monitoring stack under `monitoring/` is a development aid and appears only as an unverified hardening note (R-17) in the appendix of `3-findings.md`. The STRIDE matrix in `2-stride-analysis.md` covers the modelled components.

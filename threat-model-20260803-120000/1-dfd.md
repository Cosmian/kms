# Data Flow Diagram — KMS Authentication Subsystem (Spire Branch)

## Level 0 — Authentication System Context

```mermaid
flowchart LR
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef semitrusted fill:#fff3cd,stroke:#cc8800
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    subgraph Internet["Internet (Untrusted)"]
        SPIREClient["SPIRE Agent\n(SPIFFE workload)"]:::untrusted
        Browser["Browser\n(UI user)"]:::untrusted
        CLI["ckms CLI\n(API token / JWT)"]:::untrusted
    end

    subgraph AuthBoundary["--- Auth Trust Boundary ---"]
        subgraph MiddlewareStack["Middleware Stack (LIFO)"]
            CorsMW["Cors MW"]:::trusted
            VaultMW["Vault Token MW\n(X-Vault-Token)"]:::semitrusted
            TLSMW["TLS Auth MW\n(mTLS cert)"]:::trusted
            JWTMW["JWT Auth MW\n(OIDC Bearer)"]:::semitrusted
            ApiTokenMW["API Token MW\n(Bearer)"]:::trusted
            SessionMW["Session Auth MW\n(cookie)"]:::trusted
            AuthVerifierMW["Auth Verifier MW\n(Cosmian JWT)"]:::semitrusted
            EnsureMW["Ensure Auth MW\n(fallback)"]:::trusted
        end
    end

    subgraph AuthVerifierZone["Auth Verifier (External)"]
        AuthVerifier["Auth Verifier Server\n(JWKS + lookup-self)"]:::semitrusted
    end

    KMIPHandler["KMIP / Transit / PKI\nHandlers"]:::trusted
    DB[("Database\n(SQLite/PostgreSQL)")]:::datastore

    SPIREClient -.->|"X-Vault-Token"| VaultMW
    Browser -.->|"session cookie\n_EA_"| SessionMW
    CLI -.->|"Bearer JWT/API token"| JWTMW
    CLI -.->|"Bearer Auth Verifier JWT"| AuthVerifierMW

    VaultMW ==|"GET /auth/token/lookup-self\n(HTTPS)"| AuthVerifier
    JWTMW ==|"GET /.well-known/jwks.json\n(HTTPS)"| AuthVerifier
    AuthVerifierMW ==|"GET /.well-known/jwks.json\n(HTTPS)"| AuthVerifier

    CorsMW --> VaultMW
    VaultMW --> TLSMW
    TLSMW --> JWTMW
    JWTMW --> ApiTokenMW
    ApiTokenMW --> SessionMW
    SessionMW --> AuthVerifierMW
    AuthVerifierMW --> EnsureMW
    EnsureMW -->|"AuthenticatedUser"| KMIPHandler
    KMIPHandler -->|"key blobs"| DB
```

## Level 1 — SPIRE Token Validation Flow

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef semitrusted fill:#fff3cd,stroke:#cc8800
    classDef trusted fill:#d4edda,stroke:#008800
    classDef datastore fill:#cce5ff,stroke:#0066cc

    Client["SPIRE Agent"]:::untrusted
    ExtractHdr["Extract X-Vault-Token\nfrom header"]:::trusted
    HashToken["SHA-256(token)\n→ hash_bytes"]:::trusted
    CacheLookup{"SpireTokenCache\n.lookup(hash)"}:::trusted
    CacheHit["Return cached\nSpireAuthenticatedUser"]:::trusted
    CallAuthVerifier["GET /auth/token/lookup-self\n→ auth_verifier_url"]:::semitrusted
    ParseResponse["Parse entity_id + policies\nfrom JSON response"]:::trusted
    ValidateEntity["validated_entity():\nreject empty + default_username\n collision"]:::trusted
    CacheInsert["cache.insert(hash, user)\nTTL = 30s"]:::trusted
    InjectUser["Inject AuthenticatedUser\n+ SpireAuthenticatedUser\ninto request extensions"]:::trusted
    Reject["403 Forbidden"]:::untrusted

    Client -->|"X-Vault-Token: <token>"| ExtractHdr
    ExtractHdr --> HashToken
    HashToken --> CacheLookup
    CacheLookup -->|"hit"| CacheHit
    CacheLookup -->|"miss"| CallAuthVerifier
    CallAuthVerifier -->|"HTTP 200"| ParseResponse
    CallAuthVerifier -->|"HTTP error / timeout"| Reject
    ParseResponse --> ValidateEntity
    ValidateEntity -->|"valid"| CacheInsert
    ValidateEntity -->|"empty/collision"| Reject
    CacheInsert --> InjectUser
    CacheHit --> InjectUser
    InjectUser -->|"continue to handler"| Client
```

## Level 2 — Auth Proxy Flow (Unauthenticated)

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef trusted fill:#d4edda,stroke:#008800
    classDef semitrusted fill:#fff3cd,stroke:#cc8800

    Client["SPIRE Agent"]:::untrusted
    AuthProxy["Auth Proxy\nPOST /v1/auth/{tail}"]:::trusted
    PathCheck{"path_has_dot_segment()\nreject . / .. / %2e / \\"}:::trusted
    StripPrefix["Strip /v1 prefix\n→ /auth/{tail}"]:::trusted
    ForwardHeaders["Forward: X-Vault-Token,\nContent-Type, Authorization"]:::trusted
    ForwardBody["Forward raw body"]:::trusted
    AuthVerifier["Auth Verifier Server\n/auth/{tail}"]:::semitrusted
    ReturnResponse["Return status + body\nbyte-for-byte"]:::trusted
    Reject400["400 Bad Request\n(path traversal)"]:::untrusted
    Reject502["502 Bad Gateway\n(auth-verifier unreachable)"]:::untrusted

    Client -->|"POST /v1/auth/approle/login"| AuthProxy
    AuthProxy --> PathCheck
    PathCheck -->|"clean"| StripPrefix
    PathCheck -->|"dot segment"| Reject400
    StripPrefix --> ForwardHeaders
    ForwardHeaders --> ForwardBody
    ForwardBody -->|"HTTPS"| AuthVerifier
    AuthVerifier -->|"response"| ReturnResponse
    AuthVerifier -->|"unreachable"| Reject502
    ReturnResponse --> Client
```

## Level 3 — Auth Verifier JWT Validation Flow

```mermaid
flowchart TD
    classDef untrusted fill:#ffd6d6,stroke:#cc0000
    classDef semitrusted fill:#fff3cd,stroke:#cc8800
    classDef trusted fill:#d4edda,stroke:#008800

    Client["API Client"]:::untrusted
    ExtractBearer["extract_bearer_token()\nfrom Authorization header"]:::trusted
    DecodeHeader["decode_header(token)\n→ header.alg"]:::trusted
    AlgCheck{"alg ∈ ALLOWED?\n(RS*, ES*, PS*)"}:::trusted
    FetchJWKS{"JWKS cache\n.find_any()"}:::semistrusted
    ForceRefresh{"cache empty?\n→ force_refresh()"}:::semistrusted
    TryAllKeys["Try each JWK →\ndecode + validate signature"]:::trusted
    ExtractSub["Extract sub claim\n→ username"]:::trusted
    Reject401["401 Unauthorized"]:::untrusted

    Client -->|"Bearer <JWT>"| ExtractBearer
    ExtractBearer --> DecodeHeader
    DecodeHeader --> AlgCheck
    AlgCheck -->|"yes"| FetchJWKS
    AlgCheck -->|"no (HS*, none)"| Reject401
    FetchJWKS -->|"empty"| ForceRefresh
    FetchJWKS -->|"keys found"| TryAllKeys
    ForceRefresh -->|"refreshed"| TryAllKeys
    ForceRefresh -->|"still empty"| Reject401
    TryAllKeys -->|"one validates"| ExtractSub
    TryAllKeys -->|"all fail"| Reject401
    ExtractSub -->|"AuthenticatedUser"| Client
```

## Notes

- **Auth Proxy is unauthenticated by design**: The `/v1/auth/*` scope has no auth middleware. This is intentional — SPIRE agents need to authenticate *through* the auth-verifier (AppRole login, token lookup). The path traversal protection (`path_has_dot_segment`) is the primary security control.
- **`accept_invalid_certs` is a dual-use flag**: Both the JWKS manager and the Vault HTTP client honor it. If enabled in production, it defeats TLS verification for auth-verifier connections.
- **`find_any()` key iteration**: Auth Verifier tokens lack `kid`, so every JWKS key is tried sequentially. This is O(n) in the number of keys but acceptable for typical JWKS sizes (1–5 keys).
- **Session cookie security**: Depends on actix-session's encrypted cookie backend with the `ui_session_salt`. The salt must be identical across load-balanced instances.

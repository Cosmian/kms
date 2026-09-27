# Web UI SPIFFE Authentication & Ingress Gateway Architecture

Eviden KMS provides native zero-trust support for **SPIFFE** (Secure Production Identity Framework For Everyone) within browser and gateway environments. This architecture combines two distinct SPIFFE credentials to achieve end-to-end security without requiring individual user credential provisioning or local password databases:

1. **Hop Transport Security (X.509-SVID mTLS)**: Guarantees mutual cryptographic authentication and attestation between the Ingress Gateway (e.g., Apache APISIX or Envoy) and the KMS upstream.
2. **Workload / Application Identity (JWT-SVID)**: Establishes a verified, cookie-backed KMS session (`auth_session`) tied to a SPIFFE identity via the native `POST /ui/login_svid` endpoint.

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph Client["Client Browser"]
        Browser["Web Browser"]
    end

    subgraph GatewayPod["APISIX Gateway Pod"]
        APISIX["APISIX Engine<br/>(L7 Reverse Proxy)"]
        Reloader["spiffe-mtls-reloader<br/>(Admin API Sync)"]
        Helper["spiffe-helper<br/>(Daemon)"]
        CertVol[("EmptyDir<br/>/run/spiffe-certs")]
    end

    subgraph SPIRE["SPIRE Infrastructure"]
        Agent["SPIRE Agent<br/>(Workload API)"]
        Server["SPIRE Server"]
        OIDC["SPIRE OIDC<br/>Discovery Provider"]
    end

    subgraph KMSPod["Cosmian KMS Pod"]
        KMS["Cosmian KMS<br/>(/ui/login_svid)"]
    end

    Agent -->|UNIX Socket| Helper
    Helper -->|Write SVID & Key| CertVol
    CertVol -->|Read PEM| Reloader
    Reloader -->|PUT /admin/ssls| APISIX

    Browser --> APISIX
    APISIX --> KMS
    APISIX <-.-> KMS
    KMS --> OIDC
    KMS --> APISIX
    APISIX --> Browser
```

---

## Detailed Sequence Flow: X.509-SVID & JWT-SVID Transport

The lifecycle consists of three distinct phases: background X.509 rotation, initial transparent JWT-SVID session bootstrap, and subsequent authenticated browser requests.

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Client Browser
    participant APISIX as APISIX Gateway Engine
    participant Reloader as spiffe-mtls-reloader
    participant Helper as spiffe-helper
    participant Agent as SPIRE Agent (Host Socket)
    participant OIDC as SPIRE OIDC Discovery Provider
    participant KMS as Eviden KMS Server

    %% Phase 1: X.509-SVID Transport & Rotation Loop
    Note over Helper,KMS: Phase 1: Continuous X.509-SVID mTLS Transport Setup & Rotation
    Helper->>Agent: Workload API call via /spiffe-workload-api/spire-agent.sock
    Agent-->>Helper: Mint and return X.509-SVID (svid.pem, svid_key.pem, svid_bundle.pem)
    Helper->>Helper: Write certs to shared volume (/run/spiffe-certs/)
    Reloader->>Helper: Read certs from /run/spiffe-certs/
    Reloader->>APISIX: PUT /apisix/admin/ssls/upstream-client-cert (Local Admin API :9180)
    APISIX-->>Reloader: 200 OK (Upstream client certificate updated in memory)

    %% Phase 2: Web UI Browser Access & JWT-SVID Session Injection
    Note over Browser,KMS: Phase 2: Transparent JWT-SVID Application Authentication
    Browser->>APISIX: GET https://gateway:4443/

    critical APISIX serverless-pre-function (Lua Access Phase)
        APISIX->>APISIX: Check cookie auth_session (absent)
        APISIX->>KMS: POST https://kms:9998/ui/login_svid
    end

    KMS->>OIDC: Fetch JWKS from https://spire-oidc:8443/keys (Cached)
    OIDC-->>KMS: Public keys (EC / RSA)
    KMS->>KMS: Validate JWT-SVID (signature, issuer, expiry, audience)
    KMS->>KMS: Set user_id in encrypted session
    KMS-->>APISIX: 200 OK (Set-Cookie auth_session)

    critical APISIX Cookie Relay
        APISIX->>APISIX: Relay Set-Cookie header and set Cookie on upstream request
    end

    APISIX->>KMS: GET /ui/ (Proxied over SPIFFE X.509 mTLS with auth_session cookie)
    KMS-->>APISIX: 200 OK (Web UI HTML, JS, CSS Assets)
    APISIX-->>Browser: 200 OK (Set-Cookie auth_session)

    %% Phase 3: Authenticated Subsequent Requests
    Note over Browser,KMS: Phase 3: Subsequent Authenticated Requests
    Browser->>APISIX: GET /ui/whoami (Cookie: auth_session)
    APISIX->>KMS: Forward over SPIFFE X.509 mTLS with auth_session cookie
    KMS-->>APISIX: 200 OK (user_id response)
    APISIX-->>Browser: 200 OK (user_id response)
```

---

## Security & Architectural Invariants

### 1. Transport-Layer Isolation (mTLS)

- **Credential**: X.509-SVID with SAN `spiffe://<trust-domain>/<gateway-service>`.
- **Rotation**: `spiffe-helper` acts as a sidecar alongside the ingress gateway, interacting with the SPIRE Agent through the Workload API UNIX domain socket.
- **Zero Reload**: Certificates are pushed to the APISIX Admin API dynamically, eliminating proxy downtime or connection drops during rotation.
- **Upstream Validation**: Cosmian KMS validates the client certificate against its trust bundle (`clients_ca_cert_file = "/etc/kms/certs/spire-bundle.crt"`).

### 2. Application-Layer Identity (JWT-SVID)

- **Credential**: JWT-SVID with `sub: spiffe://<trust-domain>/<gateway-identity>` and `aud: <kms-audience>`.
- **Validation**: KMS validates the token using its `--jwt-auth-provider` configuration pointed at the SPIRE OIDC Discovery Provider (`https://<spire-oidc>:<port>/keys`).
- **Session Boundary (BFF)**: The browser never receives or stores the raw JWT-SVID. The KMS issues an encrypted, `HttpOnly`, `SameSite=Lax` session cookie (`auth_session`).

### 3. Server Configuration Reference

In `kms.toml`:

```toml
[ui_config]
enable = true

[idp_auth]
jwt_auth_provider = [
  "https://<spire-oidc>:<port>,https://<spire-oidc>:<port>/keys,<kms-audience>"
]
jwt_svid_auth = true

[tls]
tls_cert_file = "/etc/kms/certs/tls.crt"
tls_key_file = "/etc/kms/certs/tls.key"
clients_ca_cert_file = "/etc/kms/certs/spire-bundle.crt"
```

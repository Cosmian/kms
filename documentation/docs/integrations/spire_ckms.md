# CLI (`ckms`) SPIFFE Authentication Architecture

Eviden KMS supports native zero-trust workload identity for the CLI (`ckms`) through **SPIFFE** (Secure Production Identity Framework For Everyone) and the **SPIRE Agent Workload API**.

With `ckms login spire`, workloads, automated pipelines, and operators running alongside a SPIRE Agent can authenticate directly against the local agent's Workload API over a Unix Domain Socket (gRPC) to acquire a SPIFFE JWT-SVID, saving it into the CLI configuration without requiring external binaries (`spire-agent`), long-lived API keys, or hardcoded passwords.

---

## Prerequisites

- A KMS server started with `--jwt-svid-auth` and at least one `--jwt-auth-provider "<issuer>,<jwks_uri>,<audience>"` pointing at the SPIRE OIDC Discovery Provider. **The audience is mandatory**: the server refuses to start without it, and rejects SPIFFE JWT-SVIDs whose `aud` is missing or empty.
- A SPIRE Agent reachable from the host running `ckms`, with a workload entry matching the `ckms` process.
- `ckms login spire --audience` MUST use the audience configured on the KMS server.

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph Host["Workload Host / Container Environment"]
        CKMS["ckms CLI<br/>(ckms login spire)"]
        Conf[("ckms.toml<br/>(access_token)")]
        Agent["SPIRE Agent<br/>(Workload API)"]
        Socket[("Unix Domain Socket<br/>/tmp/spire-agent/public/api.sock")]
    end

    subgraph SPIRE["SPIRE Infrastructure"]
        Server["SPIRE Server<br/>(Trust Domain CA)"]
        OIDC["SPIRE OIDC<br/>Discovery Provider"]
    end

    subgraph KMS["Eviden KMS Server"]
        KMSEndpoint["KMS Server API<br/>(REST / KMIP)"]
    end

    CKMS -->|Workload API gRPC| Socket
    Socket --> Agent
    Agent <-->|Node & Workload Sync| Server
    CKMS -->|Persist JWT-SVID| Conf
    Conf -.->|Read Bearer Token| CKMS
    CKMS -->|Authorization: Bearer JWT-SVID| KMSEndpoint
    KMSEndpoint -->|JWKS Key Verification| OIDC
```

---

## Detailed Sequence Flow: Workload Attestation & JWT-SVID Transport

The authentication lifecycle consists of three distinct phases: Workload API connection and local attestation, token persistence, and subsequent authenticated KMS operations.

```mermaid
sequenceDiagram
    autonumber
    participant CLI as ckms CLI
    participant Conf as ckms.toml
    participant Agent as SPIRE Agent (Workload API)
    participant OIDC as SPIRE OIDC Discovery Provider
    participant KMS as Eviden KMS Server

    %% Phase 1: Local Workload Attestation & JWT-SVID Fetch
    Note over CLI,Agent: Phase 1: Native Workload API Call & Peer Attestation
    CLI->>Agent: Connect via SPIFFE_ENDPOINT_SOCKET (UNIX Domain Socket)
    Note over CLI,Agent: Kernel verifies peer credentials (SO_PEERCRED: UID/GID/PID)
    Agent->>Agent: Workload Attestor matches selectors (e.g., unix:uid)
    CLI->>Agent: gRPC FetchJWTSVIDRequest(audience: [kms-audience], spiffe_id: [optional])
    Agent-->>CLI: FetchJWTSVIDResponse(JWT-SVID token)

    %% Phase 2: Configuration Persistence
    Note over CLI,Conf: Phase 2: Configuration Storage
    CLI->>Conf: Store token in http_config.access_token (clear vault_token)
    CLI-->>CLI: Print success message

    %% Phase 3: Authenticated KMS Operations
    Note over CLI,KMS: Phase 3: Bearer-Authenticated KMS API Calls
    CLI->>KMS: POST /kmip/2_1 (Authorization: Bearer <JWT-SVID>)
    critical JWT-SVID Verification (jwt_auth_middleware, handle_jwt, resolve_authenticated_user)
        KMS->>OIDC: Fetch JWKS public keys (cached in memory)
        OIDC-->>KMS: RSA / EC verification keys
        KMS->>KMS: Validate signature, issuer, expiry, non-empty audience, and subject SPIFFE ID
    end
    KMS-->>CLI: 200 OK (Key Created / Operation Response)
```

---

## Security & Architectural Invariants

### 1. Pure Native Workload API Transport

- **Protocol**: Standard SPIFFE Workload API over gRPC on a local Unix Domain Socket (UDS).
- **Socket Resolution**: Taken from `--socket-path` when given (a bare absolute path such as `/run/spire/agent.sock`, or a `unix:///path` / `tcp://host:port` URI; bare paths get `unix://` prepended). When the flag is omitted, the standard `SPIFFE_ENDPOINT_SOCKET` environment variable is read (e.g. `unix:///tmp/spire-agent/public/api.sock`).
- **No External Binary Dependency**: Implemented using the pure-Rust `spiffe` crate (`WorkloadApiClient`). Does not shell out to the `spire-agent` CLI binary.
- **Kernel-Enforced Peer Attestation**: The SPIRE Agent attests the calling `ckms` process using kernel peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/BSD). Workload entries can restrict authorization by UID, GID, path, or container metadata.

### 2. Application Identity & Bearer Transport

- **Token Type**: SPIFFE JWT-SVID conforming to the SPIFFE specification.
    - `sub`: Workload SPIFFE ID (`spiffe://<trust-domain>/<path>`).
    - `aud`: Configured audience matching KMS server expectations.
- **Client Configuration Storage**:
    - Saved as `http_config.access_token` in `ckms.toml`.
    - Clears any conflicting Vault tokens (`http_config.vault_token = None`).
    - Seamlessly consumed by subsequent `ckms` subcommands (`ckms sym ...`, `ckms rsa ...`, `ckms kmip ...`).
- **Server-Side Validation**:
    - Verified by the Actix-web `jwt_auth_middleware` (`handle_jwt` → `resolve_authenticated_user`).
    - The token MUST carry a non-empty `aud`; the server rejects SPIFFE subjects without one (SPIFFE JWT-SVID spec: validators reject SVIDs not addressed to them, preventing cross-service replay).
    - When `clients_ca_cert_file` (mTLS) is also enabled, a client certificate with a CN is authenticated first and takes precedence over the bearer token.
    - Cryptographically checked against the SPIRE OIDC Discovery Provider JWKS endpoint.
    - Flags: Requires `--jwt-auth-provider="<issuer>,<jwks_url>,<audience>"` and `--jwt-svid-auth`. `--jwt-svid-auth` is global (all providers) and the server refuses to start if any provider has no audience.

---

## CLI Usage Reference

### Command Syntax

```bash
ckms login spire --audience <AUDIENCE> [OPTIONS]
```

### Options

| Flag | Environment Variable | Required | Description |
|---|---|---|---|
| `--audience` | — | **Yes** | The expected JWT audience. Must match the audience configured in KMS `--jwt-auth-provider` (the third field is mandatory when `--jwt-svid-auth` is set). |
| `--spiffe-id` | — | No | Specific SPIFFE ID to request if the agent serves multiple identities to this workload. |
| `--socket-path` | — (no clap env binding) | No | Bare absolute path (`/run/spire/agent.sock`) or `unix:///path` / `tcp://host:port` URI of the Workload API socket. When omitted, `SPIFFE_ENDPOINT_SOCKET` is read from the environment. |

### Example Workflow

```bash
# 1. Export the standard SPIFFE Workload API socket
export SPIFFE_ENDPOINT_SOCKET="unix:///tmp/spire-agent/public/api.sock"

# 2. Authenticate against the local SPIRE Agent
ckms login spire --audience dawn-kms

# 3. Perform cryptographic operations with the issued JWT-SVID
ckms sym keys create my-app-key
echo "Secret message" > message.txt
ckms sym encrypt --key-id my-app-key --output-file message.enc message.txt
```

---

## Server Configuration Reference

In `kms.toml`:

```toml
[idp_auth]
jwt_auth_provider = [
  "https://spire-oidc.spire.svc.cluster.local:8443,https://spire-oidc.spire.svc.cluster.local:8443/keys,dawn-kms"
]
jwt_svid_auth = true
```

Or via server command-line flags:

```bash
cosmian_kms_server \
  --jwt-auth-provider "https://spire-oidc.spire.svc.cluster.local:8443,https://spire-oidc.spire.svc.cluster.local:8443/keys,dawn-kms" \
  --jwt-svid-auth
```

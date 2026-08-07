---
name: cosmian-kms-last-tester-v4
description: Acts as the final quality gate for Eviden KMS PRs. Assumes all automated tests pass upstream. Builds an ACC risk map from git diff, runs adversarial tours against a live KMS instance, and produces a finding report. Use when reviewing a PR, testing a new feature end-to-end, or validating behavioral contracts after a merge.
---

# Eviden KMS — PR Review & Final-Layer Testing Agent

## 0 — Prerequisites

**KMS server**: must be running on port `9998` before any test. Check first; start if needed.

```bash
# non-FIPS (most common — all algorithms enabled)
pnpm -C ui build && cargo run -p cosmian_kms_server --features non-fips -- -c test_data/configs/server/no_auth.toml

# FIPS only
pnpm -C ui build && cargo run -p cosmian_kms_server -- -c test_data/configs/server/no_auth.toml
```

Adapt config to the PR: TLS → `tls_auth_non_fips.toml`, JWT → `jwt_auth.toml`, PostgreSQL → start DB with `docker compose up -d` first. Full config reference: `reference/kmip-ops-and-configs.md`.

**Health check:**

```bash
curl -s http://127.0.0.1:9998/health | jq .
# {"status":"UP","latency_ms":...,"dependencies":{"database":{"name":"sqlite","status":"UP"}}}

curl -s http://127.0.0.1:9998/server-info | jq .
# {"version":"...","fips_mode":false,...}
```

**Chrome DevTools MCP** (for UI testing): install `npx -y chrome-devtools-mcp@latest`. Skill is designed for VS Code but works in any MCP-capable IDE. See `reference/ui-routes.md` for fully-qualified tool names.

---

## 1 — Test Channels

Identify which channel(s) the PR affects and test accordingly.

### 1.1 — CLI (`ckms` binary)

**When**: PR touches `crate/clients/clap/`, `crate/clients/client/`, `crate/crypto/`, `crate/server/src/core/operations/`, or any KMIP-visible behavior.

```bash
cargo run -p ckms --features non-fips -- <subcommand> [args]
```

Full command tree, roundtrip examples → **`reference/cli-commands.md`**

### 1.2 — HTTP endpoints (`curl`)

**When**: PR touches `crate/server/src/routes/` (any of: KMIP, access, JOSE REST, JWKS, enterprise integrations, tokenize, middleware).

Full endpoint map, curl examples, JOSE algorithm table, JWKS eligibility rules → **`reference/endpoints.md`**

### 1.3 — Web UI (Chrome DevTools MCP)

**When**: PR touches `ui/src/`, `crate/clients/wasm/`, or UI-facing server behavior.

UI is served at `http://127.0.0.1:9998/ui/`. Use `io.github.ChromeDevTools:navigate_page` to open a route, `io.github.ChromeDevTools:fill_form` and `io.github.ChromeDevTools:click` to interact, `io.github.ChromeDevTools:take_screenshot` and `io.github.ChromeDevTools:wait_for` to observe results.

Full UI route map, action module list, MCP tool reference → **`reference/ui-routes.md`**

### 1.4 — Other channels

| Scenario              | When                                           | How to test                                                                                   |
| --------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **PKCS#11 module**    | Changes to `crate/clients/pkcs11/`             | `cargo test -p cosmian_pkcs11`                                                                |
| **WASM client**       | Changes to `crate/clients/wasm/`               | `cd crate/clients/wasm && wasm-pack test --headless --chrome`                                 |
| **TCP socket server** | Changes to socket handling                     | Enable `start_socket_server = true` (port 5696), send raw TTLV bytes                         |
| **Database backends** | Changes to `crate/server_database/`            | `docker compose up -d`, use appropriate config                                                |
| **OpenSSL/crypto**    | Changes to `crate/crypto/`                     | `cargo test -p cosmian_kms_crypto`                                                            |
| **HSM integrations**  | Changes to `crate/hsm/`                        | Requires HSM hardware or SoftHSM2 (`test_data/configs/server/hsm/softhsm2_config.toml`)      |
| **Middleware/auth**   | Changes to `crate/server/src/middlewares/`     | Test with JWT, mTLS, API token configs                                                        |
| **Build system**      | Changes to `Cargo.toml`, `build.rs`, Nix files | `cargo build && cargo build --features non-fips`                                              |
| **Documentation**     | Changes to `documentation/`, `README.md`       | `cd documentation && mkdocs build`                                                            |

---

## 2 — Context and Role

This agent operates at the **last quality gate** before a PR is merged. Unit tests, integration tests, and E2E tests have already passed upstream. The agent's job is not to re-derive coverage — it is to find **behavioral inconsistencies that no automated test has an oracle for**.

> Assume all unit, integration, and E2E tests pass for this PR. You are not a test generator — you are an experienced QA engineer doing a final sanity pass. Focus on: implicit contracts that changed, surprising interactions between new and old behavior, and the kind of thing that only breaks in production when a real user does something the happy-path tests never imagined.

---

## 3 — Build an ACC Risk Map from the Diff

Before writing a single test scenario, construct a cognitive map of what the PR touches using the **ACC (Attributes, Components, Capabilities)** framework, grounded in KMS domain concepts.

### Attributes (non-functional qualities relevant to KMS)

| Attribute       | What it means in KMS context                                                          |
| --------------- | ------------------------------------------------------------------------------------- |
| `secure`        | Key material never leaks, auth is enforced, TLS is required                           |
| `consistent`    | Database state matches KMIP-visible object lifecycle                                  |
| `idempotent`    | Repeated identical requests produce the same result without side effects              |
| `available`     | Server stays up under concurrent load, health endpoint reports UP                     |
| `auditable`     | Every operation is logged with caller identity, key ID, and timestamp                 |
| `compliant`     | FIPS algorithms reject non-approved parameters; KMIP responses match spec             |
| `interoperable` | Enterprise endpoints (AWS XKS, Azure EKM, Google CSE, MS DKE) conform to vendor specs |

### Components (KMS structural modules)

| Component               | Crate/path                                                              | What it covers                                                 |
| ----------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------------- |
| Key lifecycle           | `server/src/core/operations/`                                           | Create → Activate → Deactivate → Compromise → Destroy          |
| Access control          | `crate/access/`, `server/src/routes/access.rs`                          | Owner/user permissions, grant/revoke                           |
| KMIP protocol           | `crate/kmip/`, `server/src/routes/kmip.rs`                              | TTLV serialization, operation dispatch                         |
| Crypto primitives       | `crate/crypto/`                                                         | AES, RSA, EC, PQC, FPE, Covercrypt, hashing, MAC               |
| Database layer          | `crate/server_database/`                                                | SQLite, PostgreSQL, MySQL, Redis-Findex backends               |
| CLI                     | `crate/clients/clap/`, `crate/clients/ckms/`                            | User-facing command tree                                       |
| Web UI                  | `ui/src/`                                                               | React SPA with WASM bindings                                   |
| Enterprise integrations | `server/src/routes/{aws_xks,azure_ekm,google_cse,ms_dke}/`              | Cloud vendor endpoints                                         |
| Auth middleware         | `server/src/middlewares/`                                               | JWT, mTLS, API token, session cookies                          |
| Configuration           | `server/src/config/`                                                    | Server params, KMIP policy, algorithm allowlists               |
| Tokenization            | `server/src/routes/tokenize/`, `crate/crypto/src/crypto/anonymization/` | Hash, noise, mask, aggregate (non-fips)                        |
| JOSE REST Crypto API    | `server/src/routes/crypto/`                                             | JWK key management, JWE encrypt/decrypt, JWS sign/verify, HMAC |
| JWKS endpoint           | `server/src/routes/jwks.rs`                                             | RFC 7517 public key discovery (`/.well-known/jwks.json`)       |

### Building the Capabilities Matrix

For this PR, populate the intersection of Attributes × Components from the diff. Examples:

- `Secure × Key Lifecycle` → "Destroyed keys cannot be retrieved or activated"
- `Idempotent × Create Key` → "Creating a key with identical params returns the same key or a clear error, never a corrupt duplicate"
- `Compliant × Crypto Primitives` → "FIPS mode rejects ChaCha20; non-FIPS mode accepts it"
- `Interoperable × Azure EKM` → "wrap/unwrap responses match Azure's expected JSON schema"
- `Consistent × Database Layer` → "Concurrent revoke + encrypt on same key produces a clean error, not a partial state"

Rank cells by risk: code churn × blast radius if behavior is wrong. Only populate cells actually touched by the PR.

---

## 4 — Behavioral Diff Analysis

Read the diff and answer these questions before generating any scenarios:

1. **What implicit contract changed?** Look for behaviors the old code guaranteed by accident:
   - A field that was always non-null and is now nullable
   - A status transition that was impossible and is now reachable
   - An error type that changed (e.g., 422 → 500, or a different KMIP `ResultReason`)
   - A default value that shifted

2. **What adjacent behaviors could be silently broken?** For every function the PR touches, enumerate the callers not modified by the PR. In KMS terms:
   - A change to `encrypt()` in `crate/crypto/` — does it affect `wrap()` which calls it?
   - A change to `dispatch.rs` — does it alter the order of validation for all operations?
   - A change to access control — does it affect both CLI and UI paths?

3. **What assumptions does the new code introduce?** KMS-specific red flags:
   - `unwrap()` or `expect()` on KMIP responses
   - Unchecked index access on key material bytes
   - Implicit ordering between async operations (e.g., create then immediately activate)
   - Hardcoded algorithm identifiers that should be parameterized

4. **Is there a new failure mode with no error handling?** Check for:
   - New code paths that panic instead of returning `KmsError`
   - Incorrect HTTP status codes (see error mapping in §8)
   - Errors swallowed by `.ok()` or `let _ =`
   - Missing feature-flag gates (`#[cfg(feature = "non-fips")]`)

---

## 5 — Adversarial Tour Proposals

Propose **tours** — themed exploratory runs against the live KMS — not individual test cases. Tours target _assumptions_, not paths.

### Tour Catalogue (KMS-specific)

| Tour                   | Target assumption                                | Concrete KMS stimuli                                                                                                                                                                                                                    |
| ---------------------- | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Saboteur Tour**      | The system handles hostile inputs gracefully     | Send malformed TTLV to `/kmip/2_1`; send key ID with SQL injection payload to `/access/list/{id}`; send a 65 MB JSON body; send truncated base64 key material on import; send negative `CryptographicLength`                            |
| **Antisocial Tour**    | Operations are safe out of documented order      | Encrypt with a `PreActive` key; decrypt with a `Deactivated` key; destroy a key then try to export it; revoke access then try to use the key through the revoked user; call `Certify` on a symmetric key                                |
| **Time Tour**          | Time-dependent behavior is correct at boundaries | Create a key with expiry 1 second from now, wait, then try to encrypt; rotate a key at the exact moment a wrap request arrives; check `unwrapped_cache_max_age` eviction timing                                                         |
| **Obsessive Tour**     | Repeated operations don't degrade state          | Create 100 keys with the same tag; rotate the same key 50 times in a loop; grant+revoke access 100 times; send 100 concurrent encrypt requests on the same key                                                                          |
| **Configuration Tour** | Non-default configs don't break invariants       | Run with `clear_database = true`; run with a custom `kmip_policy` restricting key sizes; run with `force_default_username`; switch database backends mid-session                                                                        |
| **Amnesia Tour**       | Restart/crash recovery preserves guarantees      | Kill the KMS mid-encrypt; restart; verify key state is consistent; verify no partial objects in DB; verify the health endpoint comes back UP with correct DB status                                                                     |
| **Privilege Tour**     | Access control is not bypassable at edges        | Call admin-only endpoints (`/access/grant`) without auth; with `no_auth.toml`, verify `default_username` is used; test `non_revocable_key_id` enforcement; grant access to a key, destroy the key, check the access entry is cleaned up |
| **Feature-Flag Tour**  | FIPS/non-FIPS boundaries are enforced            | In FIPS mode, attempt to create a Covercrypt key (should fail); in non-FIPS mode, attempt to use the `/tokenize/` endpoints (should work); verify that `server-info` reports the correct `fips_mode`                                    |

For each tour relevant to the PR's diff, produce a **concrete sequence** of test steps using whichever channel from §1 is most direct for the surface being tested:

- `ckms` CLI commands for KMIP-visible behavior and key lifecycle
- `curl` calls for HTTP endpoints (JOSE REST, JWKS, enterprise integrations, tokenize)
- Chrome DevTools MCP for UI behavior or WASM-backed operations
- `cargo test -p <crate>` or in-process test server for database backends, PKCS#11, or crypto primitives

Choose the channel that most closely matches how a real user would reach the broken assumption.

**Example: Antisocial Tour for a key lifecycle PR**

```bash
# Create a key (starts in PreActive state — no auto-activation unless configured)
KEY_ID=$(cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 256 2>&1 | grep -oP '[0-9a-f-]{36}')

# Try to encrypt before activation — should fail if key is PreActive
cargo run -p ckms --features non-fips -- sym encrypt -k "$KEY_ID" test_data/plain.txt
# Expected: error mentioning key state or usage mask

# Destroy the key
cargo run -p ckms --features non-fips -- objects destroy -k "$KEY_ID"

# Try to export the destroyed key — must fail
cargo run -p ckms --features non-fips -- sym keys export -k "$KEY_ID" /tmp/dead-key.json
# Expected: error "Item not found" or "object is destroyed"
```

---

## 6 — SFDIPOT Canary Checklist

After tours, run a canary pass. For each dimension touched by the PR, write one cheap verification.

| Dimension      | KMS-specific probes                                                                                                                                                     | Canary command                                                                                                                      |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Structure**  | Key object schema, KMIP message framing, TTLV field ordering                                                                                                            | `curl -s -X POST -H "Content-Type: application/json" -d '{}' http://127.0.0.1:9998/kmip/2_1` → expect 422 with KMIP error, not 500  |
| **Function**   | Core KMIP: Create, Get, Activate, Revoke, Destroy, Encrypt, Decrypt, Wrap, Unwrap, Sign, Verify, MAC, Hash, Locate, Certify, Validate, DeriveKey, Import, Export, ReKey | `cargo run -p ckms --features non-fips -- server version` → expect version string                                                   |
| **Data**       | Key material encoding, algorithm identifiers, length constraints, empty/null inputs, Unicode in tags                                                                    | `cargo run -p ckms --features non-fips -- sym keys create --algorithm aes --number-of-bits 128 --tag "canary-αβγ"` → expect success |
| **Interface**  | HTTP REST endpoints, KMIP TTLV, CLI flags, TLS cert validation, CORS headers, cookie handling                                                                           | `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9998/health` → expect `200`                                                |
| **Platform**   | Linux (primary), macOS, Windows (CI), Docker, Nix packaging                                                                                                             | Check binary starts: `cargo run -p cosmian_kms_server --features non-fips -- --help` → expect help text                             |
| **Operations** | Startup, shutdown, config reload, log output, OTEL metrics, concurrent requests, DB migrations                                                                          | Check health with DB: `curl -s http://127.0.0.1:9998/health \| jq .dependencies.database.status` → expect `"UP"`                    |
| **Time**       | Key validity windows, expiry, rotation scheduling, cache TTLs (`unwrapped_cache_max_age`), session cookie TTL                                                           | Create key with activation/expiry dates, verify enforcement                                                                         |

---

## 7 — Regression Oracle Pass

For every behavioral change the PR introduces, identify the adjacent behaviors that _were not changed_ but could have been silently affected. For each:

- State the invariant (from the KMS domain invariants list below)
- Write the minimal verification
- Note whether the expected response is deterministic

**Example regression checks:**

```gherkin
Scenario: Destroyed keys cannot be retrieved
  Given a KMS with a symmetric AES-256 key that has been destroyed
  When the user runs `cargo run -p ckms --features non-fips -- sym keys export -k <destroyed-key-id> /tmp/out.json`
  Then the command fails with "Item not found" error
  And the exit code is non-zero

Scenario: Key material never appears in error messages
  Given a KMS with a symmetric key
  When the user sends a malformed encrypt request referencing that key
  Then the error response body does not contain any base64-encoded key material
  And the server log does not contain key bytes

Scenario: Health endpoint reflects actual DB state
  Given a KMS running with SQLite backend
  When the SQLite file is deleted while the server is running
  Then GET /health returns {"status":"DOWN",...} or reports database error
```

---

## 8 — KMS Error Reference

HTTP status mapping, KMIP `ResultReason` codes, and enterprise error formats → **`reference/error-codes.md`**

---

## 9 — KMS Domain Invariants

Any scenario that violates one of these is a **critical finding**.

Full invariant list (key lifecycle, security, access control, protocol, concurrency, JOSE/JWKS) → **`reference/invariants.md`**

---

## 10 — Feature Flag Awareness

The tester agent **must be aware** of which feature flags are active and test accordingly.

| Flag               | Algorithms/features enabled                                                       | How to detect                                                          |
| ------------------ | --------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **FIPS (default)** | AES, RSA ≥2048, ECDSA, EdDSA, ML-KEM, ML-DSA, SLH-DSA, SHA-2/3, HMAC              | `curl -s http://127.0.0.1:9998/server-info \| jq .fips_mode` → `true`  |
| **non-fips**       | All FIPS + ChaCha20, AES-XTS, Covercrypt, FPE, tokenize, Redis-Findex, MD5, SHA-1 | `curl -s http://127.0.0.1:9998/server-info \| jq .fips_mode` → `false` |

**JOSE REST API feature-flag specifics:**

- All `/v1/crypto/*` endpoints are available in both FIPS and non-FIPS builds.
- `kty=OKP` (Ed25519/`EdDSA`) key creation and signing is gated behind `non-fips`. In a FIPS build, `POST /v1/crypto/keys` with `kty=OKP` must return `400 Bad Request`.
- `/.well-known/jwks.json` is always compiled in but only **registered** when `jwks_endpoint_enabled = true`. Feature flag does not affect this — it is a runtime config toggle.

**Testing rule**: If the PR introduces code guarded by `#[cfg(feature = "non-fips")]`, the tester must verify:

1. The feature works when `non-fips` is enabled
2. The feature is unreachable (compile-gated) when building without it — this is verified by `cargo build` (no `--features non-fips`)

---

## 11 — KMIP Operations & Test Configurations

Full dispatch table (all 31 operations, handlers, notes) and server config reference → **`reference/kmip-ops-and-configs.md`**

---

## 12 — Workflow Checklist

Copy and track progress for each PR review:

```
PR Review Progress:
- [ ] A: KMS server running on port 9998 (health check green)
- [ ] A: Chrome DevTools MCP available (if PR touches UI)
- [ ] A: Test channels identified (CLI / HTTP / UI / Other)
- [ ] B: git diff read; ACC risk map built (Attributes × Components)
- [ ] B: Behavioral diff questions answered (§4)
- [ ] C: Relevant tours selected and run (§5)
- [ ] C: SFDIPOT canaries executed for touched dimensions (§6)
- [ ] C: Regression invariants checked (§7, reference/invariants.md)
- [ ] E: Finding report written (see template below)
```

---

## 13 — Finding Report Template

```markdown
# PR Finding Report — <PR title / branch>

## Server
- Mode: FIPS / non-FIPS
- Config: <config file used>
- Version: <curl http://127.0.0.1:9998/version>

## Channels tested
- [ ] CLI
- [ ] HTTP
- [ ] Web UI
- [ ] Other: ___

## ACC risk map (high-risk cells only)
| Attribute | Component | Risk | Tested? |
|-----------|-----------|------|---------|
| ...       | ...       | H/M/L| Y/N     |

## Tours run
| Tour | Findings |
|------|----------|
| ...  | ...      |

## SFDIPOT canaries
| Dimension | Result |
|-----------|--------|
| ...       | PASS / FAIL |

## Invariant regressions
- [ ] No invariants violated
- [ ] Violations: <describe>

## Verdict
**GO / NO-GO** — <one sentence summary>
```

---

## 14 — Literature and References

| Resource                                                 | What to extract                                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| James Whittaker, _Exploratory Software Testing_ (2009)   | Tour metaphors: Saboteur, Antisocial, Obsessive, Configuration, Time tours                  |
| James Whittaker, ACC framework (Google)                  | Attributes/Components/Capabilities matrix for rapid risk mapping                            |
| SFDIPOT heuristic (Satisfice / RST)                      | Seven-dimension checklist: Structure, Function, Data, Interface, Platform, Operations, Time |
| Michael Bolton & James Bach — Rapid Software Testing     | Oracles vs. exploration distinction; error guessing with domain priors                      |
| KMIP 2.1 specification (HTML files in `crate/kmip/src/`) | Normative reference for all KMIP operations, object types, attributes                       |
| FIPS 140-3 / NIST SP 800-175B                            | Approved algorithms, key management requirements                                            |
| Eviden KMS AGENTS.md                                    | Canonical project instructions, build commands, CI workflows                                |
| `test_data/configs/server/`                              | All available server configurations for different test scenarios                            |

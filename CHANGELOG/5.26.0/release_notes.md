# 5.26.0 release notes (full text)

Full text of the `## [5.26.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.26.0] - 2026-08-07

### 🔒 Security

- Resolve 8 Dependabot security alerts ([#1083](https://github.com/Cosmian/kms/pull/1083))
- Upgrade `opentelemetry_sdk` 0.29.0 → 0.32.1 (SSRF via malicious OTLP endpoint, [GHSA-r74r-p7x6-m97p](https://github.com/advisories/GHSA-r74r-p7x6-m97p)) + React dependency updates ([#1073](https://github.com/Cosmian/kms/pull/1073))
- `AlwaysSensitive` is now server-managed: clients can no longer add/set/modify/delete it via `AddAttribute`, `SetAttribute`, `ModifyAttribute`, or `DeleteAttribute` — such requests are rejected with `Attribute_Read_Only` ([#1103](https://github.com/Cosmian/kms/pull/1103))
- Read-only KMIP attributes could be rewritten by any client via `ModifyAttribute` (e.g. `Initial Date`, `Cryptographic Length`, `Unique Identifier`). All attributes marked "Modifiable by client: No" are now rejected with `Attribute_Read_Only`; "Deletable by client: No" attributes are rejected by `DeleteAttribute` ([#1103](https://github.com/Cosmian/kms/pull/1103))

### 🚀 Features

#### SPIRE / Workload Identity ([#1075](https://github.com/Cosmian/kms/pull/1075))

- Add SPIRE server support: KMS acts as a Vault-compatible backend for SPIRE's `upstream_ca` plugin (PKI sign-intermediate, Transit encrypt/decrypt, Auth AppRole/Kubernetes)
- Multi-tenant SPIRE integration with isolated trust domains per SPIFFE ID
- `X-Vault-Token` accepted on all KMS endpoints when `vault_api_enabled = true` — transit/PKI clients no longer need a separate native KMS credential
- Vault Transit engine routes: create/list/delete keys, sign with configurable `signature_algorithm` (PSS/PKCS1v15)
- Vault PKI engine route: `POST /root/sign-intermediate` with `ttl` forwarding
- `ckms vault approle` CLI subcommands for AppRole admin operations (create/list/delete roles, generate/destroy secret IDs)
- Transparent auth reverse proxy: `/v1/auth/*` forwarded to auth-verifier, stripping `/v1` prefix

#### Kubernetes / Helm ([#999](https://github.com/Cosmian/kms/pull/999), [#1048](https://github.com/Cosmian/kms/pull/1048))

- Add Kubernetes KMS Provider Plugin implementing the KMS v2 gRPC API for encrypting Kubernetes secrets at rest in etcd
- Add Kubernetes Secrets Store CSI Driver Provider for mounting KMS-managed secrets as files
- Add Kubernetes operator with controller, admission webhook, and init-container inject mode
- Add Helm chart for Kubernetes deployment with configurable values, RBAC, HPA, PDB, and NetworkPolicy

#### KMIP ([#1103](https://github.com/Cosmian/kms/pull/1103))

- Support `AlwaysSensitive` KMIP attribute (KMIP 2.1 §4.3): set to `True` at creation iff `Sensitive`, permanently `False` once `Sensitive` is ever set to `False`
- KMIP 1.x attribute version gating: server no longer returns attributes that the client's protocol version does not define (prevents parse failures in KMIP 1.0–1.3 clients like Synology DSM, PyKMIP, Percona)
- `Never Extractable` is now correctly serialized in KMIP 1.x responses

#### Authentication Verifier integration ([#1013](https://github.com/Cosmian/kms/pull/1013))

- Authentication methods delegated to the external Cosmian Authentication Verifier service:
    - Login/password (basic auth) + TOTP 2FA: supported on Web UI and `ckms login` CLI
    - `X-Vault-Token` (Vault AppRole, Vault Kubernetes, Vault Token)

#### Other

- Enrich SBOM with additional metadata ([#1102](https://github.com/Cosmian/kms/pull/1102))

### 🐛 Bug Fixes

#### KMIP Conformance ([#1103](https://github.com/Cosmian/kms/pull/1103))

- `Lease Time` was encoded as TTLV `Integer` instead of `Interval` — strictly typed clients rejected every `GetAttributes` response carrying it
- `RNG Parameters.Cryptographic Length` was encoded as `LongInteger` instead of `Integer`, making the `Random Number Generator` attribute undecodable
- `DeleteAttribute` responses omitted the deleted `Attribute` (required by KMIP 1.4 §4.16)
- `DeleteAttribute` by name was a silent no-op for most attributes (only handled 9 tags)
- `Comment` was write-only — never returned by `GetAttributes`

#### Server & Infrastructure

- Fix OpenSSH authentication failures — PKCS#11 `C_SignInit` now uses class-aware `CKA_ID` lookup ([#1091](https://github.com/Cosmian/kms/pull/1091))
- Fix stale connections in ckms CLI — retry HTTP requests once on stale pooled connections ([#1061](https://github.com/Cosmian/kms/pull/1061))
- Remove busybox from Docker image ([#1099](https://github.com/Cosmian/kms/pull/1099))
- Fix mdBook documentation build ([#1095](https://github.com/Cosmian/kms/pull/1095))
- Update AWS XKS service ([#1065](https://github.com/Cosmian/kms/pull/1065))
- Enable strict configuration parsing — reject unknown fields ([#1053](https://github.com/Cosmian/kms/pull/1053))
- Fix Nix upgrade for Rust toolchain ([#1057](https://github.com/Cosmian/kms/pull/1057))

### 🧪 Testing

- SPIRE PKI capability validation — 10 scenarios (M-01 through M-10) covering Aembit RFI test plan: self-signed cert rejection, TLS version enforcement, algorithm policy propagation, client/server cert parity, latency hard gate, timed revocation propagation ([#1110](https://github.com/Cosmian/kms/pull/1110))
- Go-based KMIP compliance tests (`ovh/kmip-go`, KMIP 1.0–1.4): 16 tests validating DiscoverVersions, Query, AES/RSA/EC key lifecycle, Locate, batch ops, encrypt/decrypt, sign/verify, and version-gating of KMIP 1.4+ attributes ([#1103](https://github.com/Cosmian/kms/pull/1103))

### ⚙️ Build

- Replace linkcheck with lychee for documentation link validation ([#1106](https://github.com/Cosmian/kms/pull/1106))
- Bump CI actions: `setup-minikube`, `setup-helm`, `pnpm/action-setup`, `docker/login-action`, `actions/setup-node`

### 📚 Documentation

- Major mdBook documentation overhaul ([#1095](https://github.com/Cosmian/kms/pull/1095))
- Add TLS configuration wizard documentation
- Add PostgreSQL failover retry and standby cluster documentation
- Clean server README ([#1062](https://github.com/Cosmian/kms/pull/1062))

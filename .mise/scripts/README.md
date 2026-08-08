# KMS MISE Tasks

All automation is driven by [MISE](https://mise.jdx.dev/) tasks in `.mise/tasks/`.
Run any task with `mise run <group>:<name> [flags]`.

The most common flags (accepted by most tasks):

| Flag | Values | Default | Description |
|------|--------|---------|-------------|
| `-v / --variant` | `fips`, `non-fips` | `fips` | Cryptographic variant |
| `-l / --link` | `static`, `dynamic` | `static` | Linkage type (build tasks) |
| `-r / --release` | — | off | Build in release mode |

---

## build

| Task | Description |
|------|-------------|
| `build:kms` | Build KMS server binary |
| `build:cli` | Build `ckms` CLI binary |
| `build:wasm` | Build WASM client package |
| `build:ui` | Build the web UI (depends on `build:wasm`) |
| `build:docker` | Build KMS Docker image via Nix (`--load` to push to daemon) |
| `build:nix` | Build server binary via Nix with vendor-hash verification |
| `build:openssl-binaries` | Download pre-built OpenSSL binaries (CI use) |
| `build:k8s-bins` | Build all Kubernetes binaries (plugin, operator, CSI provider, ckms) via Nix |
| `build:k8s-csi-provider-image` | Build Cosmian KMS CSI Provider Docker image via Nix |
| `build:k8s-operator-image` | Build Cosmian KMS Operator Docker image via Nix |

---

## test

### Database backends

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:sqlite` | fips | SQLite workspace tests |
| `test:psql` | fips | PostgreSQL tests |
| `test:mysql` | fips | MySQL tests |
| `test:percona` | fips | Percona XtraDB tests |
| `test:mariadb` | fips | MariaDB tests |
| `test:redis` | non-fips | Redis-findex tests |
| `test:matrix` | all | All HSM × DB backend × variant combinations |

### Cloud & SaaS integrations

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:google-cse` | fips | Google CSE tests |
| `test:gcp-cmek` | fips | GCP CMEK wrapping key tests |
| `test:azure-ekm` | non-fips | Azure EKM tests |
| `test:xks` | non-fips | AWS XKS tests |

### Secret backends

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:secret_cosmian_kms` | fips | Secrets against a local Cosmian KMS |
| `test:secret_aws` | non-fips | Secrets against AWS SSM Parameter Store |
| `test:secret_azure` | non-fips | Secrets against Azure Key Vault |
| `test:secret_vault` | non-fips | Secrets against HashiCorp Vault |

### HSM

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:hsm` | fips | All HSM tests |
| `test:hsm:softhsm2` | fips | SoftHSM2 |
| `test:hsm:utimaco` | fips | Utimaco simulator (Linux only) |
| `test:hsm:proteccio` | fips | Proteccio (Linux only) |
| `test:hsm:crypt2pay` | fips | Crypt2Pay (Linux only) |
| `test:hsm-softhsm2` | fips | Same as `test:hsm:softhsm2` (flat alias) |
| `test:hsm-utimaco` | fips | Same as `test:hsm:utimaco` |
| `test:hsm-proteccio` | fips | Same as `test:hsm:proteccio` |
| `test:hsm-crypt2pay` | fips | Same as `test:hsm:crypt2pay` |

### Kubernetes

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:k8s` | fips | All Kubernetes E2E tests |
| `test:k8s:plugin` | fips | KMS Provider Plugin (etcd Secret encryption) |
| `test:k8s:operator` | fips | KMS Operator via Kubernetes Job (Minikube) |
| `test:k8s:operator-image` | fips | KMS Operator Docker image via Minikube |
| `test:k8s:csi-provider` | fips | CSI Provider secrets store mount (Minikube) |
| `test:k8s:csi-provider-image` | fips | CSI Provider Docker image via Minikube |

### Audit & SIEM

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:audit` | non-fips | Audit log integration test (JSONL, hash chain, fields) |
| `test:cef` | non-fips | All CEF integration tests (format, UDP syslog, TCP rsyslog) |
| `test:cef-format` | non-fips | CEF v27 format validation |
| `test:cef-syslog` | non-fips | CEF over UDP syslog |
| `test:cef-tcp-syslog` | non-fips | CEF over TCP syslog (rsyslog, RFC 6587) |
| `test:siem` | non-fips | All SIEM integration tests |
| `test:siem-cef-syslog` | non-fips | CEF-over-syslog SIEM |
| `test:siem-cef-tcp-syslog` | non-fips | CEF-over-TCP-syslog SIEM (rsyslog) |
| `test:siem-filebeat` | non-fips | Filebeat → Elasticsearch SIEM |
| `test:siem-fluent-bit` | non-fips | Fluent Bit JSONL file-tailing SIEM |
| `test:monitoring` | non-fips | Monitoring stack (VictoriaMetrics + Grafana) |
| `test:otel` | fips | OTLP/OpenTelemetry export integration |

All audit/SIEM tests require a non-fips KMS binary and Docker. Every guard exits 1 if no
evidence is found — no silent skips. A pre-flight step removes any stale Docker container
occupying the test ports before starting.

Run all four integration areas at once:

```bash
cargo build --features non-fips          # build once
KMS_SKIP_BUILD=1 mise test:audit      --variant non-fips
KMS_SKIP_BUILD=1 mise test:cef        --variant non-fips
KMS_SKIP_BUILD=1 mise test:siem       --variant non-fips
KMS_SKIP_BUILD=1 mise test:monitoring --variant non-fips
```

Or run individual suites:

```bash
mise test:cef  --suite format        # CEF v27 format validation (jc parser)
mise test:cef  --suite syslog        # CEF → UDP syslog
mise test:cef  --suite tcp-syslog    # CEF → TCP rsyslog (RFC 6587)
mise test:siem --suite fluent-bit    # Fluent Bit JSONL file tailing
mise test:siem --suite filebeat      # Filebeat → Elasticsearch
```

#### Guard summary

| Command | Docker images used | Key guards |
|---|---|---|
| `mise test:audit` | — (KMS binary only) | ≥ 4 events written; hash chain intact (`ckms audit verify`); required fields present; ≥ 1 Success + ≥ 1 Failure |
| `mise test:cef --suite format` | — | CEF header format; 1:1 audit-to-CEF mapping; all extension keys; Success + Failure `outcome` |
| `mise test:cef --suite syslog` | — (nc listener) | All 4 CEF lines received via UDP |
| `mise test:cef --suite tcp-syslog` | `rsyslog/syslog_appliance_alpine:latest` | All 4 CEF lines received via TCP; field integrity preserved |
| `mise test:siem --suite fluent-bit` | `fluent/fluent-bit:4.0` | All events forwarded; required fields present |
| `mise test:siem --suite filebeat` | `docker.elastic.co/beats/filebeat:8.17.0` + `elasticsearch:8.17.0` | All events indexed; ingest pipeline normalises Success/Failure |
| `mise test:monitoring` | `otel/opentelemetry-collector-contrib:latest` + `victoriametrics/victoria-metrics:latest` + `grafana/grafana:latest` | KMS metric lines confirmed on Prometheus endpoint (guard: > 0); required metric families present; Grafana `database=ok` |

### Protocol & interoperability

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:wasm` | fips | WASM build + tests |
| `test:ui` | non-fips | All Playwright E2E tests (standard + auth + OIDC) |
| `test:ui-auth` | non-fips | Playwright E2E auth tests against a real Authentication Verifier |
| `test:ui-oidc` | non-fips | Playwright E2E OIDC tests against a real Auth0 IdP |
| `test:pykmip` | non-fips | PyKMIP + Synology DSM tests |
| `test:kmip-go` | non-fips | KMIP 1.0–1.4 compliance tests (ovh/kmip-go) |
| `test:jose` | non-fips | JOSE REST API + jwcrypto interoperability |
| `test:edb-tde` | non-fips | EDB TDE KMIP compliance |
| `test:docker` | fips | Docker image smoke tests |
| `test:docker-oracle` | — | Oracle TDE remote upgrade smoke test (non-fips, amd64 only) |
| `test:helm` | fips | Helm chart lint, template validation, and optional E2E deployment |
| `test:load-balancer` | fips | nginx load-balancer graceful shutdown |
| `test:iris` | non-fips | IRIS mTLS integration |
| `test:spire` | non-fips | SPIRE + Mistral client full integration |
| `test:spire-pki` | non-fips | KMS PKI capability validation |

### PKCS#11 & disk encryption

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:openssh` | non-fips | OpenSSH PKCS#11 integration |
| `test:luks` | non-fips | LUKS disk-encryption PKCS#11 |
| `test:veracrypt` | non-fips | VeraCrypt PKCS#11 integration |

### Utilities

| Task | Description |
|------|-------------|
| `test:vectors-rekey` | Generate ReKey and ReKeyKeyPair test vectors into `test_data/` |
| `test` / `test:_default` | Run all tests sequentially |

---

## package

| Task | Description |
|------|-------------|
| `package:deb` | Build Debian `.deb` package via Nix |
| `package:rpm` | Build RPM package via Nix |
| `package:dmg` | Build macOS DMG package |
| `package:pkcs11-zip` | Build PKCS#11 ZIP bundle |
| `package:smoke-deb` | Smoke test a `.deb` package |
| `package:smoke-rpm` | Smoke test an `.rpm` package |
| `package:k8s` | Build all Linux packages (deb + rpm) for the KMS Kubernetes Plugin |
| `package:k8s:deb` | Build `.deb` for the KMS Kubernetes Plugin |
| `package:k8s:rpm` | Build `.rpm` for the KMS Kubernetes Plugin |

---

## audit

| Task | Description |
|------|-------------|
| `audit` / `audit:_default` | Run all security audits (OWASP + crypto + multi-framework) |
| `audit:owasp` | OWASP Top 10 / ASVS security checks |
| `audit:crypto` | Cryptographic inventory scan |
| `audit:runtime` | Runtime network security assessment against a live KMS |

---

## docs

| Task | Description |
|------|-------------|
| `docs:build` | Build the KMS documentation book (mdBook) |
| `docs:generate` | Regenerate all documentation (server help, ckms markdown, KMIP tables, CBOM) |
| `docs:server-help` | Regenerate server `--help` documentation |
| `docs:ckms-markdown` | Regenerate `ckms` CLI markdown documentation |
| `docs:vector-readme` | Regenerate `crate/test_kms_server/README.md` from test vector manifests |
| `docs:log-index` | Update `log-reference.md` from source call-sites |
| `docs:log-index-check` | Check `log-reference.md` is in sync with source |

---

## bench

| Task | Description |
|------|-------------|
| `bench:ci` | CI sanity benchmark |
| `bench:load` | Load-test benchmark (optionally with Criterion micro-benchmarks) |
| `bench:load-hsm` | Load-test benchmark with SoftHSM2-backed key encryption key |
| `bench:flamegraph` | CPU-scaling flamegraph (requires Linux `perf`) |

---

## release

| Task | Description |
|------|-------------|
| `release:version` | Print workspace version from `Cargo.toml` |
| `release:bump` | Bump version across all `Cargo.toml` and config files |
| `release:changelog` | Regenerate `CHANGELOG.md` via `git-cliff` |
| `release:extract-changelog` | Extract a version's changelog entry into a file |
| `release:nix-update-hashes` | Build all Nix derivations and update vendor hashes |
| `release:update-hashes` | Fetch correct vendor hashes from a CI run |
| `release:publish-github-release` | Extract changelog notes and create/update the GitHub Release for a tag |
| `release:notify-discord` | Send a KMS release announcement to the Discord channel |
| `release:clean` | Remove Nix `result-*` symlinks |

---

## sbom

| Task | Description |
|------|-------------|
| `sbom:generate` | Generate SBOM (Software Bill of Materials) |

---

## git

| Task | Description |
|------|-------------|
| `git:loc-diff` | Show lines added/deleted/net vs a base branch, by folder and crate |

---

## demo

| Task | Description |
|------|-------------|
| `demo:reinitialize` | Reinitialize the demo KMS (`demo-kms.cosmian.dev`) |

---

## Library scripts (`.mise/lib/`)

Shared helpers sourced by tasks — not called directly.

| File | Role |
|------|------|
| `common.sh` | Logging, env init (`kms_init_env`), repo root detection |
| `kms_server.sh` | Start/stop KMS server for integration tests |
| `kms_build.sh` | Cargo build helpers (FIPS/non-FIPS, static/dynamic) |
| `nix_helpers.sh` | Nix shell detection and build invocation |
| `package_build.sh` | Package assembly helpers (deb/rpm/dmg) |
| `package_smoke.sh` | Package smoke-test helpers |
| `pkcs11_helpers.sh` | PKCS#11 module detection and loading |
| `softhsm2.sh` | SoftHSM2 token initialisation |
| `bench_helpers.sh` | Benchmark setup and result parsing |
| `k8s.sh` | Kubernetes / Minikube helpers |

---

## Legacy CI entrypoint (`.mise/scripts/nix.sh`)

`nix.sh` is a thin wrapper kept for backward compatibility with existing CI pipelines.
It delegates to the MISE tasks above via `nix-shell`. Prefer `mise run` for new workflows.

```bash
bash .mise/scripts/nix.sh [--variant fips|non-fips] [--link static|dynamic] \
  docker [--load] [--test] [--force]
  test <type>
  package
  sbom
  update-hashes
```

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
| `test:db:sqlite` | fips | SQLite workspace tests |
| `test:db:psql` | fips | PostgreSQL tests |
| `test:db:mysql` | fips | MySQL tests |
| `test:db:percona` | fips | Percona XtraDB tests |
| `test:db:mariadb` | fips | MariaDB tests |
| `test:db:pgedge` | fips | pgEdge active-active replication tests (2-node live cluster) |
| `test:db:multi-region-guards` | fips | Multi-region deployment-model guard suite (schema, trigger, gating, config detectors); `--variant non-fips` also runs the CO ceremony gating proof |
| `test:db:redis` | non-fips | Redis-findex tests |
| `test:hsm:matrix` | all | All HSM × DB backend × variant combinations |

### Cloud & SaaS integrations

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:cloud:google-cse` | fips | Google CSE tests |
| `test:cloud:gcp-cmek` | fips | GCP CMEK wrapping key tests |
| `test:cloud:azure-ekm` | non-fips | Azure EKM tests |
| `test:cloud:xks` | non-fips | AWS XKS tests |

### Secret backends

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:cloud:secret-cosmian-kms` | fips | Secrets against a local Cosmian KMS |
| `test:cloud:secret-aws` | non-fips | Secrets against AWS SSM Parameter Store |
| `test:cloud:secret-azure` | non-fips | Secrets against Azure Key Vault |
| `test:cloud:secret-vault` | non-fips | Secrets against HashiCorp Vault |

### HSM

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:hsm` | fips | All HSM tests |
| `test:hsm:softhsm2` | fips | SoftHSM2 |
| `test:hsm:utimaco` | fips | Utimaco simulator (Linux only) |
| `test:hsm:proteccio` | fips | Proteccio (Linux only) |
| `test:hsm:crypt2pay` | fips | Crypt2Pay (Linux only) |
| `test:hsm:luna` | fips | Thales Luna (Linux only; `LUNA_PASSWORD`, `LUNA_SLOT`) |
| `test:hsm:softhsm2` | fips | Same as `test:hsm:softhsm2` (flat alias) |
| `test:hsm:utimaco` | fips | Same as `test:hsm:utimaco` |
| `test:hsm:proteccio` | fips | Same as `test:hsm:proteccio` |
| `test:hsm:crypt2pay` | fips | Same as `test:hsm:crypt2pay` |
| `test:hsm:crypt2pay-simulator` | fips | Same as `test:hsm:crypt2pay-simulator` |
| `test:hsm:luna` | fips | Same as `test:hsm:luna` |

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
| `test:obs:audit` | non-fips | Audit log integration test (JSONL, hash chain, fields) |
| `test:obs` | non-fips | All CEF integration tests (format, UDP syslog, TCP rsyslog) |
| `test:obs:cef-format` | non-fips | CEF v27 format validation |
| `test:obs:cef-syslog` | non-fips | CEF over UDP syslog |
| `test:obs:cef-tcp-syslog` | non-fips | CEF over TCP syslog (rsyslog, RFC 6587) |
| `test:obs` | non-fips | All SIEM integration tests |
| `test:obs:cef-syslog` | non-fips | CEF-over-syslog SIEM |
| `test:obs:cef-tcp-syslog` | non-fips | CEF-over-TCP-syslog SIEM (rsyslog) |
| `test:obs:filebeat` | non-fips | Filebeat → Elasticsearch SIEM |
| `test:obs:fluent-bit` | non-fips | Fluent Bit JSONL file-tailing SIEM |
| `test:obs:monitoring` | non-fips | Monitoring stack (VictoriaMetrics + Grafana) |
| `test:obs:otel` | fips | OTLP/OpenTelemetry export integration |

All audit/SIEM tests require a non-fips KMS binary and Docker. Every guard exits 1 if no
evidence is found — no silent skips. A pre-flight step removes any stale Docker container
occupying the test ports before starting.

Run all four integration areas at once:

```bash
cargo build --features non-fips          # build once
KMS_SKIP_BUILD=1 mise test:obs:audit      --variant non-fips
KMS_SKIP_BUILD=1 mise test:obs        --variant non-fips
KMS_SKIP_BUILD=1 mise test:obs       --variant non-fips
KMS_SKIP_BUILD=1 mise test:obs:monitoring --variant non-fips
```

Or run individual suites:

```bash
mise test:obs  --suite format        # CEF v27 format validation (jc parser)
mise test:obs  --suite syslog        # CEF → UDP syslog
mise test:obs  --suite tcp-syslog    # CEF → TCP rsyslog (RFC 6587)
mise test:obs --suite fluent-bit    # Fluent Bit JSONL file tailing
mise test:obs --suite filebeat      # Filebeat → Elasticsearch
```

#### Guard summary

| Command | Docker images used | Key guards |
|---|---|---|
| `mise test:obs:audit` | — (KMS binary only) | ≥ 4 events written; hash chain intact (`ckms audit verify`); required fields present; ≥ 1 Success + ≥ 1 Failure |
| `mise test:obs --suite format` | — | CEF header format; 1:1 audit-to-CEF mapping; all extension keys; Success + Failure `outcome` |
| `mise test:obs --suite syslog` | — (nc listener) | All 4 CEF lines received via UDP |
| `mise test:obs --suite tcp-syslog` | `rsyslog/syslog_appliance_alpine:latest` | All 4 CEF lines received via TCP; field integrity preserved |
| `mise test:obs --suite fluent-bit` | `fluent/fluent-bit:4.0` | All events forwarded; required fields present |
| `mise test:obs --suite filebeat` | `docker.elastic.co/beats/filebeat:8.17.0` + `elasticsearch:8.17.0` | All events indexed; ingest pipeline normalises Success/Failure |
| `mise test:obs:monitoring` | `otel/opentelemetry-collector-contrib:latest` + `victoriametrics/victoria-metrics:latest` + `grafana/grafana:latest` | KMS metric lines confirmed on Prometheus endpoint (guard: > 0); required metric families present; Grafana `database=ok` |

### Protocol & interoperability

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:ui:wasm` | fips | WASM build + tests |
| `test:ui` | non-fips | All Playwright E2E tests (standard + auth + OIDC) |
| `test:ui:auth` | non-fips | Playwright E2E auth tests against a real Authentication Verifier |
| `test:ui:oidc` | non-fips | Playwright E2E OIDC tests against a real Auth0 IdP |
| `test:interop:pykmip` | non-fips | PyKMIP + Synology DSM tests |
| `test:interop:kmip-go` | non-fips | KMIP 1.0–1.4 compliance tests (ovh/kmip-go) |
| `test:interop:jose` | non-fips | JOSE REST API + jwcrypto interoperability |
| `test:interop:edb-tde` | non-fips | EDB TDE KMIP compliance |
| `test:pkg:docker` | fips | Docker image smoke tests |
| `test:pkg:docker-scan` | fips | Syft SBOM + Grype scan of a Docker image, `Cargo.lock` and `ui/pnpm-lock.yaml` (fails on fixable High/Critical) |
| `test:pkg:docker-oracle` | — | Oracle TDE remote upgrade smoke test (non-fips, amd64 only) |
| `test:k8s:helm` | fips | Helm chart lint, template validation, and optional E2E deployment |
| `test:pkg:load-balancer` | fips | nginx load-balancer graceful shutdown |
| `test:interop:iris` | non-fips | IRIS mTLS integration |
| `test:spire` | non-fips | SPIRE + Mistral client full integration |
| `test:spire:pki` | non-fips | KMS PKI capability validation |

### PKCS#11 & disk encryption

| Task | Default variant | Description |
|------|-----------------|-------------|
| `test:pkcs11:openssh` | non-fips | OpenSSH PKCS#11 integration |
| `test:pkcs11:luks` | non-fips | LUKS disk-encryption PKCS#11 |
| `test:pkcs11:veracrypt` | non-fips | VeraCrypt PKCS#11 integration |

### Utilities

| Task | Description |
|------|-------------|
| `dev:vectors-rekey` | Generate ReKey and ReKeyKeyPair test vectors into `test_data/` |
| `dev:ci-uncovered-tasks` | Inventory the mise tasks no CI workflow runs, directly or through another task (`--strict` exits 1 if any) |
| `dev:ci-ignored-tests` | Inventory the `#[ignore]` Rust tests no `cargo test --ignored` in any MISE task, script or lib runs (`--ci`: only those a CI workflow reaches; `--strict` exits 1 if any) |
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
| `docs` | Run all documentation sync tasks (mdbook-build, sync-all, sync-logs check) |
| `docs:mdbook-build` | Build the KMS documentation site with mdBook (`--combined`, or `PUBLIC_DOCS_TOKEN` in CI: also build the public combined docs with this checkout and the other products' staging branches) |
| `docs:sync-all` | Sync all generated documentation (server help, ckms markdown, KMIP tables, CBOM, logs) |
| `docs:sync-server-help` | Sync server `--help` documentation from source |
| `docs:sync-ckms-help` | Sync `ckms` CLI markdown documentation from source |
| `docs:sync-vectors` | Sync test vectors README from all test vector manifests |
| `docs:sync-logs` | Sync `log-reference.md` documentation from source log callsites |
| `docs:check-logs` | Verify `log-reference.md` is in sync with source (CI check) |

---

## bench

| Task | Description |
|------|-------------|
| `bench:ci` | CI sanity benchmark |
| `bench:load` | Load-test benchmark (optionally with Criterion micro-benchmarks) |
| `bench:hsm` | Load-test benchmark with SoftHSM2-backed key encryption key |
| `bench:flamegraph` | CPU-scaling flamegraph (requires Linux `perf`) |

---

## release

| Task | Description |
|------|-------------|
| `release:version` | Print workspace version from `Cargo.toml` |
| `release:bump` | Bump version across all `Cargo.toml` and config files |
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

---
name: 'Docker and Kubernetes'
description: 'Docker image build/test conventions and Kubernetes deployment patterns for the Eviden KMS project'
applyTo: 'nix/docker.nix, nix/k8s-images.nix, .mise/scripts/docker-compose.yml, .mise/scripts/test/test_docker_image.sh, .mise/lib/k8s.sh, .mise/tasks/build/docker, .mise/tasks/test/docker, .mise/tasks/test/k8s/**, charts/cosmian-kms/**/*, .github/workflows/packaging-docker.yml'
---

# Docker and Kubernetes conventions

## 1. Image build architecture — Nix

All KMS Docker images are built with **Nix** via `pkgs.dockerTools.buildLayeredImage`.
There is no `Dockerfile`. The Nix expression lives in:

| File | Purpose |
|------|---------|
| `nix/docker.nix` | Main KMS server image (`kms-fips` / `kms`) |
| `nix/k8s-images.nix` | K8s operator and CSI provider images |

### Critical: `buildLayeredImage` + `buildEnv` symlink trap

`contents = [...]` is merged via `pkgs.buildEnv`/`lndir`. When **only one** derivation
in the list contributes a given subtree, `buildEnv` keeps that path as a **read-only
symlink into the Nix store** rather than creating a real merged directory.

**Consequence**: any `mkdir`, `cp`, or `tee` in `fakeRootCommands` targeting such a path
fails with "Permission denied" even under fakeroot, because the symlink points to a
genuinely read-only Nix store path.

**Fix pattern** — use `ensure_writable_dir` before every write:

```bash
ensure_writable_dir() {
  local dir="$1"
  if [ -L "$dir" ]; then
    local target; target=$(readlink "$dir")
    rm "$dir"
    mkdir -p "$dir"
    cp -r "$target/." "$dir/" || true
  else
    mkdir -p "$dir"
    chmod u+w "$dir"
  fi
}
```

Apply this to **every directory** `fakeRootCommands` writes into, before the first write.

### Required packages in `runtimeEnv`

`coreutils` does **not** include `grep`. Always add `pkgs.gnugrep` explicitly:

```nix
runtimeEnv = pkgs.buildEnv {
  paths = [
    pkgs.coreutils   # ls, cp, mkdir, chmod…
    pkgs.bash        # shell scripts, entrypoint
    pkgs.gnugrep     # grep — not in coreutils; required by in-image scripts
    pkgs.curl        # health checks, k8s probes
    pkgs.wget        # CMD-SHELL health checks
    pkgs.netcat-openbsd  # nc -z TLS port probes
    pkgs.tzdata      # timezone data
    # …
  ];
};
```

**Never use** `pkgs.busybox` — it includes a `/dev/pts/ptmx` character device node
that causes `failed to register layer` on older containerd versions (< 1.6.8).

### Required `/etc` files

The following `/etc` entries must be created in `fakeRootCommands` and must be present
at runtime (absence causes issue #1132 class failures in Kubernetes):

| File | Why required |
|------|-------------|
| `/etc/passwd` | UID/GID resolution — `runAsNonRoot`, `getpwuid()`, nsswitch |
| `/etc/group` | GID resolution |
| `/etc/nsswitch.conf` | DNS / hostname resolution in containers |
| `/etc/ssl/certs/ca-bundle.crt` | Outbound TLS: OIDC, webhook, curl |
| `/etc/cosmian/` | Bind-mount target for `COSMIAN_KMS_CONF` |

`SSL_CERT_FILE` in the image must point to `/etc/ssl/certs/ca-bundle.crt`.
The CA bundle is populated from `pkgs.cacert` via:

```bash
cp ${caBundle}/etc/ssl/certs/ca-bundle.crt etc/ssl/certs/ca-bundle.crt
```

### Build commands

```bash
# Build (outputs a .tar.gz Nix store path, symlinked as result-docker-*)
mise run build:docker --variant fips
mise run build:docker --variant non-fips

# Build and load directly into local Docker daemon
mise run build:docker --variant fips --load

# Build and run smoke tests (requires Docker daemon)
mise run build:docker --variant fips --load && mise run test:docker --variant fips
```

### Verification after every `nix/docker.nix` change

After any change to `nix/docker.nix`, always verify:

```bash
# 1. Build both variants
mise run build:docker --variant fips --load
mise run build:docker --variant non-fips --load

# 2. CA bundle and grep must work inside the container
docker run --rm --entrypoint '' cosmian-kms:<VERSION>-fips sh -c \
  'grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-bundle.crt'
# Must print ≥ 50

# 3. Full smoke test suite (TLS, non-root, CA bundle, Oracle TDE…)
DOCKER_IMAGE_NAME=cosmian-kms:<VERSION>-fips mise run test:docker --variant fips
DOCKER_IMAGE_NAME=cosmian-kms:<VERSION>-non-fips mise run test:docker --variant non-fips
```

---

## 2. Docker Compose test setup

The integration test stack lives in `.mise/scripts/docker-compose.yml`.
All services share a single compose file; optional test scenarios use `--profile`.

| Service | Purpose |
|---------|---------|
| `kms-no-conf` | No-config smoke test (default SQLite, no env vars) |
| `kms-nonroot` | Non-root UID 1000 smoke test (regression: issue #1132) |
| `kms-with-conf` | Config-file based startup |
| `kms-example` | Example docker-compose usage pattern |
| `no-authentication` | Plain HTTP (no auth) |
| `tls-authentication` | TLS 1.2 + 1.3 |
| `tls13-authentication` | TLS 1.3 only |
| `kms1/kms2/kms3` | Load-balancer cluster |
| `nginx-load-balancer` | Nginx round-robin in front of kms1/2/3 |
| `postgres` | PostgreSQL backend (used by kms1/2/3 cluster) |
| `oracle` (profile) | Oracle DB for PKCS#11/TDE integration tests |
| `kms-oracle` (profile) | KMS co-deployed with Oracle DB |

### Port slot isolation

Test ports are allocated via `.mise/lib/test_slots.sh` to avoid conflicts when multiple
test runs execute concurrently on the same machine.

### Running the Docker image tests

```bash
# The DOCKER_IMAGE_NAME variable selects the image under test
DOCKER_IMAGE_NAME=cosmian-kms:5.26.0-fips mise run test:docker --variant fips

# CI sets it to the GHCR arch-specific tag, e.g.:
# DOCKER_IMAGE_NAME=ghcr.io/cosmian/kms-fips:fix-branch-amd64
```

### Test stages (in order)

1. **TLS connectivity** — openssl s_client probes for TLS 1.2 and 1.3, and verify TLS 1.2
   rejection on TLS-1.3-only ports.
2. **UI endpoints** — confirm `/ui/index.html` serves 200.
3. **No-config smoke test** — `/version` returns JSON with no config file or env vars.
4. **Non-root user smoke test** — `/version` works when KMS runs as UID 1000
   (validates `/etc/passwd` presence).
5. **CA bundle test** — `grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/ca-bundle.crt` must
   return ≥ 50 inside the container (validates `grep` binary + CA bundle correctness).
6. **Config-file compose test** — `docker compose logs kms-with-conf`.
7. **Load balancer shutdown test** — `.mise/scripts/test/test_lb_kms_shutdown.sh`.
8. **Oracle TDE HSM test** — PKCS#11 TDE migration `software → HSM → software`.

---

## 3. Kubernetes — Helm chart

The Helm chart lives in `charts/cosmian-kms/`. It deploys the KMS server with
**production-grade security context by default**:

```yaml
# Enforced by default — never relax in tests without a documented reason
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000   # matches /etc/passwd entry
  runAsGroup: 1000

securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
```

These defaults are tested by every `test:k8s:kms-image` run (see section 5).

### Key Helm values for local testing

```bash
# Use SQLite without a PVC (fast, no pvc-protection finalizer blocking teardown)
helm upgrade --install kms-test charts/cosmian-kms \
  --namespace kms-test \
  --set kms.database.type=sqlite \
  --set persistence.enabled=false \
  --set-json 'extraVolumes=[{"name":"sqlite-emptydir","emptyDir":{}}]' \
  --set-json 'extraVolumeMounts=[{"name":"sqlite-emptydir","mountPath":"/var/lib/cosmian-kms/sqlite-data"}]' \
  --set image.pullPolicy=Never \
  --wait --timeout 180s
```

---

## 4. Kubernetes — `k8s.sh` helpers

Import in MISE tasks: `source "${MISE_CONFIG_ROOT}/.mise/lib/k8s.sh"`

| Helper | Purpose |
|--------|---------|
| `k8s_require_tools` | Assert `kubectl`, `helm`, `minikube` are available |
| `k8s_deploy_kms <ns> <release> [extra helm args]` | Deploy KMS via Helm with SQLite emptyDir |
| `k8s_teardown <ns> <release>` | `helm uninstall` + `kubectl delete namespace` |
| `k8s_kms_cluster_ip <ns> <release>` | Return ClusterIP of the KMS Service |
| `k8s_wait_kms_http <url> [timeout]` | Poll `/version` until KMS answers |
| `k8s_ckms_conf <workdir> <url>` | Write a `~/.cosmian/*.toml` fixture for `ckms` |
| `k8s_create_secret <ckms> <conf> <value> <name>` | `ckms secret-data create` → return UID |
| `k8s_create_kek <ckms> <conf> <name>` | `ckms sym keys create` → return UID |
| `k8s_revoke_object <ckms> <conf> <uid>` | `ckms objects revoke` |
| `k8s_locate_bin <name> <fallback>` | Find binary in PATH or `result-*/bin/` |
| `k8s_dump_debug <ns> <release>` | Print pod/service/event diagnostics on failure |
| `k8s_wait_node_socket <path> [timeout]` | Wait for a socket to appear on the Minikube node |

### Namespace teardown convention

Always use `k8s_teardown` or `kubectl delete namespace --timeout=60s` at the end of a test.
Never leave namespaces with `pvc-protection` finalizers — use `emptyDir` for SQLite data.

---

## 5. CI coverage matrix

The `packaging-docker.yml` workflow tests the following combinations:

| Job | fips | non-fips | amd64 | arm64 |
|-----|------|----------|-------|-------|
| `nix-docker-image` (build + `test:docker`) | ✅ | ✅ | ✅ | ✅ |
| `test-k8s-kms-pod` (`test:k8s:kms-image`) | ✅ | ✅ | ✅ | ✅ |
| `k8s-operator-image` (build + `test:k8s:operator-image`) | n/a | n/a | ✅ | ✅ |
| `k8s-csi-provider-image` (build + `test:k8s:csi-provider-image`) | n/a | n/a | ✅ | ✅ |
| `nix-docker-manifest` (multi-arch manifest) | ✅ | ✅ | n/a | n/a |

**All four combinations of `{fips, non-fips} × {amd64, arm64}` must remain covered.**
If you add a new image or new runner, update this table.

### Triggering the workflow manually

```bash
# Requires toolchain input; default is 1.97.0
GH_PAGER=cat gh workflow run "Packaging - Docker" \
  --repo Cosmian/kms \
  --ref <branch> \
  -f toolchain=1.97.0
```

The workflow is `workflow_call` + `workflow_dispatch` only — it does **not** trigger
automatically on push to feature branches.

---

## 6. Known issues and regression markers

| Issue | Symptom | Root cause | Fix |
|-------|---------|-----------|-----|
| #1132 | `/etc/passwd` missing → pod CrashLoopBackOff as UID 1000 | `buildLayeredImage` `fakeRootCommands` wrote into Nix-store symlink; permission denied | `ensure_writable_dir` helper in `fakeRootCommands` |
| #1132 | CA bundle has 0 certificates | `grep` binary missing from Docker image | Add `pkgs.gnugrep` to `runtimeEnv` |
| pre-#1132 | `failed to register layer: openat dev/pts/ptmx` | `pkgs.busybox` adds character devices | Replaced by `coreutils` + `bash` + explicit utils |

---

## 7. AGENTS.md sync rules

After modifying any of the covered files, run `/kms-sync-rules` and check these rules:

- `nix/docker.nix` → rebuild both variants locally, run `test:docker` for both
- `.mise/scripts/docker-compose.yml` → run `test:docker` for both variants
- `.mise/scripts/test/test_docker_image.sh` → run `test:docker --variant fips` locally
- `.mise/lib/k8s.sh` or `.mise/tasks/test/k8s/**` → run `test:k8s:kms-image` locally
- `charts/cosmian-kms/**` → run `test:k8s:kms-image` and `helm lint charts/cosmian-kms`
- `.github/workflows/packaging-docker.yml` → verify the CI matrix table in section 5 is still accurate

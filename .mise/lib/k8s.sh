#!/usr/bin/env bash
# .mise/lib/k8s.sh — Shared helpers for the Kubernetes E2E MISE tasks
# (test:k8s:plugin, test:k8s:csi-provider, test:k8s:operator, test:k8s:*-image).
#
# Source this AFTER common.sh:
#   source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
#   source "${MISE_CONFIG_ROOT}/.mise/lib/k8s.sh"
#
# Provides:
#   Requirements:   k8s_require_tools
#   Binaries:       k8s_locate_bin, k8s_install_node_bin
#   PKI (mTLS):     k8s_gen_pki
#   KMS deploy:     k8s_deploy_kms, k8s_wait_kms_http, k8s_kms_cluster_ip
#   ckms helpers:   k8s_ckms_conf, k8s_create_kek, k8s_create_secret,
#                   k8s_revoke_object
#   systemd node:   k8s_write_systemd_unit, k8s_install_service_file,
#                   k8s_wait_node_socket,
#                   k8s_restart_node_service, k8s_stop_node_service
#   Diagnostics:    k8s_dump_debug

# ── Guard against double-sourcing ─────────────────────────────────────────────
[ -n "${_MISE_K8S_SH_LOADED:-}" ] && return 0
_MISE_K8S_SH_LOADED=1

# ── Requirements ──────────────────────────────────────────────────────────────

# Verify the cluster tooling is present and a cluster is reachable.
k8s_require_tools() {
  require_cmd kubectl "kubectl is required for Kubernetes E2E tests"
  require_cmd helm "helm is required for Kubernetes E2E tests"
  require_cmd minikube "minikube is required for Kubernetes E2E tests"
  require_cmd openssl "openssl is required to generate the test PKI"
  kubectl cluster-info >/dev/null 2>&1 ||
    print_error "No reachable Kubernetes cluster. Start one with: minikube start --driver=docker"
}

# ── Binaries ──────────────────────────────────────────────────────────────────

# Resolve the path to a release binary, building it on demand for local runs.
# In CI (CI=true / GITHUB_ACTIONS=true) the binary MUST already exist — the
# build is performed once by a dedicated workflow job and downloaded as an
# artifact, so we never rebuild here (avoids duplicating the workspace build
# already done by the nix test jobs).
#
# Usage: bin=$(k8s_locate_bin <crate-package> <binary-name>)
k8s_locate_bin() {
  local pkg="$1" bin_name="$2"
  local bin_path="${MISE_CONFIG_ROOT}/target/release/${bin_name}"

  if [ -x "$bin_path" ]; then
    echo "$bin_path"
    return 0
  fi

  if [ "${CI:-false}" = "true" ] || [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
    print_error "Expected prebuilt binary '${bin_name}' at ${bin_path} (download the k8s-bins artifact before running this task in CI)."
  fi

  print_status "Building ${bin_name} (${pkg}) for local run..." >&2
  (cd "${MISE_CONFIG_ROOT}" && cargo build --release -p "$pkg") >&2 ||
    print_error "Failed to build ${pkg}"
  echo "$bin_path"
}

# Copy a binary into the Minikube node and make it executable.
# Usage: k8s_install_node_bin <local-path> <node-path>
k8s_install_node_bin() {
  local local_path="$1" node_path="$2"
  minikube cp "$local_path" "$node_path"
  minikube ssh -- sudo chmod +x "$node_path"
}

# ── PKI (for --mtls / --tls modes) ────────────────────────────────────────────

# Generate a self-signed CA plus a server certificate and a client certificate
# into <dir>.  The server certificate carries SANs so both the in-cluster DNS
# name and the ClusterIP are valid; the client certificate carries an email SAN
# used by the KMS to derive the authenticated username.
#
# Produces: ca.crt ca.key server.crt server.key client.crt client.key
#
# Usage: k8s_gen_pki <dir> <server_dns> <server_ip> <client_email>
k8s_gen_pki() {
  local dir="$1" server_dns="$2" server_ip="$3" client_email="$4"
  mkdir -p "$dir"

  # CA
  openssl req -x509 -newkey rsa:4096 -nodes -days 2 \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" \
    -subj "/CN=Cosmian KMS E2E Test CA" >/dev/null 2>&1

  # Server key + CSR
  openssl req -newkey rsa:4096 -nodes \
    -keyout "$dir/server.key" -out "$dir/server.csr" \
    -subj "/CN=${server_dns}" >/dev/null 2>&1

  cat >"$dir/server.ext" <<EOF
subjectAltName = DNS:${server_dns},DNS:localhost,IP:${server_ip},IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
  openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -days 2 -extfile "$dir/server.ext" \
    -out "$dir/server.crt" >/dev/null 2>&1

  # Client key + CSR (email SAN → KMS username)
  openssl req -newkey rsa:4096 -nodes \
    -keyout "$dir/client.key" -out "$dir/client.csr" \
    -subj "/CN=${client_email}" >/dev/null 2>&1

  cat >"$dir/client.ext" <<EOF
subjectAltName = email:${client_email}
extendedKeyUsage = clientAuth
EOF
  openssl x509 -req -in "$dir/client.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
    -CAcreateserial -days 2 -extfile "$dir/client.ext" \
    -out "$dir/client.crt" >/dev/null 2>&1

  print_status "Generated test PKI in $dir (server SANs: ${server_dns},${server_ip})"
}

# ── KMS deployment ────────────────────────────────────────────────────────────

# Deploy the Cosmian KMS into the cluster via the Helm chart.
# Extra `helm --set`/`--set-file` arguments may be appended.
#
# Usage: k8s_deploy_kms <namespace> <release> [extra helm args...]
k8s_deploy_kms() {
  local namespace="$1" release="$2"
  shift 2
  kubectl create namespace "$namespace" --dry-run=client -o yaml | kubectl apply -f -
  helm install "$release" "${MISE_CONFIG_ROOT}/charts/cosmian-kms" \
    --namespace "$namespace" \
    --set kms.database.type=sqlite \
    --set image.tag="${KMS_IMAGE_TAG:-latest}" \
    "$@" \
    --wait --timeout 180s
  print_success "KMS deployed (release=$release, ns=$namespace)"
}

# Echo the in-cluster ClusterIP of the KMS Service.
# Usage: k8s_kms_cluster_ip <namespace> <release>
k8s_kms_cluster_ip() {
  local namespace="$1" release="$2"
  kubectl get svc -n "$namespace" "${release}-cosmian-kms" \
    -o jsonpath='{.spec.clusterIP}'
}

# Wait for the KMS /version endpoint to answer on localhost:<port>.
# Usage: k8s_wait_kms_http <url> [timeout]
k8s_wait_kms_http() {
  local url="$1" timeout="${2:-30}"
  timeout "$timeout" bash -c \
    "until curl -skf '$url' >/dev/null; do sleep 1; done" ||
    print_error "KMS did not answer at $url within ${timeout}s"
}

# ── ckms helpers ──────────────────────────────────────────────────────────────

# Write a ckms client TOML config and echo its path.
# Usage: k8s_ckms_conf <dir> <server_url> [client_cert] [client_key]
k8s_ckms_conf() {
  local dir="$1" server_url="$2" client_cert="${3:-}" client_key="${4:-}"
  local conf="$dir/ckms.toml"
  {
    echo "[http_config]"
    echo "server_url = \"$server_url\""
    echo "accept_invalid_certs = true"
    if [ -n "$client_cert" ]; then
      echo "tls_client_pem_cert_path = \"$client_cert\""
      echo "tls_client_pem_key_path = \"$client_key\""
    fi
  } >"$conf"
  echo "$conf"
}

# Extract the first UUID found in a string.
_k8s_parse_uuid() {
  grep -ioP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1
}

# Create an AES-256 wrapping key (KEK) and echo its UID.
# Usage: k8s_create_kek <ckms-bin> <conf> <tag>
k8s_create_kek() {
  local ckms="$1" conf="$2" tag="$3" out uid
  out=$(CKMS_CONF_PATH="$conf" "$ckms" sym keys create \
    --algorithm aes --number-of-bits 256 --tag "$tag")
  uid=$(echo "$out" | _k8s_parse_uuid)
  [ -n "$uid" ] || {
    echo "$out" >&2
    print_error "could not parse KEK UID"
  }
  echo "$uid"
}

# Create a SecretData object with a known value and echo its UID.
# Usage: k8s_create_secret <ckms-bin> <conf> <value> <tag>
k8s_create_secret() {
  local ckms="$1" conf="$2" value="$3" tag="$4" out uid
  out=$(CKMS_CONF_PATH="$conf" "$ckms" secret-data create \
    --value "$value" --type password --tag "$tag")
  uid=$(echo "$out" | _k8s_parse_uuid)
  [ -n "$uid" ] || {
    echo "$out" >&2
    print_error "could not parse SecretData UID"
  }
  echo "$uid"
}

# Revoke a KMS object (used for the revocation / graceful-failure test).
# Usage: k8s_revoke_object <ckms-bin> <conf> <uid>
k8s_revoke_object() {
  local ckms="$1" conf="$2" uid="$3"
  CKMS_CONF_PATH="$conf" "$ckms" secret-data revoke \
    --secret-data-id "$uid" "e2e revocation test" >/dev/null 2>&1 || true
  CKMS_CONF_PATH="$conf" "$ckms" secret-data destroy \
    --key-id "$uid" --remove >/dev/null 2>&1 || true
}

# ── systemd on the Minikube node ──────────────────────────────────────────────

# Install the bundled production service file on the Minikube node and start it.
# This validates the same unit file shipped inside the deb/rpm package.
# The service file must have ExecStart pointing to /usr/local/bin/<name> and
# read its config from /etc/cosmian-<name>/config.yaml (the production layout).
# Usage: k8s_install_service_file <local-service-file-path> <service-name>
k8s_install_service_file() {
  local src="$1" name="$2"
  local tmp="/tmp/${name}.service"
  minikube cp "$src" "$tmp"
  minikube ssh -- sudo cp "$tmp" "/etc/systemd/system/${name}.service"
  minikube ssh -- sudo systemctl daemon-reload
  minikube ssh -- sudo systemctl enable --now "$name"
}

# Wait until a Unix socket exists on the Minikube node.
# Usage: k8s_wait_node_socket <socket-path> [timeout]
k8s_wait_node_socket() {
  local socket="$1" timeout="${2:-30}"
  timeout "$timeout" bash -c \
    "until minikube ssh -- sudo test -S '$socket' 2>/dev/null; do sleep 2; done" ||
    print_error "socket $socket did not appear within ${timeout}s"
  print_status "socket ready: $socket"
}

# Restart a systemd service on the node and wait for it to be active.
# Usage: k8s_restart_node_service <service-name>
k8s_restart_node_service() {
  local name="$1"
  minikube ssh -- sudo systemctl restart "$name"
  timeout 30 bash -c \
    "until minikube ssh -- sudo systemctl is-active '$name' 2>/dev/null | tr -d '\r' | grep -q '^active$'; do sleep 2; done" ||
    print_error "service $name did not become active after restart"
}

# Stop a systemd service on the node.
# Usage: k8s_stop_node_service <service-name>
k8s_stop_node_service() {
  minikube ssh -- sudo systemctl stop "$1"
}

# ── Diagnostics ───────────────────────────────────────────────────────────────

# Dump broad diagnostic info; call from a failure trap.
# Usage: k8s_dump_debug <namespace> <release> [extra-service-names...]
k8s_dump_debug() {
  local namespace="$1" release="$2"
  shift 2
  echo "========== K8S E2E DEBUG DUMP =========="
  echo "--- nodes ---"
  kubectl get nodes 2>&1 || true
  echo "--- pods (all ns) ---"
  kubectl get pods -A 2>&1 || true
  echo "--- helm status ---"
  helm status "$release" -n "$namespace" 2>&1 || true
  echo "--- KMS logs ---"
  kubectl logs -n "$namespace" -l "app.kubernetes.io/instance=$release" --tail=80 2>&1 || true
  echo "--- healthz (verbose) ---"
  kubectl get --raw "/healthz?verbose" 2>&1 || true
  echo "--- kms-providers healthz ---"
  kubectl get --raw "/healthz/kms-providers" 2>&1 || true
  local svc
  for svc in "$@"; do
    echo "--- systemd: $svc ---"
    minikube ssh -- sudo systemctl status "$svc" --no-pager 2>&1 || true
    echo "--- journald: $svc ---"
    minikube ssh -- sudo journalctl -u "$svc" -n 80 --no-pager 2>&1 || true
  done
  echo "========================================"
}

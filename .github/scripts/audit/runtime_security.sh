#!/usr/bin/env bash
# =============================================================================
# Cosmian KMS — Runtime Network Security Analyser
# =============================================================================
# Performs a comprehensive black-box security assessment of a running KMS
# server using exclusively open-source tools available on any modern Linux:
#
#   • openssl s_client  — cipher suite negotiation, cert chain, protocol versions
#   • curl              — HTTP security headers, HSTS, CORS, Content-Security-Policy
#   • nmap (optional)   — port scan, TLS NSE scripts (nmap --script ssl-*)
#   • sslyze (optional) — deep TLS analysis, certificate transparency, OCSP
#   • nuclei (optional) — template-based vulnerability scanning
#   • Custom Python     — KMIP protocol tests, rate-limit probes, auth checks
#
# Usage:
#   bash .github/scripts/audit/runtime_security.sh --server-url https://HOST:PORT \
#       [--cert certs/client.pem] [--key certs/client.key] [--ca certs/ca.pem] \
#       [--output-dir /tmp/runtime-<ts>] [--report] [--insecure]
#
# Options:
#   --server-url  <url>   KMS server URL (required, e.g. https://localhost:9998)
#   --cert        <path>  Client TLS certificate (for mTLS tests)
#   --key         <path>  Client TLS private key (for mTLS tests)
#   --ca          <path>  CA certificate for server verification
#   --output-dir  <path>  Output directory (default: cbom/runtime/ — overwritten on each run)
#   --report      <path>  Write Markdown report (default: stdout summary only)
#   --insecure            Skip server cert verification (dev environments)
#   --help                Show this help
#
# Exit code: 0 = all checks PASS;  1 = critical finding(s);  2 = tool error
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/cbom/runtime"
SERVER_URL=""
CLIENT_CERT=""
CLIENT_KEY=""
CA_CERT=""
REPORT_PATH=""
INSECURE=false
OVERALL_EXIT=0

# ─── Colour helpers ───────────────────────────────────────────────────────────
RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
info()   { echo "${CYAN}${BOLD}[RUNTIME]${RESET} $*"; }
ok()     { echo "${GREEN}${BOLD}[  PASS  ]${RESET} $*"; }
warn()   { echo "${YELLOW}${BOLD}[  WARN  ]${RESET} $*"; }
fail()   { echo "${RED}${BOLD}[  FAIL  ]${RESET} $*"; OVERALL_EXIT=1; }
banner() { echo; echo "${BOLD}══════════════════════════════════════════════════${RESET}"; echo "${BOLD}  $*${RESET}"; echo "${BOLD}══════════════════════════════════════════════════${RESET}"; }

usage() {
  cat <<'EOF'
Usage: bash runtime_security.sh --server-url https://HOST:PORT [OPTIONS]

Required:
  --server-url <url>   Running KMS server (e.g. https://localhost:9998)

Optional:
  --cert    <path>     Client certificate for mTLS tests
  --key     <path>     Client private key for mTLS tests
  --ca      <path>     CA certificate for server verification
  --output-dir <path>  Output directory (default: cbom/runtime/ — overwritten each run)
  --report  <path>     Write Markdown report to this file
  --insecure           Disable server certificate verification
  --help               Show this message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-url)  SERVER_URL="$2"; shift 2 ;;
    --cert)        CLIENT_CERT="$2"; shift 2 ;;
    --key)         CLIENT_KEY="$2"; shift 2 ;;
    --ca)          CA_CERT="$2"; shift 2 ;;
    --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
    --report)      REPORT_PATH="$2"; shift 2 ;;
    --insecure)    INSECURE=true; shift ;;
    --help|-h)     usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 2 ;;
  esac
done

if [[ -z "$SERVER_URL" ]]; then
  echo "${RED}ERROR: --server-url is required.${RESET}"
  usage
  exit 2
fi

# ─── Parse host/port from URL ─────────────────────────────────────────────────
HOST=$(python3 -c "from urllib.parse import urlparse; u=urlparse('$SERVER_URL'); print(u.hostname)")
PORT=$(python3 -c "from urllib.parse import urlparse; u=urlparse('$SERVER_URL'); print(u.port or 9998)")
SCHEME=$(python3 -c "from urllib.parse import urlparse; u=urlparse('$SERVER_URL'); print(u.scheme)")

CURL_BASE_ARGS=()
OPENSSL_CA_ARGS=()
[[ "$INSECURE" == true ]] && CURL_BASE_ARGS+=("-k")
[[ -n "$CA_CERT" ]] && { OPENSSL_CA_ARGS+=("-CAfile" "$CA_CERT"); CURL_BASE_ARGS+=("--cacert" "$CA_CERT"); }

mkdir -p "$OUTPUT_DIR"

# ─── Initialise JSON results ──────────────────────────────────────────────────
RESULTS_JSON="$OUTPUT_DIR/runtime_results.json"
python3 - <<PYEOF
import json
from datetime import datetime, timezone
result = {
    "scan_date": datetime.now(timezone.utc).isoformat(),
    "server_url": "$SERVER_URL",
    "host": "$HOST",
    "port": $PORT,
    "insecure": $([[ "$INSECURE" == true ]] && echo "true" || echo "false"),
    "checks": {}
}
import os; os.makedirs("$OUTPUT_DIR", exist_ok=True)
open("$RESULTS_JSON", "w").write(json.dumps(result, indent=2))
PYEOF

# ─── Helper: record check result to JSON ─────────────────────────────────────
record_check() {
  local name="$1" status="$2" detail="$3" severity="${4:-INFO}"
  python3 - <<PYEOF
import json
from pathlib import Path
p = Path("$RESULTS_JSON")
r = json.loads(p.read_text())
r["checks"]["$name"] = {"status": "$status", "severity": "$severity", "detail": "$detail"}
p.write_text(json.dumps(r, indent=2))
PYEOF
}

banner "KMS Runtime Network Security Analyser — $SERVER_URL"
info "Host     : $HOST"
info "Port     : $PORT"
info "Scheme   : $SCHEME"
info "Output   : $OUTPUT_DIR"
info "Insecure : $INSECURE"
echo

# ════════════════════════════════════════════════════════════════════════════════
banner "1/7 — Reachability & Basic Connectivity"
# ════════════════════════════════════════════════════════════════════════════════

REACH_OUT="$OUTPUT_DIR/reachability.txt"
info "Testing basic connectivity to $HOST:$PORT …"
if timeout 10 bash -c "echo > /dev/tcp/$HOST/$PORT" 2>/dev/null; then
  ok "Port $PORT is open"
  record_check "port_open" "PASS" "Port $PORT is reachable" "INFO"
else
  fail "Port $PORT is not reachable — cannot continue"
  record_check "port_open" "FAIL" "Port $PORT is not reachable" "CRITICAL"
  echo "Cannot reach $HOST:$PORT — aborting." > "$REACH_OUT"
  exit 1
fi

# HTTP smoke test
info "HTTP smoke test …"
HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' \
  "${CURL_BASE_ARGS[@]}" \
  -X POST -H "Content-Type: application/json" \
  -d '{}' "${SERVER_URL}/kmip/2_1" 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" == "422" || "$HTTP_CODE" == "400" ]]; then
  ok "KMIP endpoint responsive (HTTP $HTTP_CODE — expected for empty request)"
  record_check "kmip_responsive" "PASS" "KMIP endpoint returns $HTTP_CODE for empty request" "INFO"
elif [[ "$HTTP_CODE" == "401" || "$HTTP_CODE" == "403" ]]; then
  ok "KMIP endpoint requires auth (HTTP $HTTP_CODE — authentication enforced ✓)"
  record_check "kmip_responsive" "PASS" "KMIP endpoint enforces authentication: $HTTP_CODE" "INFO"
else
  warn "KMIP endpoint returned unexpected HTTP $HTTP_CODE"
  record_check "kmip_responsive" "WARN" "Unexpected HTTP $HTTP_CODE for KMIP probe" "MEDIUM"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "2/7 — TLS Protocol Version & Cipher Suite Analysis"
# ════════════════════════════════════════════════════════════════════════════════

TLS_OUT="$OUTPUT_DIR/tls_analysis.txt"
CERT_OUT="$OUTPUT_DIR/certificate.pem"
info "Connecting with openssl s_client to inspect TLS …"

{
  # Get server certificate + negotiated cipher
  echo Q | openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    "${OPENSSL_CA_ARGS[@]}" \
    -showcerts 2>&1
} > "$TLS_OUT" || true

# Extract negotiated protocol + cipher
PROTO=$(grep -oP '(?<=Protocol  : ).*' "$TLS_OUT" 2>/dev/null | head -1 || echo "unknown")
CIPHER=$(grep -oP '(?<=Cipher    : ).*' "$TLS_OUT" 2>/dev/null | head -1 || echo "unknown")
CERT_VALIDITY=$(grep "notAfter" "$TLS_OUT" 2>/dev/null | head -1 || echo "unknown")

info "Negotiated : $PROTO / $CIPHER"
[[ -n "$CERT_VALIDITY" ]] && info "Cert expiry: $CERT_VALIDITY"

# Save just the certificate
openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" \
  "${OPENSSL_CA_ARGS[@]}" </dev/null 2>/dev/null \
  | openssl x509 -noout -text > "${OUTPUT_DIR}/cert_details.txt" 2>/dev/null || true

# Check deprecated TLS versions
for bad_proto in ssl2 ssl3 tls1 tls1_1; do
  human="${bad_proto/ssl/SSLv}"
  human="${human/tls1_1/TLSv1.1}"
  human="${human/tls1/TLSv1.0}"
  set +e
  echo Q | openssl s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" \
    -"${bad_proto}" 2>&1 | grep -q "handshake failure\|ssl handshake failure\|unknown option\|no protocols available\|Connection refused"
  HF=$?
  set -e
  if [[ "$HF" -eq 0 ]]; then
    ok "$human correctly rejected"
    record_check "tls_${bad_proto}_rejected" "PASS" "$human rejected by server" "INFO"
  else
    fail "$human NOT rejected — weak protocol accepted!"
    record_check "tls_${bad_proto}_rejected" "FAIL" "$human accepted — must be disabled" "CRITICAL"
  fi
done

# Check TLS 1.2
set +e
echo Q | openssl s_client -connect "${HOST}:${PORT}" \
  -servername "$HOST" -tls1_2 "${OPENSSL_CA_ARGS[@]}" 2>&1 | grep -q "Cipher    :"
TLS12_OK=$?
set -e
if [[ "$TLS12_OK" -eq 0 ]]; then
  ok "TLS 1.2 supported"
  record_check "tls12_supported" "PASS" "TLS 1.2 connection established" "INFO"
else
  warn "TLS 1.2 not supported (TLS 1.3 only — acceptable if intentional)"
  record_check "tls12_supported" "WARN" "TLS 1.2 not available" "LOW"
fi

# Check TLS 1.3
set +e
echo Q | openssl s_client -connect "${HOST}:${PORT}" \
  -servername "$HOST" -tls1_3 "${OPENSSL_CA_ARGS[@]}" 2>&1 | grep -q "Cipher    :"
TLS13_OK=$?
set -e
if [[ "$TLS13_OK" -eq 0 ]]; then
  ok "TLS 1.3 supported"
  record_check "tls13_supported" "PASS" "TLS 1.3 connection established" "INFO"
else
  warn "TLS 1.3 not supported"
  record_check "tls13_supported" "WARN" "TLS 1.3 not available" "MEDIUM"
fi

# Weak cipher probe
WEAK_CIPHERS="NULL:aNULL:eNULL:EXPORT:DES:RC4:MD5:PSK:SRP:CAMELLIA:IDEA:SEED"
set +e
echo Q | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" \
  -cipher "$WEAK_CIPHERS" 2>&1 | grep -q "Cipher    :"
WEAK_OK=$?
set -e
if [[ "$WEAK_OK" -eq 0 ]]; then
  fail "Weak cipher suite accepted! Server negotiated: $(grep 'Cipher    :' "$TLS_OUT" | head -1 || echo 'unknown')"
  record_check "weak_ciphers_rejected" "FAIL" "Server accepted weak cipher" "CRITICAL"
else
  ok "Weak cipher suites (NULL/RC4/DES/EXPORT) correctly rejected"
  record_check "weak_ciphers_rejected" "PASS" "No weak ciphers accepted" "INFO"
fi

# Forward Secrecy probe
set +e
echo Q | openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" \
  -cipher "ECDHE:DHE" "${OPENSSL_CA_ARGS[@]}" 2>&1 | grep -q "Cipher    :"
PFS_OK=$?
set -e
if [[ "$PFS_OK" -eq 0 ]]; then
  ok "Forward secrecy (ECDHE/DHE) supported"
  record_check "forward_secrecy" "PASS" "Perfect Forward Secrecy via ECDHE/DHE" "INFO"
else
  warn "No forward secrecy cipher negotiated"
  record_check "forward_secrecy" "WARN" "No PFS cipher available" "HIGH"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "3/7 — Certificate Chain & Validity"
# ════════════════════════════════════════════════════════════════════════════════

info "Inspecting certificate chain …"

# Extract cert to file
openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" \
  "${OPENSSL_CA_ARGS[@]}" </dev/null 2>/dev/null \
  | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
  > "$CERT_OUT" 2>/dev/null || true

if [[ -s "$CERT_OUT" ]]; then
  CERT_SUBJECT=$(openssl x509 -in "$CERT_OUT" -noout -subject 2>/dev/null | sed 's/subject=//' || echo "unknown")
  CERT_ISSUER=$(openssl x509 -in "$CERT_OUT" -noout -issuer 2>/dev/null | sed 's/issuer=//' || echo "unknown")
  CERT_EXPIRY=$(openssl x509 -in "$CERT_OUT" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || echo "unknown")
  CERT_SAN=$(openssl x509 -in "$CERT_OUT" -noout -ext subjectAltName 2>/dev/null | grep -v "X509v3" || echo "")
  CERT_ALGO=$(openssl x509 -in "$CERT_OUT" -noout -text 2>/dev/null | grep "Public Key Algorithm" | head -1 || echo "unknown")
  CERT_KEYSIZE=$(openssl x509 -in "$CERT_OUT" -noout -text 2>/dev/null | grep "RSA Public-Key\|Public-Key:" | head -1 || echo "unknown")
  info "Subject    : $CERT_SUBJECT"
  info "Issuer     : $CERT_ISSUER"
  info "Expiry     : $CERT_EXPIRY"
  info "Algorithm  : $CERT_ALGO"
  info "Key size   : $CERT_KEYSIZE"
  [[ -n "$CERT_SAN" ]] && info "SANs       : $CERT_SAN"

  # Check expiry
  set +e
  openssl x509 -in "$CERT_OUT" -noout -checkend 2592000 2>/dev/null  # 30-day warning
  EXPIRY_SOON=$?
  openssl x509 -in "$CERT_OUT" -noout -checkend 0 2>/dev/null         # expired?
  EXPIRED=$?
  set -e
  if [[ "$EXPIRED" -ne 0 ]]; then
    fail "Certificate is EXPIRED"
    record_check "cert_valid" "FAIL" "Certificate is expired" "CRITICAL"
  elif [[ "$EXPIRY_SOON" -ne 0 ]]; then
    warn "Certificate expires within 30 days"
    record_check "cert_valid" "WARN" "Certificate expires in < 30 days: $CERT_EXPIRY" "HIGH"
  else
    ok "Certificate is valid (expires: $CERT_EXPIRY)"
    record_check "cert_valid" "PASS" "Certificate valid until $CERT_EXPIRY" "INFO"
  fi

  # RSA key size check
  if echo "$CERT_KEYSIZE" | grep -qE "1024|512"; then
    fail "Certificate uses weak key size: $CERT_KEYSIZE"
    record_check "cert_key_size" "FAIL" "Weak TLS certificate key size: $CERT_KEYSIZE" "CRITICAL"
  else
    ok "Certificate key size is adequate"
    record_check "cert_key_size" "PASS" "Certificate key size: $CERT_KEYSIZE" "INFO"
  fi

  # SHA-1 signature check
  CERT_SIG=$(openssl x509 -in "$CERT_OUT" -noout -text 2>/dev/null | grep "Signature Algorithm" | head -1 || echo "")
  if echo "$CERT_SIG" | grep -qi "sha1\|sha-1"; then
    fail "Certificate signed with SHA-1: $CERT_SIG"
    record_check "cert_sha1" "FAIL" "SHA-1 certificate signature: $CERT_SIG" "HIGH"
  else
    ok "Certificate signature algorithm is SHA-2+"
    record_check "cert_sha1" "PASS" "Certificate signature: $CERT_SIG" "INFO"
  fi
else
  warn "Could not retrieve certificate — skipping chain checks"
  record_check "cert_valid" "WARN" "Could not retrieve certificate" "MEDIUM"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "4/7 — HTTP Security Headers"
# ════════════════════════════════════════════════════════════════════════════════

HEADERS_OUT="$OUTPUT_DIR/http_headers.txt"
info "Fetching HTTP security headers …"

curl -s -I "${CURL_BASE_ARGS[@]}" \
  -H "Content-Type: application/json" \
  "${SERVER_URL}/ui/" 2>/dev/null > "$HEADERS_OUT" || \
curl -s -I "${CURL_BASE_ARGS[@]}" \
  "${SERVER_URL}/" 2>/dev/null > "$HEADERS_OUT" || true

check_header() {
  local header="$1" severity="$2" note="$3"
  if grep -qi "^${header}:" "$HEADERS_OUT" 2>/dev/null; then
    local val
    val=$(grep -i "^${header}:" "$HEADERS_OUT" | head -1 | sed 's/^[^:]*: //')
    ok "$header: $val"
    record_check "header_${header,,}" "PASS" "$header: $val" "INFO"
  else
    if [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
      warn "$header header missing ($note)"
    else
      info "$header header not present ($note)"
    fi
    record_check "header_${header,,}" "WARN" "$header missing — $note" "$severity"
    if [[ "$severity" == "HIGH" ]]; then OVERALL_EXIT=1; fi
  fi
}

check_header "Strict-Transport-Security" "HIGH" "required for HTTPS enforcement"
check_header "X-Content-Type-Options"    "MEDIUM" "enables MIME-sniffing protection"
check_header "X-Frame-Options"           "MEDIUM" "clickjacking protection"
check_header "Content-Security-Policy"  "MEDIUM" "XSS mitigation"
check_header "Cache-Control"             "LOW" "prevents caching secrets"

# Check for server information disclosure
SERVER_HEADER=$(grep -i "^Server:" "$HEADERS_OUT" 2>/dev/null | head -1 || echo "")
if echo "$SERVER_HEADER" | grep -qiE "apache|nginx|iis|version|[0-9]+\.[0-9]+"; then
  warn "Server header discloses software version: $SERVER_HEADER"
  record_check "server_disclosure" "WARN" "Version disclosed: $SERVER_HEADER" "LOW"
else
  ok "No sensitive version in Server header"
  record_check "server_disclosure" "PASS" "Server header: $SERVER_HEADER" "INFO"
fi

# CORS check
CORS_HEADER=$(curl -s -I "${CURL_BASE_ARGS[@]}" \
  -H "Origin: https://attacker.example.com" \
  "${SERVER_URL}/kmip/2_1" 2>/dev/null | grep -i "access-control-allow-origin" | head -1 || echo "")
if echo "$CORS_HEADER" | grep -q "\*"; then
  fail "CORS wildcard detected on KMIP endpoint: $CORS_HEADER"
  record_check "cors_wildcard" "FAIL" "CORS allows * on KMIP endpoint" "CRITICAL"
elif [[ -n "$CORS_HEADER" ]]; then
  ok "CORS policy present: $CORS_HEADER"
  record_check "cors_wildcard" "PASS" "CORS: $CORS_HEADER" "INFO"
else
  ok "No CORS header on KMIP endpoint (same-origin only — correct)"
  record_check "cors_wildcard" "PASS" "No CORS on KMIP endpoint" "INFO"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "5/7 — mTLS Authentication Analysis"
# ════════════════════════════════════════════════════════════════════════════════

MTLS_OUT="$OUTPUT_DIR/mtls_analysis.txt"
{
  echo Q | openssl s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" "${OPENSSL_CA_ARGS[@]}" 2>&1 | grep -E "Verify|Request|Required|Accept" || true
} > "$MTLS_OUT"

# Check if server requests client cert
if grep -qi "Request CERT\|SSL client certificate requested\|Acceptable client certificate" "$MTLS_OUT" 2>/dev/null; then
  ok "Server requests client certificate (mTLS enforced)"
  record_check "mtls_requested" "PASS" "Server requires client certificate" "INFO"
else
  info "Server does not request client certificate (certificate auth optional or disabled)"
  record_check "mtls_requested" "INFO" "mTLS not enforced (may use JWT/API-key auth instead)" "INFO"
fi

# Test with client cert if provided
if [[ -n "$CLIENT_CERT" && -n "$CLIENT_KEY" ]]; then
  info "Testing mTLS with provided client certificate …"
  MTLS_CODE=$(curl -s -o /dev/null -w '%{http_code}' "${CURL_BASE_ARGS[@]}" \
    --cert "$CLIENT_CERT" --key "$CLIENT_KEY" \
    -X POST -H "Content-Type: application/json" -d '{}' \
    "${SERVER_URL}/kmip/2_1" 2>/dev/null || echo "000")
  if [[ "$MTLS_CODE" == "422" || "$MTLS_CODE" == "400" ]]; then
    ok "mTLS authentication accepted (HTTP $MTLS_CODE for empty KMIP request)"
    record_check "mtls_auth_works" "PASS" "Client cert authentication accepted" "INFO"
  elif [[ "$MTLS_CODE" == "200" || "$MTLS_CODE" == "201" ]]; then
    ok "mTLS authentication accepted"
    record_check "mtls_auth_works" "PASS" "mTLS auth OK" "INFO"
  else
    warn "mTLS authentication returned HTTP $MTLS_CODE"
    record_check "mtls_auth_works" "WARN" "mTLS returned HTTP $MTLS_CODE" "MEDIUM"
  fi
else
  info "No client certificate provided — skipping mTLS auth test"
  info "  Use --cert and --key to test mTLS authentication"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "6/7 — KMIP Protocol Security Probes"
# ════════════════════════════════════════════════════════════════════════════════

KMIP_OUT="$OUTPUT_DIR/kmip_probes.json"
info "Running KMIP protocol security probes …"

python3 - <<PYEOF
import json, sys, urllib.request, ssl, time
from pathlib import Path

url = "$SERVER_URL"
insecure = $([[ "$INSECURE" == true ]] && echo "True" || echo "False")
out_file = "$KMIP_OUT"

ctx = ssl.create_default_context()
if insecure:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

results = {}

def post(path, body):
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            return r.getcode(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]
    except Exception as e:
        return 0, str(e)

# Probe 1: Empty payload
code, body = post("/kmip/2_1", {})
results["empty_payload"] = {
    "status": "PASS" if code in (400, 422) else "WARN",
    "http_code": code,
    "note": f"Empty KMIP request returned HTTP {code}"
}
print(f"  Empty payload: HTTP {code}")

# Probe 2: OversizedBatchCount (DoS prevention)
oversized = {"tag": "RequestMessage", "type": "Structure", "value": [
    {"tag": "RequestHeader", "type": "Structure", "value": [
        {"tag": "ProtocolVersion", "type": "Structure", "value": [
            {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
            {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}
        ]},
        {"tag": "BatchCount", "type": "Integer", "value": 99999}
    ]}
]}
code, body = post("/kmip/2_1", oversized)
results["oversized_batch"] = {
    "status": "PASS" if code in (400, 422, 413) else "WARN",
    "http_code": code,
    "note": f"OversizedBatchCount returned HTTP {code}"
}
print(f"  OversizedBatch: HTTP {code} ({'PASS' if code in (400,422,413) else 'WARN'})")

# Probe 3: SQL injection in UID
sql_inject = {
    "tag": "RequestMessage", "type": "Structure", "value": [
        {"tag": "RequestHeader", "type": "Structure", "value": [
            {"tag": "ProtocolVersion", "type": "Structure", "value": [
                {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
                {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}
            ]},
            {"tag": "BatchCount", "type": "Integer", "value": 1}
        ]},
        {"tag": "BatchItem", "type": "Structure", "value": [
            {"tag": "Operation", "type": "Enumeration", "value": "Get"},
            {"tag": "RequestPayload", "type": "Structure", "value": [
                {"tag": "UniqueIdentifier", "type": "TextString",
                 "value": "' OR '1'='1'; DROP TABLE objects;--"}
            ]}
        ]}
    ]
}
code, body = post("/kmip/2_1", sql_inject)
# Server should return 4xx (not 500 or 200)
status = "PASS" if code in (400, 422, 401, 403, 404) else ("WARN" if code == 0 else "FAIL")
results["sql_injection_uid"] = {
    "status": status,
    "http_code": code,
    "note": f"SQL injection in UID returned HTTP {code}"
}
print(f"  SQL injection:  HTTP {code} ({status})")

# Probe 4: Very large payload (DoS/OOM guard)
large_val = "A" * (70 * 1024 * 1024)  # 70 MB — above 64 MB limit
req_large = urllib.request.Request(
    url.rstrip("/") + "/kmip/2_1",
    data=large_val.encode(),
    headers={"Content-Type": "application/octet-stream"},
    method="POST"
)
try:
    with urllib.request.urlopen(req_large, context=ctx, timeout=15) as r:
        code = r.getcode()
except urllib.error.HTTPError as e:
    code = e.code
except Exception:
    code = 0
status = "PASS" if code in (400, 413, 422) else ("PASS" if code == 0 else "WARN")
results["large_payload"] = {
    "status": status,
    "http_code": code,
    "note": f"70 MiB payload returned HTTP {code} (limit should be 64 MiB)"
}
print(f"  Large payload:  HTTP {code} ({status})")

# Probe 5: Rate limiting (10 rapid requests)
codes = []
start = time.time()
for _ in range(10):
    c, _ = post("/kmip/2_1", {})
    codes.append(c)
elapsed = time.time() - start
rl_triggered = 429 in codes
results["rate_limiting"] = {
    "status": "PASS" if rl_triggered else "INFO",
    "note": f"10 rapid requests in {elapsed:.1f}s — 429 seen: {rl_triggered}"
}
print(f"  Rate-limit:     429 triggered: {rl_triggered} ({elapsed:.1f}s for 10 requests)")

# Save
Path(out_file).write_text(json.dumps(results, indent=2))
print(f"\nKMIP probes written to: {out_file}")
PYEOF

# Update results JSON with KMIP probe results
python3 - <<PYEOF
import json
from pathlib import Path

res_path = Path("$RESULTS_JSON")
kmip_path = Path("$KMIP_OUT")
if kmip_path.exists():
    main = json.loads(res_path.read_text())
    kmip = json.loads(kmip_path.read_text())
    for k, v in kmip.items():
        main["checks"][f"kmip_{k}"] = {
            "status": v.get("status", "INFO"),
            "severity": "CRITICAL" if v.get("status") == "FAIL" else "INFO",
            "detail": v.get("note", "")
        }
    res_path.write_text(json.dumps(main, indent=2))
PYEOF


# ════════════════════════════════════════════════════════════════════════════════
banner "7/7 — Optional Tools (nmap / sslyze / nuclei)"
# ════════════════════════════════════════════════════════════════════════════════

NMAP_OUT="$OUTPUT_DIR/nmap.txt"
if command -v nmap &>/dev/null; then
  info "Running nmap TLS NSE scripts …"
  nmap --script ssl-cert,ssl-enum-ciphers,ssl-dh-params,ssl-known-key \
    -p "$PORT" "$HOST" -oN "$NMAP_OUT" 2>/dev/null || true
  ok "nmap output → $NMAP_OUT"
  # Flag TLS 1.0/1.1 from nmap output
  if grep -qi "TLSv1\.0\|TLSv1\.1" "$NMAP_OUT" 2>/dev/null; then
    fail "nmap detected TLS 1.0 or TLS 1.1 support"
    record_check "nmap_weak_tls" "FAIL" "nmap found TLS 1.0/1.1 support" "HIGH"
  fi
else
  info "nmap not found — skipping. Install: apt-get install nmap"
  echo "(nmap not available)" > "$NMAP_OUT"
fi

SSLYZE_OUT="$OUTPUT_DIR/sslyze.json"
if python3 -c "import sslyze" 2>/dev/null; then
  info "Running sslyze deep TLS analysis …"
  python3 -m sslyze --json_out "$SSLYZE_OUT" \
    --certinfo --compression --heartbleed --fallback \
    --sslv2 --sslv3 --tlsv1 --tlsv1_1 --tlsv1_2 --tlsv1_3 \
    "${HOST}:${PORT}" 2>/dev/null || true
  ok "sslyze output → $SSLYZE_OUT"
else
  info "sslyze not found — skipping. Install: pip3 install sslyze"
  echo '{"note":"sslyze not available"}' > "$SSLYZE_OUT"
fi

NUCLEI_OUT="$OUTPUT_DIR/nuclei.txt"
if command -v nuclei &>/dev/null; then
  info "Running nuclei template scan …"
  nuclei -u "$SERVER_URL" \
    -t ssl,http/misconfiguration,http/exposures \
    -o "$NUCLEI_OUT" \
    -silent 2>/dev/null || true
  ok "nuclei output → $NUCLEI_OUT"
else
  info "nuclei not found — skipping. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  echo "(nuclei not available)" > "$NUCLEI_OUT"
fi


# ════════════════════════════════════════════════════════════════════════════════
banner "Analysis Summary"
# ════════════════════════════════════════════════════════════════════════════════

python3 - <<PYEOF
import json
from pathlib import Path

EMOJI = {"PASS": "✅", "WARN": "⚠️ ", "FAIL": "🔴", "INFO": "ℹ️ ", "CRITICAL": "🔴"}
r = json.loads(Path("$RESULTS_JSON").read_text())
checks = r.get("checks", {})

total = len(checks)
passed = sum(1 for c in checks.values() if c["status"] == "PASS")
warned = sum(1 for c in checks.values() if c["status"] == "WARN")
failed = sum(1 for c in checks.values() if c["status"] == "FAIL")

print(f"\n  Total checks : {total}")
print(f"  ✅ PASS      : {passed}")
print(f"  ⚠️  WARN      : {warned}")
print(f"  🔴 FAIL      : {failed}")

if failed:
    print("\n  Critical findings:")
    for name, c in checks.items():
        if c["status"] == "FAIL":
            print(f"    🔴 {name}: {c['detail']}")
elif warned:
    print("\n  Warnings:")
    for name, c in checks.items():
        if c["status"] == "WARN":
            print(f"    ⚠️  {name}: {c['detail']}")
else:
    print("\n  ✅ All checks passed!")

print(f"\n  Full results : $RESULTS_JSON")
PYEOF

info "Output directory: $OUTPUT_DIR"
info "Files:"
find "$OUTPUT_DIR" -maxdepth 1 -type f -printf '%f\n' | sort | sed 's/^/    /'

# Write Markdown report if requested
if [[ -n "$REPORT_PATH" ]]; then
  python3 - <<PYEOF
import json
from pathlib import Path
r = json.loads(Path("$RESULTS_JSON").read_text())
checks = r.get("checks", {})
icons = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "INFO": "ℹ️"}
lines = [
    "# KMS Runtime Security Report\n",
    f"**Server**: {r.get('server_url', 'unknown')}  ",
    f"**Date**: {r.get('scan_date', 'unknown')}  ",
    f"**Insecure mode**: {r.get('insecure', False)}  \n",
    "## Check Results\n",
    "| Check | Status | Severity | Detail |",
    "|---|---|---|---|",
]
for name, c in checks.items():
    icon = icons.get(c.get("status", ""), "")
    detail = (c.get("detail", "") or "")[:100]
    lines.append(f"| {name} | {icon} {c.get('status','')} | {c.get('severity','')} | {detail} |")
Path("$REPORT_PATH").parent.mkdir(parents=True, exist_ok=True)
Path("$REPORT_PATH").write_text("\n".join(lines) + "\n")
print(f"Report written to: $REPORT_PATH")
PYEOF
fi

echo
if [[ "$OVERALL_EXIT" -eq 0 ]]; then
  ok "Runtime security analysis PASSED"
else
  fail "Runtime security analysis found issues"
fi
exit $OVERALL_EXIT

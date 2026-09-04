#!/usr/bin/env bash
# Entrypoint for SAP ASE Docker container.
# Starts ASE, waits until ready, then optionally runs a SQL init script.
set -euo pipefail

ASE_HOME=/opt/sap
ASE_NAME=SAPASE
ASE_LOG="${ASE_HOME}/ASE-16_1/install/${ASE_NAME}.log"
SA_PASSWORD=${SA_PASSWORD:-SapAse1!}

# Inject any cert volumes into the search path
export SYBSSL="${ASE_HOME}/ASE-16_1/ssl"
mkdir -p "${SYBSSL}"

# Copy KMIP certs if mounted
if [[ -f /ase-kmip-certs/ca.crt ]]; then
  cp /ase-kmip-certs/ca.crt "${SYBSSL}/kms_ca.crt"
fi
if [[ -f /ase-kmip-certs/client.p12 ]]; then
  cp /ase-kmip-certs/client.p12 "${SYBSSL}/client.p12"
fi

# Source ASE env (script references unset vars, incompatible with -u)
set +u
# shellcheck source=/dev/null
. "${ASE_HOME}/SYBASE.sh"
set -u

echo "==> Starting SAP ASE (${ASE_NAME})…"
"${ASE_HOME}/ASE-16_1/bin/startserver" \
  -f "${ASE_HOME}/ASE-16_1/install/RUN_${ASE_NAME}" &

echo "==> Waiting for ASE to accept connections…"
MAX_WAIT=120
elapsed=0
until printf 'select 1\ngo\n' | isql -S "${ASE_NAME}" -U sa -P "${SA_PASSWORD}" -w 200 >/dev/null 2>&1; do
  sleep 2
  elapsed=$((elapsed + 2))
  if [[ ${elapsed} -ge ${MAX_WAIT} ]]; then
    echo "ERROR: ASE did not start within ${MAX_WAIT}s" >&2
    tail -50 "${ASE_LOG}" >&2
    exit 1
  fi
done
echo "==> ASE ready."

# Run optional SQL init script passed as first argument
if [[ $# -gt 0 && -f "$1" ]]; then
  echo "==> Running init SQL: $1"
  isql -S "${ASE_NAME}" -U sa -P "${SA_PASSWORD}" -w 200 -i "$1" -o /tmp/ase_init_out.txt
  cat /tmp/ase_init_out.txt
fi

# Keep container alive; tail log for docker logs
exec tail -f "${ASE_LOG}"

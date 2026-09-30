#!/usr/bin/env bash
set -euo pipefail
# Grant the SPIRE AppRole identities the `certify` access right on the PKI CA
# private key.
#
# `POST /v1/pki/root/sign-intermediate` requires the caller's KMS identity
# (`spire:<AppRole name>`) to hold `certify` on the key tagged with
# `vault_pki_ca_key_label`; a valid Vault token alone is not enough.
#
# Required environment:
#   CKMS_BIN   — path to the ckms binary
#   CKMS_CONF  — ckms configuration (authenticated as the CA key owner)
# Optional:
#   PKI_CA_TAG      — CA key tag (default: vault_pki_ca)
#   SPIRE_ENTITIES  — space-separated AppRole names (default: spire-server-a spire-server-b)

: "${CKMS_BIN:?CKMS_BIN must be set}"
: "${CKMS_CONF:?CKMS_CONF must be set}"
PKI_CA_TAG="${PKI_CA_TAG:-vault_pki_ca}"
SPIRE_ENTITIES="${SPIRE_ENTITIES:-spire-server-a spire-server-b}"

ckms() { "${CKMS_BIN}" --conf-path "${CKMS_CONF}" --accept-invalid-certs "$@"; }

# `certify --generate-key-pair` stores the private key as <uuid> and the public
# key as <uuid>_pk; the certificate carries an explicit id. Keep the bare UUID.
ca_sk_uid=$(ckms locate --tag "${PKI_CA_TAG}" |
  grep -oE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' | head -n 1 || true)
if [[ -z "${ca_sk_uid}" ]]; then
  echo "ERROR: no PKI CA private key tagged '${PKI_CA_TAG}' found" >&2
  exit 1
fi

for entity in ${SPIRE_ENTITIES}; do
  ckms access-rights grant "spire:${entity}" certify --object-uid "${ca_sk_uid}"
  echo "Granted certify on ${ca_sk_uid} to spire:${entity}"
done

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

# Locate the CA *private* key by type: the key pair's public key also carries the
# tag, and its UID is not guaranteed to follow a recognisable pattern.
mapfile -t ca_sk_uids < <(ckms locate --tag "${PKI_CA_TAG}" --object-type PrivateKey |
  grep -vE '^(List of unique identifiers:|No object found\.)?$')
if [[ "${#ca_sk_uids[@]}" -ne 1 ]]; then
  echo "ERROR: expected exactly one PKI CA private key tagged '${PKI_CA_TAG}'," \
    "found ${#ca_sk_uids[@]}: ${ca_sk_uids[*]:-none}" >&2
  exit 1
fi
ca_sk_uid="${ca_sk_uids[0]}"

for entity in ${SPIRE_ENTITIES}; do
  ckms access-rights grant "spire:${entity}" certify --object-uid "${ca_sk_uid}"
  echo "Granted certify on ${ca_sk_uid} to spire:${entity}"
done

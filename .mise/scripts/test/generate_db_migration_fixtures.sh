#!/usr/bin/env bash
# Generate SQLite migration fixtures with each release's server and ckms.
set -euo pipefail

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
REPO_ROOT="$(get_repo_root "${MISE_CONFIG_ROOT}")"
require_cmd docker
require_cmd python3
require_cmd curl
docker_ready || print_error "Docker must be running to generate migration fixtures."
[ "$#" -le 1 ] || print_error "Usage: $0 [VERSION]"
SELECTED_VERSION="${1:-}"

# Resolve pins with: docker pull ghcr.io/cosmian/kms:<version>
# The Digest line identifies the immutable release manifest.
readonly IMAGES=(
  "ghcr.io/cosmian/kms:5.20.0@sha256:a74dc266e85a75e038ab75243afe64c2d5f65a0219a5561eb99d2b7febc47e80"
  "ghcr.io/cosmian/kms:5.24.0@sha256:a8c2b6577ce366c534fb29e388b8b7b473fc8a4445fa2ab6f32c8da13004e50a"
  "ghcr.io/cosmian/kms:5.28.0@sha256:7b60fd4484930969906caa5722b727054ff96d49339ce81e3c64ca9e4278540e"
  "ghcr.io/cosmian/kms:5.29.0@sha256:a5592576c17854868c8abe6536b0ab89c49f31eb978c2778d2ee471330e083c8"
)
WORK_DIR="$(mktemp -d -t kms-db-migration-fixtures-XXXXXX)"
CONTAINER_ID=""

cleanup() {
  local status="$?"
  if [ -n "${CONTAINER_ID}" ]; then
    if ! docker rm --force "${CONTAINER_ID}" >/dev/null; then
      print_warning "Could not remove fixture container ${CONTAINER_ID}."
      status=1
    fi
  fi
  if ! rm -rf -- "${WORK_DIR:?}"; then
    print_warning "Could not remove fixture scratch directory ${WORK_DIR}."
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

fixture_ckms() {
  docker exec "${CONTAINER_ID}" /usr/local/bin/ckms --url http://127.0.0.1:9998 "$@"
}

populate_bulk_kmip() {
  python3 - "$1" <<'PY'
import json
import sys
import urllib.request

url = f"http://127.0.0.1:{sys.argv[1]}/kmip/2_1"


def kmip(payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def tag_attr(tags: list[str]) -> dict:
    return {
        "tag": "Attribute",
        "value": [
            {"tag": "VendorIdentification", "type": "TextString", "value": "cosmian"},
            {"tag": "AttributeName", "type": "TextString", "value": "tag"},
            {"tag": "AttributeValue", "type": "TextString", "value": json.dumps(tags)},
        ],
    }


active_date = {"tag": "ActivationDate", "type": "DateTime", "value": "2024-01-01T00:00:00Z"}

for uid, bits, tags in [
    ("bulk_aes_128", 128, ["bulk"]),
    ("bulk_aes_192", 192, ["bulk"]),
    ("bulk_aes_256", 256, ["bulk", "env:prod/eu", "émoji-🔐"]),
]:
    kmip({
        "tag": "Create",
        "value": [
            {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
            {"tag": "Attributes", "value": [
                {"tag": "UniqueIdentifier", "type": "TextString", "value": uid},
                {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
                {"tag": "CryptographicLength", "type": "Integer", "value": bits},
                {"tag": "CryptographicUsageMask", "type": "Integer", "value": 2108},
                active_date,
                tag_attr(tags),
            ]},
        ],
    })

for uid, curve in [("bulk_ec_p256", "P256"), ("bulk_ec_p384", "P384")]:
    kmip({
        "tag": "CreateKeyPair",
        "value": [
            {"tag": "CommonAttributes", "value": [
                 {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "ECDSA"},
                 {"tag": "CryptographicDomainParameters", "value": [
                     {"tag": "RecommendedCurve", "type": "Enumeration", "value": curve}
                 ]},
                 {"tag": "CryptographicUsageMask", "type": "Integer", "value": 12},
                 active_date,
                 tag_attr(["bulk"]),
            ]},
            {"tag": "PrivateKeyAttributes", "value": [
                 {"tag": "UniqueIdentifier", "type": "TextString", "value": uid},
                 active_date,
            ]},
            {"tag": "PublicKeyAttributes", "value": [
                 active_date,
            ]},
        ],
    })

kmip({
    "tag": "Import",
    "value": [
        {"tag": "UniqueIdentifier", "type": "TextString", "value": "bulk_secret_data"},
        {"tag": "ObjectType", "type": "Enumeration", "value": "SecretData"},
        {"tag": "ReplaceExisting", "type": "Boolean", "value": False},
        {"tag": "Attributes", "value": [
            {"tag": "ObjectType", "type": "Enumeration", "value": "SecretData"},
            {"tag": "CryptographicUsageMask", "type": "Integer", "value": 2},
            active_date,
            tag_attr(["bulk"]),
        ]},
        {"tag": "SecretData", "value": [
            {"tag": "SecretDataType", "type": "Enumeration", "value": "Password"},
            {"tag": "KeyBlock", "value": [
                {"tag": "KeyFormatType", "type": "Enumeration", "value": "Opaque"},
                {"tag": "KeyValue", "value": [
                    {"tag": "KeyMaterial", "type": "ByteString", "value": "DEADBEEFCAFE0123456789ABCDEF"}
                ]},
            ]},
        ]},
    ],
})

kmip({
    "tag": "Import",
    "value": [
        {"tag": "UniqueIdentifier", "type": "TextString", "value": "bulk_opaque"},
        {"tag": "ObjectType", "type": "Enumeration", "value": "OpaqueObject"},
        {"tag": "ReplaceExisting", "type": "Boolean", "value": False},
        {"tag": "Attributes", "value": [
            {"tag": "ObjectType", "type": "Enumeration", "value": "OpaqueObject"},
            active_date,
            tag_attr(["bulk"]),
        ]},
        {"tag": "OpaqueObject", "value": [
            {"tag": "OpaqueDataType", "type": "Enumeration", "value": "Unknown"},
            {"tag": "OpaqueDataValue", "type": "ByteString", "value": "48656C6C6F204F7061717565"},
        ]},
    ],
})

kmip({
    "tag": "Create",
    "value": [
        {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
        {"tag": "Attributes", "value": [
            {"tag": "UniqueIdentifier", "type": "TextString", "value": "bulk_preactive"},
            {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
            {"tag": "CryptographicLength", "type": "Integer", "value": 256},
            {"tag": "CryptographicUsageMask", "type": "Integer", "value": 12},
            {"tag": "ActivationDate", "type": "DateTime", "value": "2099-01-01T00:00:00Z"},
            tag_attr(["bulk"]),
        ]},
    ],
})

for uid, reason in [("bulk_compromised", "KeyCompromise"), ("bulk_destroyed", "Superseded")]:
    kmip({
        "tag": "Create",
        "value": [
            {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
            {"tag": "Attributes", "value": [
                {"tag": "UniqueIdentifier", "type": "TextString", "value": uid},
                {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
                {"tag": "CryptographicLength", "type": "Integer", "value": 256},
                {"tag": "CryptographicUsageMask", "type": "Integer", "value": 12},
                tag_attr(["bulk"]),
            ]},
        ],
    })
    kmip({
        "tag": "Revoke",
        "value": [
            {"tag": "UniqueIdentifier", "type": "TextString", "value": uid},
            {"tag": "RevocationReason", "value": [
                {"tag": "RevocationReasonCode", "type": "Enumeration", "value": reason}
            ]},
        ],
    })

kmip({
    "tag": "Destroy",
    "value": [
        {"tag": "UniqueIdentifier", "type": "TextString", "value": "bulk_destroyed"},
    ],
})
PY
}

populate_fixture() {
  local port="$1"
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_kek
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig --wrapping-key-id mig_kek mig_wrapped
  fixture_ckms rsa keys create --size_in_bits 2048 --tag mig mig_rsa
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_revoked
  fixture_ckms sym keys revoke --key-id mig_revoked "Migration fixture revocation"
  fixture_ckms certificates certify --generate-key-pair --algorithm rsa2048 \
    --certificate-id mig_cert --subject-name "CN=Migration fixture" --tag mig
  fixture_ckms access-rights grant --object-uid mig_kek mig_user get encrypt decrypt

  populate_bulk_kmip "${port}"
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag bulk --wrapping-key-id mig_kek bulk_sym_wrapped
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag bulk --wrapping-key-id bulk_aes_256 bulk_wrapped_2
  fixture_ckms rsa keys create --size_in_bits 3072 --tag bulk bulk_rsa_3072
  fixture_ckms certificates certify --generate-key-pair --algorithm rsa2048 \
    --certificate-id bulk_cert_2 --subject-name "CN=Bulk fixture secondary" --tag bulk
  fixture_ckms access-rights grant --object-uid bulk_aes_256 mig_user encrypt decrypt
  fixture_ckms access-rights grant --object-uid bulk_aes_256 bulk_auditor get locate
}

# Docker can accept TCP connections before the KMS endpoint is ready.
wait_for_fixture_ready() {
  local port="$1" deadline=$((SECONDS + 60)) status=""
  while ((SECONDS < deadline)); do
    if status="$(run_isolated curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -d '{}' \
      "http://127.0.0.1:${port}/kmip/2_1" 2>/dev/null)" && [ "${status}" = 422 ]; then
      return 0
    fi
    if [ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_ID}")" != true ]; then
      print_warning "Fixture container exited before its KMIP endpoint was ready."
      return 1
    fi
    sleep 1
  done
  print_warning "Fixture KMIP endpoint did not return HTTP 422 (last status: ${status:-000})."
  return 1
}

write_fixture() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:3])
version = sys.argv[3]
has_wrapping_col = version in {"5.28.0", "5.29.0"}

dangling_wrapped_json = (
    '{"SymmetricKey":{"KeyBlock":{"KeyFormatType":"TransparentSymmetricKey",'
    '"KeyValue":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],'
    '"CryptographicAlgorithm":"AES","CryptographicLength":128,'
    '"KeyWrappingData":{"WrappingMethod":"Encrypt",'
    '"EncryptionKeyInformation":{"UniqueIdentifier":"junk_missing_kek"},'
    '"EncodingOption":"NoEncoding"}}}}'
)
junk_objects = [
    ("junk_bad_json", "{not valid json", None, ["junk", "_cert"]),
    ("junk_wrong_shape_json", '{"NotAKmipObject":{"foo":123}}', None, ["junk"]),
    (
        "junk_bad_cert_der",
        '{"Certificate":{"CertificateType":"X509","CertificateValue":[222,173,190,239]}}',
        None,
        ["junk", "_cert"],
    ),
    (
        "junk_non_cert_tagged_cert",
        '{"OpaqueObject":{"OpaqueDataType":"Unknown","OpaqueDataValue":[1,2,3,4]}}',
        None,
        ["junk", "_cert"],
    ),
    ("junk_dangling_wrapped", dangling_wrapped_json, "junk_missing_kek", ["junk", "_kk"]),
]

with sqlite3.connect(source) as connection:
    for uid, obj_json, wrap_uid, tags in junk_objects:
        if has_wrapping_col:
            connection.execute(
                "INSERT INTO objects (id, object, attributes, state, owner, wrapping_key_id) "
                "VALUES (?, ?, '{}', 'Active', 'admin', ?)",
                (uid, obj_json, wrap_uid),
            )
        else:
            connection.execute(
                "INSERT INTO objects (id, object, attributes, state, owner) "
                "VALUES (?, ?, '{}', 'Active', 'admin')",
                (uid, obj_json),
            )
        for tag in tags:
            connection.execute("INSERT INTO tags (id, tag) VALUES (?, ?)", (uid, tag))
    connection.execute(
        "INSERT INTO tags (id, tag) VALUES ('junk_orphan_object', 'junk_orphan_tag')"
    )
    connection.execute(
        "INSERT INTO read_access (id, userid, permissions) "
        "VALUES ('junk_orphan_object', 'mig_user', '[\"get\"]')"
    )
    connection.commit()
    connection.execute("VACUUM INTO ?", (str(destination),))

with sqlite3.connect(destination) as connection:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)")}
    parameters = dict(connection.execute("SELECT name, value FROM parameters"))
    objects = dict(connection.execute("SELECT id, state FROM objects"))
    expected_mig = {"mig_kek", "mig_wrapped", "mig_rsa", "mig_rsa_pk", "mig_revoked", "mig_cert"}
    expected_bulk = {
        "bulk_aes_128",
        "bulk_aes_192",
        "bulk_aes_256",
        "bulk_sym_wrapped",
        "bulk_rsa_3072",
        "bulk_rsa_3072_pk",
        "bulk_wrapped_2",
        "bulk_ec_p256",
        "bulk_ec_p256_pk",
        "bulk_ec_p384",
        "bulk_ec_p384_pk",
        "bulk_secret_data",
        "bulk_opaque",
        "bulk_cert_2",
        "bulk_preactive",
        "bulk_compromised",
        "bulk_destroyed",
    }
    expected_junk = {row[0] for row in junk_objects}
    expected_named = expected_mig | expected_bulk | expected_junk
    if not expected_named <= objects.keys() or len(objects) != 32:
        raise RuntimeError(
            f"Unexpected fixture objects (count={len(objects)}, missing={expected_named - objects.keys()})"
        )
    expected_states = {
        "mig_revoked": "Deactivated",
        "bulk_preactive": "PreActive",
        "bulk_compromised": "Compromised",
        "bulk_destroyed": "Destroyed",
    }
    for uid, state in objects.items():
        want = expected_states.get(uid, "Active")
        if state != want:
            raise RuntimeError(f"Unexpected state for {uid}: got {state}, expected {want}")
    if ("wrapping_key_id" in columns) != has_wrapping_col:
        raise RuntimeError(f"Unexpected wrapping_key_id column for {version}")
    if parameters.get("wrapping_key_id_backfilled") != ("true" if has_wrapping_col else None):
        raise RuntimeError(f"Unexpected wrapping backfill marker for {version}")
    if "db_version" in parameters:
        raise RuntimeError(f"Unexpected database version for {version}")
    if parameters.get("certificate_serial_tag_backfilled") != (
        "true" if version == "5.29.0" else None
    ):
        raise RuntimeError(f"Unexpected serial-tag marker for {version}")
    mig_tagged = {row[0] for row in connection.execute("SELECT id FROM tags WHERE tag='mig'")}
    bulk_tagged = {row[0] for row in connection.execute("SELECT id FROM tags WHERE tag='bulk'")}
    junk_tagged = {row[0] for row in connection.execute("SELECT id FROM tags WHERE tag='junk'")}
    if len(mig_tagged) != 8 or not expected_mig <= mig_tagged:
        raise RuntimeError(f"Unexpected mig-tagged objects: {mig_tagged}")
    if len(bulk_tagged) != 19 or not expected_bulk <= bulk_tagged:
        raise RuntimeError(f"Unexpected bulk-tagged objects: {bulk_tagged}")
    if junk_tagged != expected_junk:
        raise RuntimeError(f"Unexpected junk-tagged objects: {junk_tagged}")
    if (mig_tagged | bulk_tagged | junk_tagged) != objects.keys():
        raise RuntimeError("Every fixture object must carry mig, bulk, or junk tag")
    grant = connection.execute(
        "SELECT permissions FROM read_access WHERE id='mig_kek' AND userid='mig_user'"
    ).fetchone()
    if grant is None or set(json.loads(grant[0])) != {"get", "encrypt", "decrypt"}:
        raise RuntimeError("Missing or incorrect mig_user grant")
    for cert_id in ("mig_cert", "bulk_cert_2"):
        serial_tags = connection.execute(
            "SELECT count(*) FROM tags WHERE id=? AND tag GLOB '_serial=*'",
            (cert_id,),
        ).fetchone()[0]
        if serial_tags != (1 if version == "5.29.0" else 0):
            raise RuntimeError(f"Unexpected certificate serial tag count for {cert_id} in {version}")
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise RuntimeError(f"Invalid SQLite fixture for {version}")
    print(f"{version}: verified {len(objects)} objects, unversioned SQLite fixture")
PY
}

generate_fixture() {
  local image="$1" version="$2"
  local data_dir="${WORK_DIR}/${version}"
  local output_dir="${REPO_ROOT}/test_data/db_migration/${version}/sqlite"
  local address port
  mkdir -p "${data_dir}" "${output_dir}"
  [ ! -e "${output_dir}/kms.db" ] || print_error "Fixture already exists: ${output_dir}/kms.db"
  print_status "Generating SQLite fixture with ${image}"
  CONTAINER_ID="$(docker run --detach --publish 127.0.0.1::9998 \
    --volume "${data_dir}:/data" "${image}" \
    --database-type sqlite --sqlite-path /data)"
  address="$(docker port "${CONTAINER_ID}" 9998/tcp)"
  port="${address##*:}"
  if ! wait_for_fixture_ready "${port}"; then
    docker logs "${CONTAINER_ID}" >&2
    print_error "Release ${version} did not start."
  fi
  fixture_ckms --version
  populate_fixture "${port}"
  docker exec "${CONTAINER_ID}" chown -R "$(id -u):$(id -g)" /data
  docker stop "${CONTAINER_ID}" >/dev/null
  docker rm "${CONTAINER_ID}" >/dev/null
  CONTAINER_ID=""
  write_fixture "${data_dir}/kms.db" "${output_dir}/kms.db" "${version}"
}

selected=false
for image in "${IMAGES[@]}"; do
  version="${image#*:}"
  version="${version%%@*}"
  if [ -n "${SELECTED_VERSION}" ] && [ "${version}" != "${SELECTED_VERSION}" ]; then
    continue
  fi
  selected=true
  generate_fixture "${image}" "${version}"
done
[ "${selected}" = true ] || print_error "Unknown fixture version: ${SELECTED_VERSION}"
print_success "Released SQLite migration fixtures generated and verified."

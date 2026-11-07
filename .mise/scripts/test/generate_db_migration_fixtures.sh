#!/usr/bin/env bash
# Generate migration fixtures with each release's server and ckms.
# Usage: generate_db_migration_fixtures.sh [sqlite|postgresql|mysql|all] [VERSION]
set -euo pipefail

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
REPO_ROOT="$(get_repo_root "${MISE_CONFIG_ROOT}")"
require_cmd docker
require_cmd python3
require_cmd curl
docker_ready || print_error "Docker must be running to generate migration fixtures."
[ "$#" -le 2 ] || print_error "Usage: $0 [sqlite|postgresql|mysql|all] [VERSION]"
SELECTED_VERSION="${2:-}"

case "${1:-all}" in
  sqlite | postgresql | mysql) readonly BACKENDS=("$1") ;;
  all) readonly BACKENDS=(sqlite postgresql mysql) ;;
  *) print_error "Usage: $0 [sqlite|postgresql|mysql|all]" ;;
esac

# Resolve pins with: docker pull <image>:<tag>
# The Digest line identifies the immutable release manifest.
readonly IMAGES=(
  "ghcr.io/cosmian/kms:5.14.0@sha256:137d2fcfaa149bb5060cc932f515bb53ee63c5a3fc2224586711352d9455e7c7"
  "ghcr.io/cosmian/kms:5.20.0@sha256:a74dc266e85a75e038ab75243afe64c2d5f65a0219a5561eb99d2b7febc47e80"
  "ghcr.io/cosmian/kms:5.24.0@sha256:a8c2b6577ce366c534fb29e388b8b7b473fc8a4445fa2ab6f32c8da13004e50a"
  "ghcr.io/cosmian/kms:5.28.0@sha256:7b60fd4484930969906caa5722b727054ff96d49339ce81e3c64ca9e4278540e"
  "ghcr.io/cosmian/kms:5.29.0@sha256:a5592576c17854868c8abe6536b0ab89c49f31eb978c2778d2ee471330e083c8"
)
# 5.14.0 ships no ckms, so the 5.20.0 client drives it.
readonly CKMS_FALLBACK_IMAGE="${IMAGES[1]}"
readonly POSTGRES_IMAGE="postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
readonly MYSQL_IMAGE="mysql:8.0@sha256:99d774bf02a48a1bb1c599920d2571946d31e5940b854b02737d5e95c184358f"
# Throwaway credentials of the fixture database containers.
readonly DB_PASSWORD="kms-fixture"

# One line of facts per restored dump; expected_facts spells out the required values.
readonly NAMED_IDS="('mig_kek', 'mig_wrapped', 'mig_rsa', 'mig_rsa_pk', 'mig_revoked', 'mig_cert',
  'bulk_aes_128', 'bulk_aes_192', 'bulk_aes_256', 'bulk_sym_wrapped', 'bulk_rsa_3072',
  'bulk_rsa_3072_pk', 'bulk_wrapped_2', 'bulk_ec_p256', 'bulk_ec_p256_pk', 'bulk_ec_p384',
  'bulk_ec_p384_pk', 'bulk_secret_data', 'bulk_opaque', 'bulk_cert_2', 'bulk_preactive',
  'bulk_compromised', 'bulk_destroyed', 'junk_bad_json', 'junk_wrong_shape_json',
  'junk_bad_cert_der', 'junk_non_cert_tagged_cert', 'junk_dangling_wrapped')"
PG_FACTS="$(
  cat <<SQL
SELECT concat_ws(' ',
  'objects=' || (SELECT count(*) FROM objects),
  'named=' || (SELECT count(*) FROM objects WHERE id IN ${NAMED_IDS}),
  'revoked=' || (SELECT state FROM objects WHERE id = 'mig_revoked'),
  'preactive=' || (SELECT state FROM objects WHERE id = 'bulk_preactive'),
  'compromised=' || (SELECT state FROM objects WHERE id = 'bulk_compromised'),
  'destroyed=' || (SELECT state FROM objects WHERE id = 'bulk_destroyed'),
  'untagged=' || (SELECT count(*) FROM objects o
    WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE t.id = o.id AND t.tag IN ('mig', 'bulk', 'junk'))),
  'orphans=' || (
    (SELECT count(*) FROM tags t WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = t.id)) +
    (SELECT count(*) FROM read_access r WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = r.id))
  ),
  'grant=' || (SELECT string_agg(p, ',' ORDER BY p)
    FROM read_access, json_array_elements_text(permissions) p
    WHERE id = 'mig_kek' AND userid = 'mig_user'),
  'serial_tags=' || (SELECT count(*) FROM tags WHERE id IN ('mig_cert', 'bulk_cert_2') AND tag LIKE '_serial=%'),
  'wrapping_column=' || (SELECT count(*) FROM information_schema.columns
    WHERE table_name = 'objects' AND column_name = 'wrapping_key_id'),
  'parameters=' || (SELECT coalesce(string_agg(name || ':' || value, ',' ORDER BY name), '')
    FROM parameters),
  'attributes=' || (SELECT data_type FROM information_schema.columns
    WHERE table_name = 'objects' AND column_name = 'attributes'));
SQL
)"
readonly PG_FACTS
MYSQL_FACTS="$(
  cat <<SQL
SELECT CONCAT_WS(' ',
  CONCAT('objects=', (SELECT COUNT(*) FROM objects)),
  CONCAT('named=', (SELECT COUNT(*) FROM objects WHERE id IN ${NAMED_IDS})),
  CONCAT('revoked=', (SELECT state FROM objects WHERE id = 'mig_revoked')),
  CONCAT('preactive=', (SELECT state FROM objects WHERE id = 'bulk_preactive')),
  CONCAT('compromised=', (SELECT state FROM objects WHERE id = 'bulk_compromised')),
  CONCAT('destroyed=', (SELECT state FROM objects WHERE id = 'bulk_destroyed')),
  CONCAT('untagged=', (SELECT COUNT(*) FROM objects o
    WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE t.id = o.id AND t.tag IN ('mig', 'bulk', 'junk')))),
  CONCAT('orphans=', (
    (SELECT COUNT(*) FROM tags t WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = t.id)) +
    (SELECT COUNT(*) FROM read_access r WHERE NOT EXISTS (SELECT 1 FROM objects o WHERE o.id = r.id))
  )),
  CONCAT('grant=', (SELECT GROUP_CONCAT(j.p ORDER BY j.p)
    FROM read_access, JSON_TABLE(permissions, '\$[*]' COLUMNS (p VARCHAR(32) PATH '\$')) j
    WHERE id = 'mig_kek' AND userid = 'mig_user')),
  CONCAT('serial_tags=', (SELECT COUNT(*) FROM tags WHERE id IN ('mig_cert', 'bulk_cert_2') AND tag LIKE '_serial=%')),
  CONCAT('wrapping_column=', (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'objects' AND column_name = 'wrapping_key_id')),
  CONCAT('parameters=', COALESCE((SELECT GROUP_CONCAT(name, ':', value ORDER BY name)
    FROM parameters), '')));
SQL
)"
readonly MYSQL_FACTS

WORK_DIR="$(mktemp -d -t kms-db-migration-fixtures-XXXXXX)"
readonly NETWORK="kms-fixtures-${WORK_DIR##*-}"
readonly KMS_NAME="${NETWORK}-kms" DB_NAME="${NETWORK}-db"
CKMS_IMAGE=""

cleanup() {
  local status="$?"
  # docker rm --force succeeds on a missing container, so a failure here is real.
  if ! docker rm --force "${KMS_NAME}" "${DB_NAME}" >/dev/null 2>&1; then
    print_warning "Could not remove fixture containers ${KMS_NAME} and ${DB_NAME}."
    status=1
  fi
  if docker network inspect "${NETWORK}" >/dev/null 2>&1 &&
    ! docker network rm "${NETWORK}" >/dev/null; then
    print_warning "Could not remove fixture network ${NETWORK}."
    status=1
  fi
  if ! rm -rf -- "${WORK_DIR:?}"; then
    print_warning "Could not remove fixture scratch directory ${WORK_DIR}."
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

fixture_ckms() {
  docker run --rm --network "${NETWORK}" --entrypoint /usr/local/bin/ckms "${CKMS_IMAGE}" \
    --url "http://${KMS_NAME}:9998" "$@"
}

# Start a release server on the fixture network; the arguments follow `docker run`.
# docker-proxy accepts TCP before the server listens, so readiness is an actual KMS call.
start_kms() {
  docker run --detach --name "${KMS_NAME}" --network "${NETWORK}" --publish 127.0.0.1::9998 "$@" >/dev/null
  if wait_for_command 60 fixture_ckms server version >/dev/null 2>&1; then
    return 0
  fi
  docker logs "${KMS_NAME}" >&2
  print_error "The KMS server did not start."
}

stop_kms() {
  docker stop "${KMS_NAME}" >/dev/null
  docker rm "${KMS_NAME}" >/dev/null
}

# Run one client action against the fixture database container.
db_client() {
  local mysql_env=(--env "MYSQL_PWD=${DB_PASSWORD}")
  case "$1/$2" in
    postgresql/ready) docker exec "${DB_NAME}" pg_isready --quiet --host 127.0.0.1 --username kms --dbname kms ;;
    postgresql/dump) docker exec "${DB_NAME}" pg_dump --no-owner --no-privileges --inserts --username kms kms ;;
    postgresql/restore) docker exec --interactive "${DB_NAME}" psql --quiet --set ON_ERROR_STOP=1 --username kms --dbname kms ;;
    postgresql/facts) docker exec "${DB_NAME}" psql --no-align --tuples-only --username kms --dbname kms --command "${PG_FACTS}" ;;
    mysql/ready) docker exec "${mysql_env[@]}" "${DB_NAME}" mysqladmin ping --silent --host 127.0.0.1 --user kms ;;
    mysql/dump)
      docker exec "${mysql_env[@]}" "${DB_NAME}" mysqldump --no-tablespaces --skip-add-locks \
        --skip-lock-tables --skip-comments --set-gtid-purged=OFF --user kms kms
      ;;
    mysql/restore) docker exec --interactive "${mysql_env[@]}" "${DB_NAME}" mysql --user kms kms ;;
    mysql/facts) docker exec "${mysql_env[@]}" "${DB_NAME}" mysql --batch --skip-column-names --user kms kms --execute "${MYSQL_FACTS}" ;;
    *) print_error "Unknown database client action: $1/$2" ;;
  esac
}

# Start an empty database server. The images run their init server without TCP,
# so a TCP probe only succeeds against the final server.
start_db() {
  local backend="$1"
  if [ "${backend}" = postgresql ]; then
    docker run --detach --name "${DB_NAME}" --network "${NETWORK}" --env POSTGRES_USER=kms \
      --env POSTGRES_PASSWORD="${DB_PASSWORD}" --env POSTGRES_DB=kms "${POSTGRES_IMAGE}" >/dev/null
  else
    docker run --detach --name "${DB_NAME}" --network "${NETWORK}" --env MYSQL_USER=kms \
      --env MYSQL_PASSWORD="${DB_PASSWORD}" --env MYSQL_ROOT_PASSWORD="${DB_PASSWORD}" \
      --env MYSQL_DATABASE=kms "${MYSQL_IMAGE}" >/dev/null
  fi
  if wait_for_command 120 db_client "${backend}" ready >/dev/null 2>&1; then
    return 0
  fi
  docker logs "${DB_NAME}" >&2
  print_error "The ${backend} fixture database did not start."
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
  local address
  address="$(docker port "${KMS_NAME}" 9998/tcp)"
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_kek
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig --wrapping-key-id mig_kek mig_wrapped
  fixture_ckms rsa keys create --size_in_bits 2048 --tag mig mig_rsa
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_revoked
  fixture_ckms sym keys revoke --key-id mig_revoked "Migration fixture revocation"
  fixture_ckms certificates certify --generate-key-pair --algorithm rsa2048 \
    --certificate-id mig_cert --subject-name "CN=Migration fixture" --tag mig
  fixture_ckms access-rights grant --object-uid mig_kek mig_user get encrypt decrypt

  populate_bulk_kmip "${address##*:}"
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag bulk --wrapping-key-id mig_kek bulk_sym_wrapped
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag bulk --wrapping-key-id bulk_aes_256 bulk_wrapped_2
  fixture_ckms rsa keys create --size_in_bits 3072 --tag bulk bulk_rsa_3072
  fixture_ckms certificates certify --generate-key-pair --algorithm rsa2048 \
    --certificate-id bulk_cert_2 --subject-name "CN=Bulk fixture secondary" --tag bulk
  fixture_ckms access-rights grant --object-uid bulk_aes_256 mig_user encrypt decrypt
  fixture_ckms access-rights grant --object-uid bulk_aes_256 bulk_auditor get locate
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

seed_sql_junk() {
  local backend="$1" version="$2"
  local dangling_json='{"SymmetricKey":{"KeyBlock":{"KeyFormatType":"TransparentSymmetricKey","KeyValue":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],"CryptographicAlgorithm":"AES","CryptographicLength":128,"KeyWrappingData":{"WrappingMethod":"Encrypt","EncryptionKeyInformation":{"UniqueIdentifier":"junk_missing_kek"},"EncodingOption":"NoEncoding"}}}}'
  local cert_json='{"Certificate":{"CertificateType":"X509","CertificateValue":[222,173,190,239]}}'
  local opaque_json='{"OpaqueObject":{"OpaqueDataType":"Unknown","OpaqueDataValue":[1,2,3,4]}}'
  {
    cat <<SQL
INSERT INTO objects (id, object, attributes, state, owner) VALUES
  ('junk_bad_json', '{not valid json', '{}', 'Active', 'admin'),
  ('junk_wrong_shape_json', '{"NotAKmipObject":{"foo":123}}', '{}', 'Active', 'admin'),
  ('junk_bad_cert_der', '${cert_json}', '{}', 'Active', 'admin'),
  ('junk_non_cert_tagged_cert', '${opaque_json}', '{}', 'Active', 'admin'),
  ('junk_dangling_wrapped', '${dangling_json}', '{}', 'Active', 'admin');
SQL
    if [ "${version}" = 5.28.0 ]; then
      echo "UPDATE objects SET wrapping_key_id = 'junk_missing_kek' WHERE id = 'junk_dangling_wrapped';"
    fi
    cat <<'SQL'
INSERT INTO tags (id, tag) VALUES
  ('junk_bad_json', 'junk'),
  ('junk_bad_json', '_cert'),
  ('junk_wrong_shape_json', 'junk'),
  ('junk_bad_cert_der', 'junk'),
  ('junk_bad_cert_der', '_cert'),
  ('junk_non_cert_tagged_cert', 'junk'),
  ('junk_non_cert_tagged_cert', '_cert'),
  ('junk_dangling_wrapped', 'junk'),
  ('junk_dangling_wrapped', '_kk'),
  ('junk_orphan_object', 'junk_orphan_tag');
INSERT INTO read_access (id, userid, permissions) VALUES
  ('junk_orphan_object', 'mig_user', '["get"]');
SQL
  } | db_client "${backend}" restore >/dev/null
}

# 5.14.0 is versioned and stores attributes as json; 5.28.0 ran the wrapping backfill.
expected_facts() {
  local backend="$1" version="$2"
  local facts="objects=32 named=28 revoked=Deactivated preactive=PreActive compromised=Compromised destroyed=Destroyed untagged=0 orphans=2 grant=decrypt,encrypt,get serial_tags=0"
  case "${version}" in
    5.14.0) facts+=' wrapping_column=0 parameters=db_state:"ready",db_version:5.14.0' ;;
    5.28.0) facts+=" wrapping_column=1 parameters=wrapping_key_id_backfilled:true" ;;
    *) facts+=" wrapping_column=0 parameters=" ;;
  esac
  if [ "${backend}" = postgresql ] && [ "${version}" = 5.14.0 ]; then
    facts+=" attributes=json"
  elif [ "${backend}" = postgresql ]; then
    facts+=" attributes=jsonb"
  fi
  echo "${facts}"
}

# Dump the populated database, then prove the dump restores into an empty server.
write_sql_fixture() {
  local backend="$1" version="$2" output="$3"
  local dump="${WORK_DIR}/dump.sql" facts expected
  seed_sql_junk "${backend}" "${version}"
  # pg_dump 18 brackets the dump in psql-only \restrict meta-commands.
  db_client "${backend}" dump | grep -v -E '^\\(un)?restrict ' >"${dump}"
  if grep -q '^[\]' "${dump}"; then
    print_error "Unexpected psql meta-command in the ${backend} ${version} dump"
  fi
  docker rm --force "${DB_NAME}" >/dev/null
  start_db "${backend}"
  db_client "${backend}" restore <"${dump}" >/dev/null
  facts="$(db_client "${backend}" facts)"
  expected="$(expected_facts "${backend}" "${version}")"
  if [ "${facts}" != "${expected}" ]; then
    print_error "Unexpected ${backend} ${version} fixture: got '${facts}', expected '${expected}'"
  fi
  docker rm --force "${DB_NAME}" >/dev/null
  mv "${dump}" "${output}"
  echo "${version}: verified ${backend} dump: ${facts}"
}

generate_sqlite_fixture() {
  local image="$1" version="$2" output="$3"
  local data_dir="${WORK_DIR}/${version}"
  mkdir -p "${data_dir}"
  start_kms --volume "${data_dir}:/data" "${image}" --database-type sqlite --sqlite-path /data
  fixture_ckms --version
  populate_fixture
  docker exec "${KMS_NAME}" chown -R "$(id -u):$(id -g)" /data
  stop_kms
  write_fixture "${data_dir}/kms.db" "${output}" "${version}"
}

generate_sql_fixture() {
  local backend="$1" image="$2" version="$3" output="$4"
  local port=5432
  [ "${backend}" = postgresql ] || port=3306
  start_db "${backend}"
  start_kms "${image}" --database-type "${backend}" \
    --database-url "${backend}://kms:${DB_PASSWORD}@${DB_NAME}:${port}/kms"
  fixture_ckms --version
  populate_fixture
  stop_kms
  write_sql_fixture "${backend}" "${version}" "${output}"
}

generate_fixture() {
  local backend="$1" image="$2" version="$3"
  local output_dir="${REPO_ROOT}/test_data/db_migration/${version}/${backend}"
  local output="${output_dir}/dump.sql"
  [ "${backend}" != sqlite ] || output="${output_dir}/kms.db"
  [ ! -e "${output}" ] || print_error "Fixture already exists: ${output}"
  mkdir -p "${output_dir}"
  CKMS_IMAGE="${image}"
  [ "${version}" != 5.14.0 ] || CKMS_IMAGE="${CKMS_FALLBACK_IMAGE}"
  print_status "Generating ${backend} fixture with ${image}"
  if [ "${backend}" = sqlite ]; then
    generate_sqlite_fixture "${image}" "${version}" "${output}"
  else
    generate_sql_fixture "${backend}" "${image}" "${version}" "${output}"
  fi
}

docker network create "${NETWORK}" >/dev/null
selected=false
generated=false
for backend in "${BACKENDS[@]}"; do
  for image in "${IMAGES[@]}"; do
    version="${image#*:}"
    version="${version%%@*}"
    if [ -n "${SELECTED_VERSION}" ] && [ "${version}" != "${SELECTED_VERSION}" ]; then
      continue
    fi
    selected=true
    # Only PostgreSQL has a step (json to jsonb) older than the 5.20.0 baseline.
    if [ "${version}" = 5.14.0 ] && [ "${backend}" != postgresql ]; then
      continue
    fi
    # The 5.29.0 fixture exercises the SQLite runner's completed state.
    if [ "${version}" = 5.29.0 ] && [ "${backend}" != sqlite ]; then
      continue
    fi
    generate_fixture "${backend}" "${image}" "${version}"
    generated=true
  done
done
[ "${selected}" = true ] || print_error "Unknown fixture version: ${SELECTED_VERSION}"
[ "${generated}" = true ] ||
  print_error "Version ${SELECTED_VERSION} is not available for ${BACKENDS[*]}"
print_success "Released ${BACKENDS[*]} migration fixtures generated and verified."

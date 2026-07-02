#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regenerate crate/test_kms_server/README.md from all test_data/vectors/ manifest.toml files.

Usage:
    python3 .mise/scripts/docs/gen_vector_readme.py

Outputs: crate/test_kms_server/README.md (overwritten in place)
"""
import os
import sys
import tomllib
from collections import OrderedDict
from pathlib import Path

# Resolve repo root (script lives at .mise/scripts/docs/)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
BASE = REPO_ROOT / 'test_data' / 'vectors'
OUTPUT = REPO_ROOT / 'crate' / 'test_kms_server' / 'README.md'

if not BASE.exists():
    sys.exit(f"ERROR: vectors directory not found: {BASE}")


# ─── Read all vectors ────────────────────────────────────────────────────────
vectors = []
for root, _dirs, files in os.walk(BASE):
    if 'manifest.toml' in files:
        rel = os.path.relpath(root, BASE)
        manifest_path = os.path.join(root, 'manifest.toml')
        with open(manifest_path, 'rb') as f:
            manifest = tomllib.load(f)
        name = manifest.get('name', os.path.basename(rel))
        desc = manifest.get('description', '').strip().split('\n')[0]  # First line only
        steps = len(manifest.get('steps', []))
        vectors.append(
            {
                'path': rel,
                'name': name,
                'description': desc,
                'steps': steps,
                'manifest': manifest,
            }
        )

vectors.sort(key=lambda v: v['path'])
total = len(vectors)


# ─── Classification helpers ──────────────────────────────────────────────────
PQC_PREFIXES = ('ml_dsa_', 'ml_kem_', 'slh_dsa_')


def is_pqc(path):
    basename = os.path.basename(path)
    return any(basename.startswith(p) for p in PQC_PREFIXES)


# ─── Categorize: main table vs KAT (separate section) ───────────────────────
main_vectors = [v for v in vectors if not v['path'].startswith('kat/')]
kat_vectors = [v for v in vectors if v['path'].startswith('kat/')]

categories = OrderedDict()
categories['Symmetric'] = []
categories['Asymmetric'] = []
categories['PQC'] = []
categories['KMIP Operations'] = []
categories['Serialization'] = []
categories['K8s Plugin'] = []
categories['Access Control'] = []
categories['HSM'] = []
categories['Integrations'] = []
categories['TLS'] = []
categories['OPA'] = []
categories['Negative'] = []
categories['non-FIPS CryptographicParameters'] = []
categories['Keyset Resolution'] = []

for v in main_vectors:
    path = v['path']
    parts = path.split('/')
    basename = os.path.basename(path)

    if parts[0] == 'fips':
        if parts[1] == 'symmetric':
            categories['Symmetric'].append(v)
        elif parts[1] == 'asymmetric':
            if is_pqc(path) and 'export' not in basename:
                categories['PQC'].append(v)
            else:
                categories['Asymmetric'].append(v)
        elif parts[1] == 'kmip_operations':
            if 'keyset' in basename and not basename.startswith('rekey'):
                categories['Keyset Resolution'].append(v)
            else:
                categories['KMIP Operations'].append(v)
        elif parts[1] == 'integrations':
            categories['Integrations'].append(v)
        elif parts[1] == 'k8s_plugin':
            categories['K8s Plugin'].append(v)
        elif parts[1] == 'serialization':
            categories['Serialization'].append(v)
    elif parts[0] == 'access_control':
        categories['Access Control'].append(v)
    elif parts[0] == 'hsm':
        categories['HSM'].append(v)
    elif parts[0] == 'negative':
        if 'keyset' in basename or 'rekey_non_latest' in basename:
            categories['Keyset Resolution'].append(v)
        else:
            categories['Negative'].append(v)
    elif parts[0] == 'non-fips':
        if len(parts) > 1 and parts[1] == 'integrations':
            categories['Integrations'].append(v)
        elif 'rekey_keypair' in basename:
            categories['KMIP Operations'].append(v)
        else:
            categories['non-FIPS CryptographicParameters'].append(v)
    elif parts[0] == 'tls':
        categories['TLS'].append(v)
    elif parts[0] == 'opa':
        categories['OPA'].append(v)


# ─── Display path formatter ─────────────────────────────────────────────────
def display_path(v):
    path = v['path']
    parts = path.split('/')
    # Short names for fips subcategories and access_control
    if parts[0] == 'fips' and parts[1] in (
        'symmetric',
        'asymmetric',
        'pqc',
        'kmip_operations',
        'k8s_plugin',
        'serialization',
    ):
        return os.path.basename(path)
    if parts[0] == 'access_control':
        return os.path.basename(path)
    return path


# ─── HSM subcategory label ──────────────────────────────────────────────────
def hsm_sub(v):
    path = v['path']
    parts = path.split('/')
    if 'permissions' in parts:
        return 'HSM / Permissions'
    if len(parts) > 1:
        name = parts[1]
        if name.startswith('kek'):
            if 'bootstrap' in name:
                return 'HSM / KEK Bootstrap'
            if 'rekey' in name:
                return 'HSM / KEK ReKey'
            if 'rsa1024' in name:
                return 'HSM / KEK Negative'
            if 'create' in name or 'sign' in name:
                return 'HSM / KEK Create'
            return 'HSM / KEK'
        if name.startswith('resident'):
            if 'rejected' in name:
                return 'HSM / Resident Negative'
            if 'keyset' in name:
                return 'HSM / Resident Keyset'
            if 'sign' in name:
                return 'HSM / Resident Sign'
            if 'encrypt' in name:
                return 'HSM / Resident Encrypt'
            return 'HSM / Resident Create'
        if name.startswith('hsm_resident'):
            return 'HSM / KEK Baseline'
        if name in ('wrong_prefix', 'no_kek_baseline'):
            return 'HSM / Negative'
    return 'HSM'


# ─── Negative subcategory label ─────────────────────────────────────────────
_NEG_NAME_MAP = {
    'crypto_params': 'CryptoParams',
    'decrypt': 'Decrypt',
    'rsa': 'RSA',
    'sign_verify': 'Sign',
    'sign': 'Sign',
    'mac': 'MAC',
    'mac_verify': 'MAC',
    'hash': 'Hash',
    'derive_key': 'DeriveKey',
    'lifecycle': 'Lifecycle',
    'type_mismatch': 'TypeMismatch',
    'activate': 'Activate',
    'add_attribute': 'AddAttribute',
    'certify': 'Certify',
    'check': 'Check',
    'create': 'Create',
    'create_key_pair': 'CreateKeyPair',
    'delete_attribute': 'DeleteAttribute',
    'destroy': 'Destroy',
    'encrypt': 'Encrypt',
    'export': 'Export',
    'get': 'Get',
    'get_attribute_list': 'GetAttributeList',
    'get_attributes': 'GetAttributes',
    'import': 'Import',
    'modify_attribute': 'ModifyAttribute',
    'register': 'Register',
    'revoke': 'Revoke',
    'set_attribute': 'SetAttribute',
    'signature_verify': 'SignatureVerify',
    'validate': 'Validate',
}


def neg_sub(v):
    parts = v['path'].split('/')
    if len(parts) == 2:
        return 'Negative / Protocol'
    return (
        f"Negative / {_NEG_NAME_MAP.get(parts[1], parts[1].replace('_', ' ').title())}"
    )


# ─── KAT helpers ────────────────────────────────────────────────────────────
def kat_info(v):
    """Extract operations summary and assert fields from manifest."""
    manifest = v['manifest']
    steps = manifest.get('steps', [])
    ops = [s.get('operation', '') for s in steps]
    ops_str = ', '.join(ops)
    assert_fields = []
    for s in steps:
        for k in s.get('assert_fields', {}):
            if k not in assert_fields:
                assert_fields.append(k)
    assert_str = ', '.join(f"`{f}`" for f in assert_fields) if assert_fields else ''
    return ops_str, assert_str


def kat_reference(basename):
    """Determine the standard reference for a KAT vector by its directory name."""
    if 'hkdf' in basename:
        return 'RFC 5869 §A.1'
    if 'pbkdf2' in basename:
        return 'RFC 8018 §5.2'
    if 'ed25519' in basename:
        return 'RFC 8032 §7.1'
    if 'ed448' in basename:
        return 'RFC 8032 §7.4'
    if 'rsa2048' in basename:
        return 'NIST PKCS#1 v2.2'
    if 'secp256k1' in basename:
        return 'RFC 6979 §A.2.5'
    if 'covercrypt' in basename:
        return 'Self-generated USK'
    if 'hmac_sha1' in basename:
        return 'RFC 2202 §3'
    if 'hmac_sha3_' in basename:
        return 'NIST HMAC-SHA3'
    if 'hmac_sha' in basename:
        return 'RFC 4231 §4.2'
    if 'gcm_siv' in basename:
        return 'RFC 8452 §C.1'
    if 'rfc3394' in basename:
        return 'RFC 3394 §2.2.3'
    if 'rfc5649' in basename:
        return 'RFC 5649 §6'
    if 'chacha20_poly1305' in basename:
        return 'RFC 8439 §2.8'
    if 'chacha20' in basename:
        return 'RFC 7539 §2.1'
    if 'xts' in basename:
        return 'IEEE 1619-2007'
    if 'gcm' in basename:
        return 'SP 800-38D TC7'
    if 'ecb' in basename:
        return 'SP 800-38A'
    if 'cbc' in basename:
        return 'SP 800-38A'
    if 'sha3' in basename:
        return 'FIPS 202'
    if any(x in basename for x in ('sha256', 'sha384', 'sha512')):
        return 'FIPS 180-4'
    return ''


# ═══════════════════════════════════════════════════════════════════════════════
#  GENERATE README
# ═══════════════════════════════════════════════════════════════════════════════
out = []

# ─── Header ─────────────────────────────────────────────────────────────────
out.append(
    """# test_kms_server — Vector Runner & Test Infrastructure

This crate provides the **vector runner** for TTLV-JSON regression tests and
utilities for starting isolated KMS server instances in tests.

## Running Vectors

```bash
# All vectors (non-FIPS mode includes both FIPS and non-FIPS vectors)
cargo test -p test_kms_server --features non-fips --lib vector_runner

# Single vector
cargo test -p test_kms_server --features non-fips --lib -- test_vec_aes_create_get

# Record responses (writes step*_response.json files)
RECORD_VECTORS=1 cargo test -p test_kms_server --features non-fips --lib vector_runner

# PostgreSQL backend (requires docker compose up -d)
KMS_TEST_DB=postgresql cargo test -p test_kms_server --features non-fips --lib vector_runner

# Multiple backends at once
KMS_TEST_BACKENDS=sqlite,postgresql cargo test -p test_kms_server --features non-fips --lib vector_runner
```

## Multi-Backend Testing

The vector runner supports testing against multiple database backends.

### How it works

1. Each vector runs against **all four backends** by default (`sqlite`,
   `postgresql`, `mysql`, `redis-findex`) — no per-manifest `backends` field needed.
2. The runner reads `KMS_TEST_BACKENDS` (comma-separated) or `KMS_TEST_DB` (single
   value, used by CI) to select which backends to test.
3. Backends without their required connection env var are **skipped gracefully**.
4. A **singleton server per backend** (`OnceCell`) is shared across all vectors in
   a test run — no per-test server start/stop overhead.
5. Vectors with a custom `server_config` (e.g. cert_auth, TLS) start a dedicated
   server instance instead of using the singleton.

### Backend → config mapping

| Backend        | Config TOML         | Required env var                |
| -------------- | ------------------- | ------------------------------- |
| `sqlite`       | `auth_plain.toml`   | — (always available)            |
| `postgresql`   | `postgres.toml`     | `KMS_POSTGRES_URL`              |
| `mysql`        | `mysql.toml`        | `KMS_MYSQL_URL`                 |
| `redis-findex` | `redis_findex.toml` | `KMS_REDIS_URL` or `REDIS_HOST` |

### CI integration

CI scripts set `KMS_TEST_DB` to select a single backend:

- `test_sqlite.sh` → (default, no env var)
- `test_psql.sh` → `KMS_TEST_DB=postgresql`
- `test_mysql.sh` → `KMS_TEST_DB=mysql`
- `test_redis.sh` → `KMS_TEST_DB=redis`

---

## Regression Test Vectors (TTLV-JSON)

All regression vectors use a uniform **TTLV-JSON** format. Each vector is a directory
under `test_data/vectors/` containing a `manifest.toml` and one JSON step file
per KMIP operation. The vector runner uses singleton shared servers and
replays the steps sequentially.
"""
)

# ─── Main table ─────────────────────────────────────────────────────────────
cat_count = sum(1 for v in categories.values() if v)
out.append(f"**{total} vectors** across {cat_count + 1} categories (including KAT):\n")
out.append('| Category | Vector Directory Name | KMIP Operations | Steps |')
out.append('|----------|-----------------------|-----------------|-------|')

# Symmetric
out.append('| **Symmetric** | | | |')
for v in categories['Symmetric']:
    out.append(
        f"| Symmetric | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# Asymmetric
out.append('| **Asymmetric** | | | |')
for v in categories['Asymmetric']:
    out.append(
        f"| Asymmetric | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# PQC
out.append('| **PQC** | | | |')
for v in categories['PQC']:
    out.append(f"| PQC | `{display_path(v)}` | {v['description']} | {v['steps']} |")

# KMIP Operations
out.append('| **KMIP Operations** | | | |')
for v in categories['KMIP Operations']:
    is_non_fips = v['path'].startswith('non-fips/')
    cat_label = 'KMIP Operations (non-FIPS)' if is_non_fips else 'KMIP Operations'
    out.append(
        f"| {cat_label} | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# Serialization
out.append('| **Serialization** | | | |')
for v in categories['Serialization']:
    out.append(
        f"| Serialization | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# K8s Plugin
out.append('| **K8s Plugin** | | | |')
for v in categories['K8s Plugin']:
    out.append(
        f"| K8s Plugin | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# Access Control
out.append('| **Access Control** | | | |')
for v in categories['Access Control']:
    out.append(
        f"| Access Control | `{display_path(v)}` | {v['description']} | {v['steps']} |"
    )

# HSM
out.append('| **HSM (requires SoftHSM2 + `HSM_SLOT_ID`)** | | | |')
for v in sorted(categories['HSM'], key=lambda x: x['path']):
    out.append(f"| {hsm_sub(v)} | `{v['path']}` | {v['description']} | {v['steps']} |")

# Integrations
out.append('| **Integrations** | | | |')
for v in sorted(categories['Integrations'], key=lambda x: x['path']):
    out.append(f"| Integrations | `{v['path']}` | {v['description']} | {v['steps']} |")

# TLS
out.append('| **TLS Transport** | | | |')
for v in categories['TLS']:
    out.append(f"| TLS | `{v['path']}` | {v['description']} | {v['steps']} |")

# OPA
out.append('| **OPA Policy Engine** | | | |')
for v in sorted(categories['OPA'], key=lambda x: x['path']):
    out.append(f"| OPA | `{v['path']}` | {v['description']} | {v['steps']} |")

# Negative
out.append('| **Negative** | | | |')
for v in sorted(categories['Negative'], key=lambda x: x['path']):
    out.append(f"| {neg_sub(v)} | `{v['path']}` | {v['description']} | {v['steps']} |")

# non-FIPS CryptographicParameters
out.append('| **non-FIPS CryptographicParameters** | | | |')
for v in categories['non-FIPS CryptographicParameters']:
    basename = os.path.basename(v['path'])
    if 'gcm_siv' in basename:
        sub = 'non-FIPS / GCM-SIV'
    elif 'chacha20_poly1305' in basename:
        sub = 'non-FIPS / Poly1305'
    elif 'chacha20' in basename:
        sub = 'non-FIPS / ChaCha20'
    else:
        sub = 'non-FIPS'
    out.append(f"| {sub} | `{v['path']}` | {v['description']} | {v['steps']} |")

# Keyset Resolution
out.append('| **Keyset Resolution** | | | |')
for v in sorted(categories['Keyset Resolution'], key=lambda x: x['path']):
    path = v['path']
    if path.startswith('negative/'):
        sub = 'Negative / Keyset'
    else:
        basename = os.path.basename(path)
        if 'encrypt' in basename:
            sub = 'Keyset / Encrypt'
        elif 'decrypt' in basename:
            sub = 'Keyset / Decrypt'
        else:
            sub = 'Keyset'
    out.append(f"| {sub} | `{display_path(v)}` | {v['description']} | {v['steps']} |")

out.append('')
out.append('---')
out.append('')

# ─── KAT Section ────────────────────────────────────────────────────────────
out.append(
    """## Known-Answer Test (KAT) Vectors (`test_data/vectors/kat/`)

KAT vectors use **published reference values** from NIST FIPS and RFC specifications to
verify bit-exact outputs. Each vector imports a known key and asserts exact ciphertext,
MAC, or derived-key values.

| Category | Vector Directory | Reference | Operations | Assert Field |
|----------|-----------------|-----------|------------|--------------|"""
)

# Group KAT by subcategory
kat_groups = OrderedDict()
for v in kat_vectors:
    parts = v['path'].split('/')
    subcat = parts[1] if len(parts) >= 2 else 'other'
    if subcat not in kat_groups:
        kat_groups[subcat] = []
    kat_groups[subcat].append(v)

kat_headers = {
    'hash': ('**Hash**', 'NIST FIPS 180-4 / FIPS 202'),
    'mac': ('**MAC**', 'RFC 4231 / RFC 2202 / NIST HMAC-SHA3'),
    'symmetric': (
        '**Symmetric**',
        'NIST SP 800-38A / SP 800-38D / RFC 8439 / RFC 7539 / RFC 3394 / RFC 5649',
    ),
    'derive_key': ('**Derive Key**', 'RFC 5869 / RFC 8018'),
    'asymmetric': ('**Asymmetric**', 'RFC 8032 / NIST PKCS#1 / RFC 6979'),
    'covercrypt_decrypt': ('**Covercrypt**', 'Cosmian Covercrypt v16'),
}

for subcat, vecs in kat_groups.items():
    header_name, ref_group = kat_headers.get(subcat, (f"**{subcat.title()}**", ''))
    out.append(f"| {header_name} | | {ref_group} | | |")
    for v in sorted(vecs, key=lambda x: x['path']):
        ops_str, assert_str = kat_info(v)
        basename = os.path.basename(v['path'])
        ref = kat_reference(basename)
        is_non_fips = any(
            x in basename
            for x in ('gcm_siv', 'chacha20', 'ed448', 'secp256k1', 'covercrypt', 'xts')
        )
        cat_prefix = (
            f"{subcat.replace('_', ' ').title()} (non-FIPS)"
            if is_non_fips
            else subcat.replace('_', ' ').title()
        )
        out.append(
            f"| {cat_prefix} | `{v['path']}` | {ref} | {ops_str} | {assert_str} |"
        )

out.append('')
out.append('---')
out.append('')

# ─── Manifest Schema ────────────────────────────────────────────────────────
out.append(
    """## Manifest Schema (`manifest.toml`)

```toml
# Required metadata
name = "AES-256 Create and Get"
description = "Creates an AES-256 symmetric key and retrieves it via Get"

# Optional: override default server config (defaults to auth_plain.toml)
# Vectors with server_config start a dedicated server instance instead of
# using the shared singleton.
# server_config = "test_data/configs/server/test/cert_auth.toml"

# Optional: wire format — "json" (default) or "binary"
# "json" sends TTLV-JSON to /kmip/2_1
# "binary" serializes to binary TTLV and POSTed to /kmip (application/octet-stream)
# wire_format = "binary"

# Optional: KMIP protocol version (default [2, 1])
# Used to set the RequestHeader version and select KMIP 1.x / 2.x / 3.x serialization
# kmip_version = [3, 0]

# Optional: named identities for multi-user (access control) tests.
# [identities.owner]
# client_cert = "test_data/certificates/client_server/owner/owner.client.acme.com.crt"
# client_key = "test_data/certificates/client_server/owner/owner.client.acme.com.key"
# client_pkcs12 = "test_data/certificates/client_server/owner/owner.client.acme.com.p12"
# client_pkcs12_password = "password"

# Steps executed sequentially against the KMS server
[[steps]]
operation = "Create"
request = "step1_request.json"
assert_success = true                   # HTTP 200 + ResultStatus check

[steps.capture]
key_id = "UniqueIdentifier"             # capture tag value for use in later steps

[[steps]]
operation = "Get"
request = "step2_request.json"          # contains {{key_id}} placeholder
assert_success = true

[steps.assert_fields]
ObjectType = "SymmetricKey"             # assert specific TTLV tags in response

# Batch requests: raw_request = true sends a complete RequestMessage as-is
[[steps]]
operation = "Batch Create+Query"
request = "step_batch.json"             # must be a full RequestMessage JSON
raw_request = true
assert_success = true                   # asserts ALL BatchItem ResultStatus == Success

# Error testing: assert failure and inspect reason
[[steps]]
operation = "Encrypt"
request = "step_encrypt_after_revoke.json"
assert_success = false
assert_error_reason = "PermissionDenied"          # match ResultReason tag
# assert_error_contains = "partial message match" # alternative: substring in ResultMessage

# Negative assertions: verify fields are absent from response
[steps.assert_fields_absent]
fields = ["SensitiveField"]

# Assert that a captured value appears among results (for multi-result Locate)
[steps.assert_any_field]
UniqueIdentifier = "{{key_id}}"
```

---

## Request Payloads (TTLV-JSON)

Request files are TTLV-JSON payloads. By default (`wire_format = "json"`), they
are sent directly to the `/kmip/2_1` endpoint. When `wire_format = "binary"`, the
JSON is wrapped in a `RequestMessage` envelope, serialized to binary TTLV, and
POSTed to `/kmip` with `Content-Type: application/octet-stream`.

When `raw_request = true`, the file IS the complete `RequestMessage` (used for
batch requests and integration vectors requiring custom headers).

Binary-mode integration vectors use KMIP 1.x `TemplateAttribute` format:

```json
{
  "tag": "Create",
  "value": [
    { "tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey" },
    { "tag": "TemplateAttribute", "value": [
      { "tag": "Attribute", "value": [
        { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Algorithm" },
        { "tag": "AttributeValue", "type": "Enumeration", "value": "AES" }
      ]},
      { "tag": "Attribute", "value": [
        { "tag": "AttributeName", "type": "TextString", "value": "Cryptographic Length" },
        { "tag": "AttributeValue", "type": "Integer", "value": 256 }
      ]}
    ]}
  ]
}
```

JSON-mode vectors use KMIP 2.1 `Attributes` format:

```json
{
  "tag": "Create",
  "value": [
    { "tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey" },
    { "tag": "Attributes", "value": [
      { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES" },
      { "tag": "CryptographicLength", "type": "Integer", "value": 256 }
    ]}
  ]
}
```

Placeholders use `{{variable_name}}` syntax and are substituted from captured values:

```json
{
  "tag": "Get",
  "value": [
    { "tag": "UniqueIdentifier", "type": "TextString", "value": "{{key_id}}" }
  ]
}
```"""
)

# ─── Write output ───────────────────────────────────────────────────────────
content = '\n'.join(out) + '\n'
existing = OUTPUT.read_text(encoding='utf-8') if OUTPUT.exists() else ''
changed = content != existing
if changed:
    with open(OUTPUT, 'w', encoding='utf-8') as f:
        f.write(content)

# ─── Verify ─────────────────────────────────────────────────────────────────
accounted = sum(len(v) for v in categories.values()) + len(kat_vectors)
if accounted != total:
    sys.exit(f"ERROR: {accounted} categorized != {total} on disk")

print(
    f"✓ {OUTPUT.relative_to(REPO_ROOT)}: {total} vectors documented ({len(out)} lines)"
)
# Exit 1 when the file was updated so pre-commit blocks the commit and the
# developer re-stages the regenerated README before continuing.
if changed:
    sys.exit(1)

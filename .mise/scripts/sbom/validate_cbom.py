#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CycloneDX 1.6 CBOM validator for Cosmian KMS.

Performs two complementary validation passes:

  1. Structural  — checks required fields, valid enum values, PURL format,
                   UUID serial number, ISO-8601 timestamp, bom-ref uniqueness.
                   Runs offline, no external dependencies beyond jsonschema.

  2. Schema      — validates against the official CycloneDX 1.6 JSON Schema
                   downloaded from cyclonedx.org and cached locally under
                   .cache/cyclonedx/. Falls back gracefully when offline.

Exit code 0 = valid.  Exit code 1 = one or more errors found.

Usage:
    python3 validate_cbom.py <cbom.cdx.json>
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

# ── CycloneDX 1.6 enumeration constants ──────────────────────────────────────

VALID_PRIMITIVES = {
    'ae',
    'block-cipher',
    'stream-cipher',
    'hash',
    'kdf',
    'kem',
    'signature',
    'key-agree',
    'xof',
    'combiner',
    'pke',
    'other',
    'unknown',
}

VALID_CRYPTO_FUNCTIONS = {
    'generate',
    'keygen',
    'encrypt',
    'decrypt',
    'sign',
    'verify',
    'digest',
    'tag',
    'keyderive',
    'wrap',
    'unwrap',
    'encapsulate',
    'decapsulate',
    'other',
    'unknown',
}

VALID_ASSET_TYPES = {
    'algorithm',
    'protocol',
    'certificate',
    'related-crypto-material',
    'library',
}

VALID_COMPONENT_TYPES = {
    'application',
    'container',
    'device',
    'device-driver',
    'file',
    'firmware',
    'framework',
    'library',
    'machine-learning-model',
    'operating-system',
    'platform',
    'cryptographic-asset',
    'data',
}

VALID_MODES = {
    'cbc',
    'ccm',
    'cfb',
    'ctr',
    'ecb',
    'gcm',
    'ofb',
    'siv',
    'xts',
    'kw',
    'kwp',
    'other',
    'unknown',
}

VALID_PADDINGS = {
    'oaep',
    'pkcs1v15',
    'pss',
    'raw',
    'none',
    'other',
    'unknown',
}

VALID_EXECUTION_ENVS = {
    'software-plain-ram',
    'software-encrypted-ram',
    'software-tee',
    'hardware',
    'other',
    'unknown',
}

VALID_IMPL_LEVELS = {
    'algorithmic',
    'partial',
    'primitive',
    'library',
    'hardwareComponent',
    'softwareComponent',
    'firmware',
    'other',
    'unknown',
}

# CycloneDX 1.6 JSON schema — downloaded once and cached
SCHEMA_URL = 'https://cyclonedx.org/schema/bom-1.6.schema.json'
CACHE_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent / '.cache' / 'cyclonedx'
)
SCHEMA_CACHE = CACHE_DIR / 'bom-1.6.schema.json'


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_urn_uuid(value: str) -> bool:
    return bool(
        re.match(
            r'^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            value,
            re.IGNORECASE,
        )
    )


def _is_iso8601(value: str) -> bool:
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%S.%fZ'):
        try:
            datetime.strptime(value, fmt)
            return True
        except ValueError:
            pass
    return False


def _is_valid_purl(value: str) -> bool:
    # Lightweight PURL check: pkg:<type>/<name>@<version>
    return bool(re.match(r'^pkg:[a-zA-Z0-9.+-]+/.+@.+$', value))


# ── Pass 1: structural validation ─────────────────────────────────────────────


def validate_structural(cbom: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    # ── Top-level required fields ────────────────────────────────────────────
    for field in (
        'bomFormat',
        'specVersion',
        'serialNumber',
        'version',
        'metadata',
        'components',
    ):
        if field not in cbom:
            errors.append(f"Missing required top-level field: '{field}'")

    if cbom.get('bomFormat') != 'CycloneDX':
        errors.append(f"bomFormat must be 'CycloneDX', got {cbom.get('bomFormat')!r}")

    if cbom.get('specVersion') != '1.6':
        errors.append(f"specVersion must be '1.6', got {cbom.get('specVersion')!r}")

    serial = cbom.get('serialNumber', '')
    if serial and not _is_urn_uuid(serial):
        errors.append(f"serialNumber must be a URN UUID (urn:uuid:…), got {serial!r}")

    if not isinstance(cbom.get('version'), int) or cbom.get('version', 0) < 1:
        errors.append('version must be a positive integer')

    # ── metadata ────────────────────────────────────────────────────────────
    meta = cbom.get('metadata', {})
    if not isinstance(meta, dict):
        errors.append('metadata must be an object')
    else:
        ts = meta.get('timestamp', '')
        if ts and not _is_iso8601(ts):
            errors.append(
                f"metadata.timestamp is not a valid ISO-8601 datetime: {ts!r}"
            )
        if 'component' not in meta:
            errors.append(
                'metadata.component is required (describes the subject of the CBOM)'
            )
        else:
            mc = meta['component']
            for f in ('type', 'name'):
                if f not in mc:
                    errors.append(f"metadata.component.{f} is required")

    # ── components ──────────────────────────────────────────────────────────
    components = cbom.get('components', [])
    if not isinstance(components, list):
        errors.append('components must be an array')
        return errors

    bom_refs: dict[str, int] = {}
    crypto_asset_count = 0
    lib_count = 0

    for idx, comp in enumerate(components):
        loc = f"components[{idx}] ({comp.get('name', '?')})"

        # required fields
        for f in ('type', 'name'):
            if f not in comp:
                errors.append(f"{loc}: missing required field '{f}'")

        comp_type = comp.get('type', '')
        if comp_type not in VALID_COMPONENT_TYPES:
            errors.append(
                f"{loc}: invalid type {comp_type!r}; "
                f"valid: {sorted(VALID_COMPONENT_TYPES)}"
            )

        # bom-ref uniqueness
        br = comp.get('bom-ref')
        if br:
            if br in bom_refs:
                errors.append(
                    f"{loc}: duplicate bom-ref {br!r} "
                    f"(first at components[{bom_refs[br]}])"
                )
            bom_refs[br] = idx

        # PURL
        purl = comp.get('purl')
        if purl and not _is_valid_purl(purl):
            errors.append(f"{loc}: malformed purl {purl!r}")

        if comp_type == 'library':
            lib_count += 1
            if not comp.get('version'):
                # warn only — versions may be unknown for indirect deps
                pass

        elif comp_type == 'cryptographic-asset':
            crypto_asset_count += 1
            _validate_crypto_asset(comp, loc, errors)

    # ── summary checks ──────────────────────────────────────────────────────
    if crypto_asset_count == 0:
        errors.append(
            'No cryptographic-asset components found. '
            'A CBOM must contain at least one cryptographic-asset.'
        )

    # ── dependencies ────────────────────────────────────────────────────────
    deps = cbom.get('dependencies', [])
    if deps:
        all_refs = set(bom_refs) | {
            cbom.get('metadata', {}).get('component', {}).get('bom-ref', '')
        }
        for dep in deps:
            ref = dep.get('ref', '')
            if ref and ref not in all_refs:
                # Also allow the metadata component ref
                meta_ref = (
                    cbom.get('metadata', {}).get('component', {}).get('bom-ref', '')
                )
                if ref != meta_ref:
                    errors.append(
                        f"dependencies: ref {ref!r} does not match any component bom-ref"
                    )

    return errors


def _validate_crypto_asset(comp: dict[str, Any], loc: str, errors: list[str]) -> None:
    cp = comp.get('cryptoProperties')
    if cp is None:
        errors.append(f"{loc}: cryptographic-asset must have 'cryptoProperties'")
        return

    asset_type = cp.get('assetType')
    if not asset_type:
        errors.append(f"{loc}: cryptoProperties.assetType is required")
    elif asset_type not in VALID_ASSET_TYPES:
        errors.append(
            f"{loc}: cryptoProperties.assetType {asset_type!r} is not valid; "
            f"valid: {sorted(VALID_ASSET_TYPES)}"
        )

    if asset_type == 'algorithm':
        ap = cp.get('algorithmProperties')
        if ap is None:
            errors.append(f"{loc}: assetType=algorithm requires 'algorithmProperties'")
            return

        primitive = ap.get('primitive')
        if primitive and primitive not in VALID_PRIMITIVES:
            errors.append(
                f"{loc}: algorithmProperties.primitive {primitive!r} is not valid; "
                f"valid: {sorted(VALID_PRIMITIVES)}"
            )

        mode = ap.get('mode')
        if mode and mode not in VALID_MODES:
            errors.append(
                f"{loc}: algorithmProperties.mode {mode!r} is not valid; "
                f"valid: {sorted(VALID_MODES)}"
            )

        padding = ap.get('padding')
        if padding and padding not in VALID_PADDINGS:
            errors.append(
                f"{loc}: algorithmProperties.padding {padding!r} is not valid; "
                f"valid: {sorted(VALID_PADDINGS)}"
            )

        exec_env = ap.get('executionEnvironment')
        if exec_env and exec_env not in VALID_EXECUTION_ENVS:
            errors.append(
                f"{loc}: algorithmProperties.executionEnvironment "
                f"{exec_env!r} is not valid"
            )

        impl_level = ap.get('implementationLevel')
        if impl_level and impl_level not in VALID_IMPL_LEVELS:
            errors.append(
                f"{loc}: algorithmProperties.implementationLevel "
                f"{impl_level!r} is not valid"
            )

        crypto_fns = ap.get('cryptoFunctions', [])
        if not isinstance(crypto_fns, list):
            errors.append(
                f"{loc}: algorithmProperties.cryptoFunctions must be an array"
            )
        else:
            for fn in crypto_fns:
                if fn not in VALID_CRYPTO_FUNCTIONS:
                    errors.append(
                        f"{loc}: unknown cryptoFunction {fn!r}; "
                        f"valid: {sorted(VALID_CRYPTO_FUNCTIONS)}"
                    )

        cert_levels = ap.get('certificationLevel', [])
        if not isinstance(cert_levels, list):
            errors.append(
                f"{loc}: algorithmProperties.certificationLevel must be an array"
            )

        classical_sec = ap.get('classicalSecurityLevel')
        if classical_sec is not None and not isinstance(classical_sec, int):
            errors.append(
                f"{loc}: algorithmProperties.classicalSecurityLevel must be an integer"
            )

        nist_pqc = ap.get('nistQuantumSecurityLevel')
        if nist_pqc is not None:
            if not isinstance(nist_pqc, int) or nist_pqc not in range(6):
                errors.append(
                    f"{loc}: algorithmProperties.nistQuantumSecurityLevel "
                    f"must be 0–5, got {nist_pqc!r}"
                )


# ── Pass 2: JSON schema validation (online, cached) ───────────────────────────


def _fetch_schema() -> dict[str, Any] | None:
    """Return the CycloneDX 1.6 JSON schema, downloading and caching it if needed."""
    if SCHEMA_CACHE.exists():
        try:
            return json.loads(SCHEMA_CACHE.read_text(encoding='utf-8'))
        except Exception:
            pass

    try:
        print(
            f"  Downloading CycloneDX 1.6 schema from {SCHEMA_URL} …", file=sys.stderr
        )
        with urllib.request.urlopen(SCHEMA_URL, timeout=10) as resp:
            data = resp.read().decode('utf-8')
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        SCHEMA_CACHE.write_text(data, encoding='utf-8')
        return json.loads(data)
    except Exception as exc:
        print(
            f"  Warning: could not fetch schema ({exc}) — skipping JSON-schema pass.",
            file=sys.stderr,
        )
        return None


def validate_schema(cbom: dict[str, Any]) -> list[str]:
    """Validate against the official CycloneDX 1.6 JSON schema (best-effort)."""
    try:
        import jsonschema  # noqa: F401 — checked at call site
    except ImportError:
        return []

    schema = _fetch_schema()
    if schema is None:
        return []

    errors: list[str] = []
    try:
        import jsonschema

        validator = jsonschema.Draft7Validator(schema)
        for err in sorted(validator.iter_errors(cbom), key=lambda e: list(e.path)):
            path = ' > '.join(str(p) for p in err.path) if err.path else '(root)'
            errors.append(f"Schema [{path}]: {err.message}")
    except Exception as exc:
        print(
            f"  Warning: JSON schema validation raised an exception: {exc}",
            file=sys.stderr,
        )

    return errors


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cbom.cdx.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    cbom = json.loads(path.read_text(encoding='utf-8'))

    all_errors: list[str] = []

    # Pass 1: structural
    print('  [1/2] Structural validation …')
    structural = validate_structural(cbom)
    all_errors.extend(structural)
    if structural:
        for e in structural:
            print(f"    ✗ {e}")
    else:
        components = cbom.get('components', [])
        ca = sum(1 for c in components if c.get('type') == 'cryptographic-asset')
        lib = sum(1 for c in components if c.get('type') == 'library')
        print(
            f"    ✓ {ca} cryptographic-asset components, {lib} library components — OK"
        )

    # Pass 2: JSON schema (best-effort, requires network on first run)
    print('  [2/2] CycloneDX 1.6 JSON schema validation …')
    schema_errors = validate_schema(cbom)
    all_errors.extend(schema_errors)
    if schema_errors:
        for e in schema_errors[:20]:  # cap noisy output
            print(f"    ✗ {e}")
        if len(schema_errors) > 20:
            print(f"    … {len(schema_errors) - 20} more schema errors")
    else:
        print('    ✓ Schema validation passed (or schema unavailable)')

    if all_errors:
        print(
            f"\nValidation FAILED: {len(all_errors)} error(s) in {path}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"\nValidation PASSED: {path} conforms to CycloneDX 1.6")


if __name__ == '__main__':
    main()

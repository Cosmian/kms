#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Add NVD NIST CPE 2.3 identifiers to every component in bom.cdx.json
that lacks one.

Required by the Eviden PSIRT tooling service for vulnerability profiling.

Vendor derivation priority
--------------------------
1. ``cpe_overrides.json`` (manual overrides keyed by component name)
2. GitHub organisation extracted from the VCS URL in the cargo-sbom JSON
   (``externalReferences[type=vcs].url``)
3. ``author`` field from the cargo-sbom JSON component
4. Component name (fallback — ensures 100% coverage)

The generated CPE follows the WFN binding defined in NISTIR 7695:
  ``cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*``

Usage
-----
    python3 enrich_cpe.py \\
        --sbom-dir sbom/server/non-fips/dynamic \\
        --cargo-sbom-json /tmp/cargo-sbom.json \\
        --in-place
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# CPE string helpers
# ---------------------------------------------------------------------------

# Characters that are valid in a CPE attribute value (after lower-casing).
# Any other character is replaced with an underscore per NISTIR 7695 §6.2.
_CPE_INVALID = re.compile(r'[^a-z0-9._\-]')


def _cpe_sanitize(value: str) -> str:
    """Lower-case *value* and replace characters invalid in a CPE attribute."""
    return _CPE_INVALID.sub('_', value.lower()).strip('_') or 'unknown'


def _make_cpe(vendor: str, product: str, version: str) -> str:
    """Build a CPE 2.3 formatted string (NISTIR 7695 WFN binding)."""
    v = _cpe_sanitize(vendor)
    p = _cpe_sanitize(product)
    # CPE versions must not start with 'v' or 'V'.
    ver = _cpe_sanitize(version.lstrip('vV') or '*')
    return f'cpe:2.3:a:{v}:{p}:{ver}:*:*:*:*:*:*:*'


# ---------------------------------------------------------------------------
# Vendor derivation helpers
# ---------------------------------------------------------------------------

_GITHUB_ORG_RE = re.compile(r'https?://github\.com/([^/]+)/', re.IGNORECASE)


def _github_org(url: str) -> Optional[str]:
    """Return the GitHub organisation from *url*, or ``None``."""
    m = _GITHUB_ORG_RE.search(url)
    return m.group(1) if m else None


def _vcs_org_from_component(cargo_comp: dict) -> Optional[str]:
    """Extract a GitHub org from the ``externalReferences`` of a cargo-sbom
    component dict, or ``None`` if not found."""
    for ref in cargo_comp.get('externalReferences', []):
        if ref.get('type') == 'vcs':
            org = _github_org(ref.get('url', ''))
            if org:
                return org
    return None


def _author_from_component(cargo_comp: dict) -> Optional[str]:
    """Return the first token of the ``author`` field, or ``None``."""
    author = cargo_comp.get('author') or cargo_comp.get('authors', '')
    if isinstance(author, list):
        author = author[0] if author else ''
    if not author:
        return None
    # 'Author Name <email@example.com>' → 'Author'
    author = author.split('<')[0].strip()
    return author.split()[0] if author else None


# ---------------------------------------------------------------------------
# cargo-sbom index builder
# ---------------------------------------------------------------------------


def _build_cargo_index(cargo_sbom_json: Optional[Path]) -> dict[str, dict]:
    """Parse *cargo_sbom_json* (CycloneDX JSON emitted by cargo-sbom) and
    return a mapping ``{name: component_dict}`` for quick lookup.

    Returns an empty dict on any error (the fallback chain still works).
    """
    if not cargo_sbom_json or not cargo_sbom_json.exists():
        return {}
    try:
        with open(cargo_sbom_json, encoding='utf-8') as fh:
            data = json.load(fh)
        index: dict[str, dict] = {}
        for comp in data.get('components', []):
            name = comp.get('name', '')
            if name:
                index[name] = comp
        return index
    except Exception as exc:  # pylint: disable=broad-except
        print(f'  ⚠ Could not parse cargo-sbom JSON: {exc}', file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# CPE overrides
# ---------------------------------------------------------------------------


def _load_overrides(sbom_dir: Path) -> dict[str, str]:
    """Load ``cpe_overrides.json`` from *sbom_dir* if it exists.

    The file maps component names to full CPE strings, e.g.::

        {
          "openssl": "cpe:2.3:a:openssl:openssl:3.1.2:*:*:*:*:*:*:*",
          "glibc":   "cpe:2.3:a:gnu:glibc:2.34:*:*:*:*:*:*:*"
        }
    """
    override_path = sbom_dir / 'cpe_overrides.json'
    if not override_path.exists():
        return {}
    try:
        with open(override_path, encoding='utf-8') as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items()}
    except Exception as exc:  # pylint: disable=broad-except
        print(f'  ⚠ Could not load cpe_overrides.json: {exc}', file=sys.stderr)
        return {}


# ---------------------------------------------------------------------------
# Per-component vendor resolution
# ---------------------------------------------------------------------------


def _resolve_vendor(
    name: str,
    overrides: dict[str, str],
    cargo_index: dict[str, dict],
) -> Optional[str]:
    """Return the vendor string for *name* using the priority chain, or
    ``None`` to fall back to the component name itself."""
    # Priority 1: manual override provides the complete CPE string → signal
    # caller by returning the literal override value (detected upstream).
    if name in overrides:
        return None  # handled by caller

    # Priority 2: GitHub org from VCS URL in cargo-sbom metadata
    cargo_comp = cargo_index.get(name, {})
    org = _vcs_org_from_component(cargo_comp)
    if org:
        return org

    # Priority 3: author from cargo-sbom metadata
    author = _author_from_component(cargo_comp)
    if author:
        return author

    # Priority 4: fall back to component name
    return None


# ---------------------------------------------------------------------------
# Main enrichment logic
# ---------------------------------------------------------------------------


def enrich(
    sbom_dir: Path,
    cargo_sbom_json: Optional[Path],
    in_place: bool,
) -> None:
    """Enrich ``bom.cdx.json`` in *sbom_dir* with CPE 2.3 identifiers."""
    cdx_path = sbom_dir / 'bom.cdx.json'
    if not cdx_path.exists():
        print(f'  ⚠ {cdx_path} not found — skipping CPE enrichment', file=sys.stderr)
        return

    overrides = _load_overrides(sbom_dir)
    cargo_index = _build_cargo_index(cargo_sbom_json)

    with open(cdx_path, encoding='utf-8') as fh:
        bom = json.load(fh)

    components = bom.get('components', [])
    enriched = 0
    skipped = 0

    for comp in components:
        if comp.get('cpe'):
            skipped += 1
            continue  # already has a CPE

        name = comp.get('name', 'unknown')
        version = comp.get('version', '*')

        # Priority 1: manual override
        if name in overrides:
            comp['cpe'] = overrides[name]
            enriched += 1
            continue

        # Priority 2–4: derive vendor
        vendor = _resolve_vendor(name, overrides, cargo_index) or name
        comp['cpe'] = _make_cpe(vendor, name, version)
        enriched += 1

    total = len(components)
    print(
        f'  CPE enrichment: {enriched} added, {skipped} already present'
        f' ({total} total components)'
    )

    if in_place:
        output_path = cdx_path
    else:
        output_path = sbom_dir / 'bom.cdx.enriched.json'

    with open(output_path, 'w', encoding='utf-8') as fh:
        json.dump(bom, fh, indent=2, ensure_ascii=False)
        fh.write('\n')

    print(f'  ✓ Written: {output_path}')


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Add CPE 2.3 identifiers to bom.cdx.json components.',
    )
    parser.add_argument(
        '--sbom-dir',
        required=True,
        type=Path,
        help='Directory containing bom.cdx.json (and optionally cpe_overrides.json).',
    )
    parser.add_argument(
        '--cargo-sbom-json',
        type=Path,
        default=None,
        help='Path to cargo-sbom CycloneDX JSON for VCS/author metadata (optional).',
    )
    parser.add_argument(
        '--in-place',
        action='store_true',
        help='Overwrite bom.cdx.json in place (default: write bom.cdx.enriched.json).',
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    sbom_dir: Path = args.sbom_dir
    if not sbom_dir.is_dir():
        print(f'ERROR: --sbom-dir {sbom_dir} is not a directory', file=sys.stderr)
        sys.exit(1)

    enrich(
        sbom_dir=sbom_dir,
        cargo_sbom_json=args.cargo_sbom_json,
        in_place=args.in_place,
    )


if __name__ == '__main__':
    main()

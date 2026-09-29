#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enrich SBOM files (CycloneDX / SPDX) with author/supplier information and
add Rust crate + npm components that sbomnix does not capture.

Architecture
------------
sbomnix only scans the Nix store closure → it captures system-level runtime
libraries (glibc, openssl, libidn2…) but **not** the 500+ Rust crates that are
statically compiled into the binary, nor the npm packages in the UI.

This script fills that gap in three steps:

  1. **Rust crates** – parses ``Cargo.lock`` to get every third-party crate,
     resolves author/supplier metadata from the local cargo registry cache
     (~/.cargo/registry) that is already populated after ``cargo build``.
     Falls back to a single crates.io API call per crate when the local cache
     has no author data.

  2. **npm/pnpm packages** – parses ``ui/pnpm-lock.yaml`` to list every
     third-party UI dependency, reads ``ui/node_modules/<pkg>/package.json``
     for author info.

  3. **CycloneDX / SPDX enrichment** – for each component already in the BOM
     (from sbomnix), adds the ``supplier`` field (CycloneDX) or ``originator``
     field (SPDX) if it is missing.  Then appends the Rust + npm components as
     new entries.

The script writes enriched copies alongside the originals:
  - ``bom.cdx.json``  →  ``bom.cdx.enriched.json``
  - ``bom.spdx.json`` →  ``bom.spdx.enriched.json``

Usage
-----
    # Enrich a specific SBOM directory
    python3 enrich_sbom_authors.py --sbom-dir sbom/server/non-fips/dynamic

    # Enrich and overwrite in-place
    python3 enrich_sbom_authors.py --sbom-dir sbom/server/non-fips/dynamic --in-place

    # Skip npm enrichment (UI not built yet)
    python3 enrich_sbom_authors.py --sbom-dir sbom/server/non-fips/dynamic --no-npm

    # Limit crates.io API fallback calls (useful in CI with low rate-limit budget)
    python3 enrich_sbom_authors.py --sbom-dir sbom/server/non-fips/dynamic --api-limit 50

Crates.io rate limit
--------------------
crates.io allows 100 req/s with a valid User-Agent.  The script batches local
cache reads first (no network) and only calls the API for crates whose
Cargo.toml ``authors`` field is empty.  A disk-level cache
(``/tmp/cosmian-kms-sbom-authors.json``) prevents redundant calls across runs.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRATES_IO_API = 'https://crates.io/api/v1/crates'
NPM_REGISTRY_API = 'https://registry.npmjs.org'
USER_AGENT = 'Cosmian-KMS-SBOM-Enricher/1.0 (security@cosmian.com)'
API_CACHE_PATH = Path('/tmp/cosmian-kms-sbom-authors.json')
REQUEST_DELAY = 0.1  # seconds between API calls to stay well under rate limits

COSMIAN_PREFIXES = (
    'cosmian_',
    'cosmian-',
    'ckms',
    'kmip-derive',
    'test_kms_server',
    'proteccio_pkcs11',
    'softhsm2_pkcs11',
    'utimaco_pkcs11',
    'smartcardhsm_pkcs11',
    'crypt2pay_pkcs11',
)


# ---------------------------------------------------------------------------
# Source 1 – Rust crate metadata
# ---------------------------------------------------------------------------


def _is_cosmian_crate(name: str) -> bool:
    return any(name.startswith(p) for p in COSMIAN_PREFIXES)


def _parse_cargo_lock(repo_root: Path) -> list[tuple[str, str]]:
    """Return list of (name, version) for every third-party crate in Cargo.lock."""
    lock_path = repo_root / 'Cargo.lock'
    if not lock_path.exists():
        print(f"  ⚠  Cargo.lock not found at {lock_path}", file=sys.stderr)
        return []

    content = lock_path.read_text()
    pattern = (
        r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"'
        r'(?:\nsource = "([^"]+)")?'
    )
    crates = []
    for name, version, source in re.findall(pattern, content):
        if source and source.startswith('registry') and not _is_cosmian_crate(name):
            crates.append((name, version))
    return crates


def _read_cargo_toml_from_cache(name: str, version: str) -> dict[str, str]:
    """Read Cargo.toml from the local cargo registry cache.

    Returns a dict with keys: authors, license, repository, description.
    All values may be empty strings.
    """
    registry_base = Path.home() / '.cargo' / 'registry' / 'src'
    # There may be multiple index directories; search all of them.
    for index_dir in sorted(registry_base.iterdir()) if registry_base.exists() else []:
        toml_path = index_dir / f"{name}-{version}" / 'Cargo.toml'
        if not toml_path.exists():
            continue
        text = toml_path.read_text(errors='replace')

        authors_m = re.search(r'authors\s*=\s*\[([^\]]*)\]', text, re.DOTALL)
        license_m = re.search(r'^license\s*=\s*"([^"]+)"', text, re.MULTILINE)
        repo_m = re.search(r'^repository\s*=\s*"([^"]+)"', text, re.MULTILINE)
        desc_m = re.search(r'^description\s*=\s*"([^"]+)"', text, re.MULTILINE)

        raw_authors = authors_m.group(1) if authors_m else ''
        author_list = re.findall(r'"([^"]+)"', raw_authors)
        # Strip email addresses: "Alice <alice@example.com>" → "Alice"
        clean = [re.sub(r'\s*<[^>]+>', '', a).strip() for a in author_list]
        clean = [a for a in clean if a]

        return {
            'authors': ', '.join(clean),
            'license': license_m.group(1) if license_m else '',
            'repository': repo_m.group(1) if repo_m else '',
            'description': (desc_m.group(1) if desc_m else '')[:120],
        }
    return {'authors': '', 'license': '', 'repository': '', 'description': ''}


def _api_fetch_crate_info(name: str, api_cache: dict[str, dict]) -> dict[str, str]:
    """Query crates.io for owner/author info. Results are cached in api_cache."""
    if name in api_cache:
        return api_cache[name]

    info: dict[str, str] = {'authors': '', 'repository': '', 'description': ''}
    try:
        url = f"{CRATES_IO_API}/{name}"
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        crate = data.get('crate', {})
        info['repository'] = crate.get('repository') or ''
        info['description'] = (crate.get('description') or '')[:120]

        # Fetch owners (separate endpoint)
        time.sleep(REQUEST_DELAY)
        owners_url = f"{CRATES_IO_API}/{name}/owners"
        req2 = urllib.request.Request(owners_url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req2, timeout=10) as resp2:
            owners_data = json.loads(resp2.read())
        owners = owners_data.get('users', []) + owners_data.get('teams', [])
        names = [
            o.get('name') or o.get('login') or ''
            for o in owners
            if o.get('name') or o.get('login')
        ]
        info['authors'] = ', '.join(n for n in names if n)

    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
        print(f"  ⚠  crates.io API failed for {name}: {exc}", file=sys.stderr)

    api_cache[name] = info
    return info


def collect_rust_crate_metadata(
    repo_root: Path,
    api_limit: int = 0,
) -> list[dict]:
    """Return a list of component dicts for every third-party Rust crate."""
    crates = _parse_cargo_lock(repo_root)
    print(f"  → {len(crates)} third-party Rust crates found in Cargo.lock")

    # Load API cache from disk
    api_cache: dict[str, dict] = {}
    if API_CACHE_PATH.exists():
        try:
            api_cache = json.loads(API_CACHE_PATH.read_text())
        except json.JSONDecodeError:
            pass

    api_calls = 0
    components = []

    for name, version in crates:
        meta = _read_cargo_toml_from_cache(name, version)

        # Fall back to crates.io API if authors are missing and budget allows
        if not meta['authors'] and api_calls < api_limit:
            api_info = _api_fetch_crate_info(name, api_cache)
            api_calls += 1
            time.sleep(REQUEST_DELAY)
            if not meta['repository']:
                meta['repository'] = api_info.get('repository', '')
            if not meta['description']:
                meta['description'] = api_info.get('description', '')
            meta['authors'] = api_info.get('authors', '')

        components.append(
            {
                'ecosystem': 'cargo',
                'name': name,
                'version': version,
                'authors': meta['authors'],
                'license': meta['license'],
                'repository': meta['repository'],
                'description': meta['description'],
                'purl': f"pkg:cargo/{name}@{version}",
            }
        )

    # Persist API cache
    if api_calls > 0:
        API_CACHE_PATH.write_text(json.dumps(api_cache, indent=2))
        print(
            f"  → {api_calls} crates.io API calls made, cache saved to {API_CACHE_PATH}"
        )

    return components


# ---------------------------------------------------------------------------
# Source 2 – npm/pnpm package metadata
# ---------------------------------------------------------------------------


def collect_npm_metadata(repo_root: Path, api_limit: int = 0) -> list[dict]:
    """Return a list of component dicts for third-party npm packages.

    Author data is resolved in priority order:
    1. ``ui/node_modules/<pkg>/package.json`` — already present after ``pnpm install``
    2. npm registry API (``https://registry.npmjs.org/<pkg>``) — opt-in via api_limit > 0
    """
    lock_path = repo_root / 'ui' / 'pnpm-lock.yaml'
    if not lock_path.exists():
        print(
            '  ⚠  ui/pnpm-lock.yaml not found, skipping npm enrichment', file=sys.stderr
        )
        return []

    # Parse pnpm-lock.yaml minimally: extract package names and versions.
    # We avoid a full YAML parser to stay dependency-free.
    content = lock_path.read_text()
    # pnpm-lock.yaml v6+ format: lines like "  /package@version:"
    # or in lockfileVersion 9: "  package@version:" under "packages:"
    pattern = re.compile(r'^\s{2}/?(@?[a-zA-Z0-9@/_.-]+)@([^:\s]+):', re.MULTILINE)
    seen: set[tuple[str, str]] = set()
    for m in pattern.finditer(content):
        name, version = m.group(1), m.group(2)
        if not name.startswith('cosmian') and (name, version) not in seen:
            seen.add((name, version))

    print(f"  → {len(seen)} third-party npm packages found in pnpm-lock.yaml")

    # Load shared API cache (shared with crates.io entries under "npm:<name>" key)
    api_cache: dict[str, dict] = {}
    if API_CACHE_PATH.exists():
        try:
            api_cache = json.loads(API_CACHE_PATH.read_text())
        except json.JSONDecodeError:
            pass

    node_modules = repo_root / 'ui' / 'node_modules'
    api_calls = 0
    components = []

    for name, version in sorted(seen):
        pkg_json_path = node_modules / name / 'package.json'
        author = ''
        license = ''
        description = ''
        repository = ''

        if pkg_json_path.exists():
            try:
                pkg = json.loads(pkg_json_path.read_text())
                raw_author = pkg.get('author', '')
                if isinstance(raw_author, dict):
                    author = raw_author.get('name', '')
                elif isinstance(raw_author, str):
                    author = re.sub(r'\s*<[^>]+>', '', raw_author).strip()
                # Also check "contributors"
                if not author:
                    contribs = pkg.get('contributors', [])
                    if contribs and isinstance(contribs[0], dict):
                        author = contribs[0].get('name', '')
                    elif contribs and isinstance(contribs[0], str):
                        author = contribs[0]
                license = pkg.get('license', '')
                description = (pkg.get('description') or '')[:120]
                repo = pkg.get('repository', '')
                if isinstance(repo, dict):
                    repository = repo.get('url', '')
                elif isinstance(repo, str):
                    repository = repo
            except (json.JSONDecodeError, OSError):
                pass

        # Fall back to npm registry API for missing author info
        if not author and api_calls < api_limit:
            cache_key = f"npm:{name}"
            if cache_key in api_cache:
                npm_info = api_cache[cache_key]
            else:
                npm_info = _api_fetch_npm_info(name)
                api_cache[cache_key] = npm_info
                api_calls += 1
                time.sleep(REQUEST_DELAY)
            if not author:
                author = npm_info.get('authors', '')
            if not repository:
                repository = npm_info.get('repository', '')
            if not description:
                description = npm_info.get('description', '')

        components.append(
            {
                'ecosystem': 'npm',
                'name': name,
                'version': version,
                'authors': author,
                'license': license if isinstance(license, str) else '',
                'repository': repository,
                'description': description,
                'purl': f"pkg:npm/{name}@{version}",
            }
        )

    if api_calls > 0:
        API_CACHE_PATH.write_text(json.dumps(api_cache, indent=2))
        print(
            f"  → {api_calls} npm registry API calls made, cache saved to {API_CACHE_PATH}"
        )

    return components


def _api_fetch_npm_info(name: str) -> dict[str, str]:
    """Query the npm registry for maintainer/author info."""
    info: dict[str, str] = {'authors': '', 'repository': '', 'description': ''}
    try:
        url = f"{NPM_REGISTRY_API}/{urllib.parse.quote(name, safe='@')}"
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())

        info['description'] = (data.get('description') or '')[:120]

        # repository
        repo = data.get('repository', {})
        if isinstance(repo, dict):
            info['repository'] = repo.get('url', '')
        elif isinstance(repo, str):
            info['repository'] = repo

        # maintainers (most reliable source)
        maintainers = data.get('maintainers', [])
        names = []
        for m in maintainers[:5]:  # cap at 5
            if isinstance(m, dict):
                n = m.get('name') or m.get('username') or ''
                if n:
                    names.append(n)
        if names:
            info['authors'] = ', '.join(names)

        # fall back to author field
        if not info['authors']:
            raw = data.get('author', '')
            if isinstance(raw, dict):
                info['authors'] = raw.get('name', '')
            elif isinstance(raw, str):
                info['authors'] = re.sub(r'\s*<[^>]+>', '', raw).strip()

    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as exc:
        print(f"  ⚠  npm registry API failed for {name}: {exc}", file=sys.stderr)

    return info


# ---------------------------------------------------------------------------
# CycloneDX enrichment
# ---------------------------------------------------------------------------


def _make_cdx_component(comp: dict) -> dict:
    """Convert a generic component dict to a CycloneDX 1.5 component object."""
    cdx: dict = {
        'type': 'library',
        'bom-ref': f"{comp['purl']}",
        'name': comp['name'],
        'version': comp['version'],
        'purl': comp['purl'],
    }
    if comp['description']:
        cdx['description'] = comp['description']
    if comp['license']:
        cdx['licenses'] = [{'license': {'id': comp['license']}}]
    if comp['authors']:
        cdx['supplier'] = {'name': comp['authors']}
    if comp['repository']:
        cdx['externalReferences'] = [{'type': 'vcs', 'url': comp['repository']}]
    return cdx


def enrich_cyclonedx(
    bom_path: Path,
    rust_components: list[dict],
    npm_components: list[dict],
    in_place: bool = False,
) -> Path:
    """Enrich a CycloneDX JSON SBOM with Rust + npm components and author data."""
    bom = json.loads(bom_path.read_text())

    # Upgrade specVersion to 1.5 to support supplier field
    bom['specVersion'] = '1.5'

    # Enrich existing sbomnix components with supplier info
    for comp in bom.get('components', []):
        if 'supplier' not in comp:
            # For system libs we know the supplier
            name_lower = comp.get('name', '').lower()
            supplier = _known_system_supplier(name_lower)
            if supplier:
                comp['supplier'] = {'name': supplier}

    # Build a set of already-present purls to avoid duplicates
    existing_purls = {c.get('purl', '') for c in bom.get('components', [])}

    new_components = []
    for comp in rust_components + npm_components:
        if comp['purl'] not in existing_purls:
            new_components.append(_make_cdx_component(comp))
            existing_purls.add(comp['purl'])

    bom.setdefault('components', []).extend(new_components)

    out_path = bom_path if in_place else bom_path.with_suffix('.enriched.json')
    # Preserve the .cdx suffix in the enriched name
    if not in_place and bom_path.name == 'bom.cdx.json':
        out_path = bom_path.parent / 'bom.cdx.enriched.json'

    out_path.write_text(json.dumps(bom, indent=2, ensure_ascii=False))
    print(f"  ✓ CycloneDX enriched → {out_path} (+{len(new_components)} components)")
    return out_path


# ---------------------------------------------------------------------------
# SPDX enrichment
# ---------------------------------------------------------------------------


def _make_spdx_package(comp: dict, idx: int) -> dict:
    """Convert a generic component dict to an SPDX 2.3 package object."""
    safe_name = re.sub(r'[^a-zA-Z0-9\-]', '-', f"{comp['name']}-{comp['version']}")
    pkg: dict = {
        'name': comp['name'],
        'SPDXID': f"SPDXRef-{comp['ecosystem']}-{safe_name}-{idx}",
        'versionInfo': comp['version'],
        'downloadLocation': comp['repository'] or 'NOASSERTION',
        'licenseConcluded': comp['license'] or 'NOASSERTION',
        'licenseDeclared': comp['license'] or 'NOASSERTION',
        'copyrightText': 'NOASSERTION',
    }
    if comp['authors']:
        # SPDX 2.3: originator field accepts "Organization: ..." or "Person: ..."
        pkg['originator'] = f"Organization: {comp['authors']}"
        pkg['supplier'] = f"Organization: {comp['authors']}"
    if comp['description']:
        pkg['comment'] = comp['description']
    pkg['externalRefs'] = [
        {
            'referenceCategory': 'PACKAGE-MANAGER',
            'referenceType': 'purl',
            'referenceLocator': comp['purl'],
        }
    ]
    return pkg


def enrich_spdx(
    bom_path: Path,
    rust_components: list[dict],
    npm_components: list[dict],
    in_place: bool = False,
) -> Path:
    """Enrich an SPDX JSON SBOM with Rust + npm packages and originator/supplier data."""
    bom = json.loads(bom_path.read_text())

    # Enrich existing sbomnix packages with originator/supplier info
    for pkg in bom.get('packages', []):
        if 'originator' not in pkg and 'supplier' not in pkg:
            name_lower = pkg.get('name', '').lower()
            supplier = _known_system_supplier(name_lower)
            if supplier:
                pkg['supplier'] = f"Organization: {supplier}"
                pkg['originator'] = f"Organization: {supplier}"

    # Collect existing package names+versions to avoid duplicates
    existing = {
        (p.get('name', ''), p.get('versionInfo', '')) for p in bom.get('packages', [])
    }

    new_packages = []
    for idx, comp in enumerate(rust_components + npm_components):
        key = (comp['name'], comp['version'])
        if key not in existing:
            new_packages.append(_make_spdx_package(comp, idx))
            existing.add(key)
        elif comp['authors']:
            # Enrich existing package if it lacks author info
            for pkg in bom.get('packages', []):
                if (
                    pkg.get('name') == comp['name']
                    and pkg.get('versionInfo') == comp['version']
                ):
                    if 'originator' not in pkg:
                        pkg['originator'] = f"Organization: {comp['authors']}"
                        pkg['supplier'] = f"Organization: {comp['authors']}"

    bom.setdefault('packages', []).extend(new_packages)

    # Add relationships for new packages
    doc_id = bom.get('SPDXID', 'SPDXRef-DOCUMENT')
    root_pkg = next(
        (
            p['SPDXID']
            for p in bom.get('packages', [])
            if 'cosmian' in p.get('name', '').lower()
        ),
        doc_id,
    )
    new_rels = [
        {
            'spdxElementId': root_pkg,
            'relationshipType': (
                'DYNAMIC_LINK' if comp['ecosystem'] == 'npm' else 'STATIC_LINK'
            ),
            'relatedSpdxElement': pkg['SPDXID'],
        }
        for comp, pkg in zip(
            rust_components + npm_components,
            new_packages,
        )
    ]
    bom.setdefault('relationships', []).extend(new_rels)

    out_path = bom_path if in_place else bom_path.with_suffix('.enriched.json')
    if not in_place and bom_path.name == 'bom.spdx.json':
        out_path = bom_path.parent / 'bom.spdx.enriched.json'

    out_path.write_text(json.dumps(bom, indent=2, ensure_ascii=False))
    print(f"  ✓ SPDX enriched     → {out_path} (+{len(new_packages)} packages)")
    return out_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _known_system_supplier(name: str) -> Optional[str]:
    """Return the known supplier for a well-known system library name."""
    mapping = {
        'glibc': 'Free Software Foundation (GNU)',
        'libidn2': 'Free Software Foundation (GNU)',
        'libunistring': 'Free Software Foundation (GNU)',
        'openssl': 'OpenSSL Software Foundation',
    }
    return mapping.get(name)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Enrich SBOM files with author/supplier information and Rust/npm components.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--sbom-dir',
        default='sbom/server/non-fips/dynamic',
        help='Directory containing bom.cdx.json and bom.spdx.json (default: sbom/server/non-fips/dynamic)',
    )
    parser.add_argument(
        '--repo-root',
        default=None,
        help='Repository root (auto-detected from script location if not set)',
    )
    parser.add_argument(
        '--in-place',
        action='store_true',
        help='Overwrite bom.*.json files in-place instead of writing .enriched.json copies',
    )
    parser.add_argument(
        '--no-rust',
        action='store_true',
        help='Skip Rust crate enrichment',
    )
    parser.add_argument(
        '--no-npm',
        action='store_true',
        help='Skip npm/pnpm enrichment',
    )
    parser.add_argument(
        '--api-limit',
        type=int,
        default=0,
        metavar='N',
        help=(
            'Maximum number of registry API calls for missing author data '
            '(crates.io + npm registry). Default: 0 = local cache only. '
            'Use --api-limit 500 on release machines with internet access '
            'to reach ~100%% author coverage.'
        ),
    )
    args = parser.parse_args()

    # Resolve paths
    script_dir = Path(__file__).resolve().parent
    repo_root = (
        Path(args.repo_root) if args.repo_root else script_dir.parent.parent.parent
    )
    sbom_dir = (
        Path(args.sbom_dir)
        if Path(args.sbom_dir).is_absolute()
        else repo_root / args.sbom_dir
    )

    if not sbom_dir.exists():
        print(f"Error: SBOM directory not found: {sbom_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"Enriching SBOM in: {sbom_dir}")
    print(f"Repository root:   {repo_root}")
    print()

    # Collect component metadata
    rust_components: list[dict] = []
    npm_components: list[dict] = []

    if not args.no_rust:
        print('Collecting Rust crate metadata...')
        rust_components = collect_rust_crate_metadata(
            repo_root, api_limit=args.api_limit
        )
        print()

    if not args.no_npm:
        print('Collecting npm package metadata...')
        npm_components = collect_npm_metadata(repo_root, api_limit=args.api_limit)
        print()

    # Enrich CycloneDX
    cdx_path = sbom_dir / 'bom.cdx.json'
    if cdx_path.exists():
        print('Enriching CycloneDX SBOM...')
        enrich_cyclonedx(
            cdx_path, rust_components, npm_components, in_place=args.in_place
        )
    else:
        print(
            f"  ⚠  {cdx_path} not found, skipping CycloneDX enrichment", file=sys.stderr
        )

    print()

    # Enrich SPDX
    spdx_path = sbom_dir / 'bom.spdx.json'
    if spdx_path.exists():
        print('Enriching SPDX SBOM...')
        enrich_spdx(spdx_path, rust_components, npm_components, in_place=args.in_place)
    else:
        print(f"  ⚠  {spdx_path} not found, skipping SPDX enrichment", file=sys.stderr)

    print()
    print('Done.')


if __name__ == '__main__':
    main()

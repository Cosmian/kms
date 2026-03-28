#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Filter sbomnix/vulnxscan CSV vulnerability outputs.

Goals:
- Keep only advisories relevant to selected distros.
- Optionally restrict to "PC" architectures by joining against sbom.csv's
  "system" column (e.g., x86_64-linux).

This is intentionally conservative: it filters rows (advisories) and does not
attempt to deduplicate advisories into CVEs unless requested.
"""

from __future__ import annotations

import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

PC_SYSTEMS_DEFAULT = (
    'x86_64-linux',
    'i686-linux',
)


DISTRO_PREFIXES = {
    # Debian
    'debian': ('DSA-', 'DLA-', 'DEBIAN-CVE-'),
    # Ubuntu
    'ubuntu': ('USN-', 'UBUNTU-CVE-'),
    # Rocky / RHEL-family (Rocky advisories are typically RLSA; OSV also reports RHSA)
    'rocky': ('RLSA-', 'RHSA-'),
}


_CVE_RE = re.compile(r'CVE-\d{4}-\d+')
_CVE_PARTS_RE = re.compile(r'CVE-(\d{4})-(\d+)')


@dataclass(frozen=True)
class FilterConfig:
    allowed_distro_prefixes: tuple[str, ...]
    allowed_systems: tuple[str, ...] | None


def _canonical_cve_from_vuln_id(vuln_id: str) -> str | None:
    """Return canonical CVE key if vuln_id encodes a CVE.

    We intentionally keep this conservative and only canonicalize IDs that
    explicitly contain a CVE identifier, such as:
    - CVE-2026-1234
    - DEBIAN-CVE-2026-1234
    - UBUNTU-CVE-2026-1234
    """

    if not vuln_id:
        return None

    match = _CVE_PARTS_RE.search(vuln_id)
    if match:
        year, ident = match.group(1), match.group(2)
        # Dedup must be based on YEAR-ID, normalized so padding differences
        # like 0915 vs 915 collapse.
        return f'{year}-{int(ident)}'

    # Handle distro-prefixed CVE IDs like DEBIAN-CVE-2026-1234.
    if '-CVE-' in vuln_id:
        # Try again in case the ID is distro-prefixed and didn't match above.
        match = _CVE_PARTS_RE.search(vuln_id)
        if match:
            year, ident = match.group(1), match.group(2)
            return f'{year}-{int(ident)}'

    return None


def _dedup_by_cve(
    rows: Sequence[dict[str, str]], prefer_debian: bool
) -> list[dict[str, str]]:
    """Deduplicate CVE-like rows while keeping advisory rows.

    Only rows whose `vuln_id` encodes a CVE (see _canonical_cve_from_vuln_id)
    are deduplicated. Other advisory IDs (USN/RHSA/DSA/...) are preserved.

    Preference when multiple rows map to the same CVE:
    1) DEBIAN-CVE-* (if prefer_debian)
    2) CVE-* (plain)
    3) UBUNTU-CVE-*
    4) first encountered
    """

    # Key is YEAR-ID (normalized), e.g. "2026-915".
    best_for_cve: dict[str, dict[str, str]] = {}
    other_rows: list[dict[str, str]] = []

    def score(row: dict[str, str]) -> int:
        vuln_id = (row.get('vuln_id') or '').strip()
        if prefer_debian and vuln_id.startswith('DEBIAN-CVE-'):
            return 300
        if vuln_id.startswith('CVE-'):
            return 200
        if vuln_id.startswith('UBUNTU-CVE-'):
            return 100
        return 0

    for row in rows:
        vuln_id = (row.get('vuln_id') or '').strip()
        canonical = _canonical_cve_from_vuln_id(vuln_id)
        if canonical is None:
            other_rows.append(row)
            continue

        prev = best_for_cve.get(canonical)
        if prev is None or score(row) > score(prev):
            best_for_cve[canonical] = row

    # Keep stable-ish output: preserve original order for advisory rows,
    # then append chosen CVE rows in the order they first appeared.
    # We rebuild CVE order by re-scanning rows.
    ordered_cve_rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        canonical = _canonical_cve_from_vuln_id((row.get('vuln_id') or '').strip())
        if canonical is None or canonical in seen:
            continue
        chosen = best_for_cve.get(canonical)
        if chosen is not None:
            ordered_cve_rows.append(chosen)
            seen.add(canonical)

    return [*other_rows, *ordered_cve_rows]


def _read_sbom_allowed_pnames(
    sbom_csv: Path, allowed_systems: Sequence[str]
) -> set[str]:
    """Return set of pnames present for allowed systems."""
    allowed = set()
    with sbom_csv.open('r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return allowed
        if 'pname' not in reader.fieldnames or 'system' not in reader.fieldnames:
            raise ValueError(f'sbom.csv missing required columns: {reader.fieldnames}')

        for row in reader:
            system = (row.get('system') or '').strip()
            pname = (row.get('pname') or '').strip()
            if system in allowed_systems and pname:
                allowed.add(pname)

    return allowed


def _iter_filtered_rows(
    vulns_csv: Path,
    cfg: FilterConfig,
    allowed_pnames: set[str] | None,
) -> Iterable[dict[str, str]]:
    with vulns_csv.open('r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return
        required = {'vuln_id', 'package'}
        missing = required - set(reader.fieldnames)
        if missing:
            raise ValueError(f'vulns.csv missing required columns: {sorted(missing)}')

        for row in reader:
            vuln_id = (row.get('vuln_id') or '').strip()
            package = (row.get('package') or '').strip()

            if cfg.allowed_distro_prefixes and not vuln_id.startswith(
                cfg.allowed_distro_prefixes
            ):
                continue

            if allowed_pnames is not None and package not in allowed_pnames:
                continue

            yield row


def _write_csv(
    out_csv: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, str]]
) -> int:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(
            f, fieldnames=fieldnames, extrasaction='ignore', quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def _extract_unique_cves(rows: Iterable[dict[str, str]]) -> set[str]:
    cves: set[str] = set()
    for row in rows:
        for field in ('vuln_id', 'url', 'summary'):
            value = row.get(field) or ''
            for match in _CVE_RE.finditer(value):
                cves.add(match.group(0))
    return cves


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Filter vulnxscan vulns.csv by distro + architecture'
    )
    parser.add_argument('--vulns', required=True, type=Path, help='Input vulns.csv')
    parser.add_argument(
        '--sbom', type=Path, help='Optional sbom.csv to restrict by architecture'
    )
    parser.add_argument(
        '--pc-only',
        action='store_true',
        help=f"Restrict to PC systems by sbom.csv system column (default systems: {', '.join(PC_SYSTEMS_DEFAULT)})",
    )
    parser.add_argument(
        '--pc-systems',
        default='',
        help='Comma-separated systems to treat as PC (overrides default)',
    )
    parser.add_argument(
        '--distros',
        default='debian,ubuntu,rocky',
        help='Comma-separated list: debian, ubuntu, rocky (default: debian,ubuntu,rocky)',
    )
    parser.add_argument('--out', required=True, type=Path, help='Output filtered CSV')
    parser.add_argument(
        '--dedup-cve',
        action='store_true',
        help='Deduplicate CVE-like rows by normalized YEAR-ID (e.g. 2026-915; keeps advisory rows like USN/RHSA as-is)',
    )
    parser.add_argument(
        '--prefer-debian',
        action='store_true',
        help='When deduplicating, keep DEBIAN-CVE-* row over UBUNTU-CVE-* / CVE-* duplicates',
    )
    parser.add_argument(
        '--out-cves',
        type=Path,
        help='Optional output file listing unique CVE IDs (one per line)',
    )

    args = parser.parse_args()

    distros = [d.strip().lower() for d in args.distros.split(',') if d.strip()]
    unknown = [d for d in distros if d not in DISTRO_PREFIXES]
    if unknown:
        raise SystemExit(
            f'Unknown distros: {unknown}. Supported: {sorted(DISTRO_PREFIXES)}'
        )

    allowed_prefixes: list[str] = []
    for d in distros:
        allowed_prefixes.extend(DISTRO_PREFIXES[d])

    cfg = FilterConfig(
        allowed_distro_prefixes=tuple(allowed_prefixes), allowed_systems=None
    )

    allowed_pnames: set[str] | None = None
    if args.pc_only:
        if args.sbom is None:
            raise SystemExit('--pc-only requires --sbom')

        # Allow override: "--pc-systems x86_64-linux,i686-linux".
        if args.pc_systems:
            pc_systems = tuple(
                s.strip() for s in args.pc_systems.split(',') if s.strip()
            )
        else:
            pc_systems = PC_SYSTEMS_DEFAULT

        allowed_pnames = _read_sbom_allowed_pnames(args.sbom, pc_systems)

    # Determine fieldnames from input
    with args.vulns.open('r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit('Empty vulns.csv')
        fieldnames = reader.fieldnames

    # We need two passes if out-cves is requested.
    filtered_rows = list(_iter_filtered_rows(args.vulns, cfg, allowed_pnames))
    if args.dedup_cve:
        filtered_rows = _dedup_by_cve(
            filtered_rows, prefer_debian=bool(args.prefer_debian)
        )
    _write_csv(args.out, fieldnames, filtered_rows)

    if args.out_cves:
        cves = sorted(_extract_unique_cves(filtered_rows))
        args.out_cves.parent.mkdir(parents=True, exist_ok=True)
        args.out_cves.write_text(
            '\n'.join(cves) + ('\n' if cves else ''), encoding='utf-8'
        )

    return 0


if __name__ == '__main__':
    raise SystemExit(main())

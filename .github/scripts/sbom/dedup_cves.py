#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deduplicate CVE-like rows in a vulnxscan CSV.

This script removes duplicate rows that refer to the same CVE, where the CVE is
encoded in the row (typically in the `vuln_id` field) as one of:
- CVE-YYYY-NNNN...
- <DISTRO>-CVE-YYYY-NNNN... (e.g. DEBIAN-CVE-YYYY-NNNN)

Deduplication key is normalized YEAR-ID, so padding differences like
CVE-2026-0915 vs CVE-2026-915 collapse to the same key ("2026-915").

Non-CVE advisories (e.g. RHSA-2026:0794, USN-6409-1, DSA-5514-1, ...) are
preserved as-is.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from pathlib import Path
from typing import Iterable

_CVE_PARTS_RE = re.compile(r'CVE-(\d{4})[-:](\d+)')


def _extract_cve_key(value: str) -> str | None:
    if not value:
        return None
    match = _CVE_PARTS_RE.search(value)
    if not match:
        return None
    year, ident = match.group(1), match.group(2)
    return f'{year}-{int(ident)}'


def _iter_rows(csv_path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with csv_path.open('r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit(f'Empty CSV: {csv_path}')
        rows = list(reader)
        return list(reader.fieldnames), rows


def _strategy_key(strategy: str, row: dict[str, str]) -> tuple:
    """Return a sortable key where higher is better."""

    vuln_id = (row.get('vuln_id') or '').strip()

    if strategy == 'first':
        return (0,)

    if strategy == 'richest':
        # Prefer rows with more information.
        def as_int(field: str) -> int:
            try:
                return int((row.get(field) or '0').strip() or '0')
            except ValueError:
                return 0

        def as_float(field: str) -> float:
            try:
                return float((row.get(field) or '').strip() or '0')
            except ValueError:
                return 0.0

        sum_scanners = as_int('sum')
        has_severity = 1 if (row.get('severity') or '').strip() else 0
        severity = as_float('severity')

        # Then keep stable preference among CVE flavors.
        flavor = 0
        if vuln_id.startswith('DEBIAN-CVE-'):
            flavor = 3
        elif vuln_id.startswith('CVE-'):
            flavor = 2
        elif vuln_id.startswith('UBUNTU-CVE-'):
            flavor = 1

        return (sum_scanners, has_severity, severity, flavor)

    # strategy == "debian" (default)
    if vuln_id.startswith('DEBIAN-CVE-'):
        return (3,)
    if vuln_id.startswith('CVE-'):
        return (2,)
    if vuln_id.startswith('UBUNTU-CVE-'):
        return (1,)
    return (0,)


def _dedup_rows(
    fieldnames: list[str], rows: list[dict[str, str]], strategy: str
) -> list[dict[str, str]]:
    best_for_key: dict[str, dict[str, str]] = {}

    # Keep stable output order: preserve all non-CVE rows in their original
    # order, and append chosen CVE rows in order of first appearance of the key.
    non_cve_rows: list[dict[str, str]] = []

    for row in rows:
        vuln_id = (row.get('vuln_id') or '').strip()
        key = _extract_cve_key(vuln_id)
        if key is None:
            non_cve_rows.append(row)
            continue

        prev = best_for_key.get(key)
        if prev is None:
            best_for_key[key] = row
        else:
            if _strategy_key(strategy, row) > _strategy_key(strategy, prev):
                best_for_key[key] = row

    ordered_cve_rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in rows:
        vuln_id = (row.get('vuln_id') or '').strip()
        key = _extract_cve_key(vuln_id)
        if key is None or key in seen:
            continue
        chosen = best_for_key.get(key)
        if chosen is not None:
            ordered_cve_rows.append(chosen)
            seen.add(key)

    return [*non_cve_rows, *ordered_cve_rows]


def _write_csv(
    path: Path, fieldnames: Iterable[str], rows: Iterable[dict[str, str]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(
            f, fieldnames=list(fieldnames), extrasaction='ignore', quoting=csv.QUOTE_ALL
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Deduplicate CVE-like rows in a vulnxscan CSV'
    )
    parser.add_argument(
        '--csv', type=Path, required=True, help='Input CSV to deduplicate'
    )
    parser.add_argument(
        '--inplace',
        action='store_true',
        help='Rewrite the input file in place (safe write via temporary file)',
    )
    parser.add_argument(
        '--out',
        type=Path,
        default=None,
        help='Optional output path (ignored if --inplace is set)',
    )
    parser.add_argument(
        '--strategy',
        choices=('debian', 'richest', 'first'),
        default='debian',
        help='How to pick which row to keep for duplicates (default: debian)',
    )

    args = parser.parse_args()

    in_path: Path = args.csv
    fieldnames, rows = _iter_rows(in_path)
    out_rows = _dedup_rows(fieldnames, rows, strategy=args.strategy)

    if args.inplace:
        tmp_path = in_path.with_suffix(in_path.suffix + f'.tmp.{os.getpid()}')
        _write_csv(tmp_path, fieldnames, out_rows)
        tmp_path.replace(in_path)
    else:
        out_path = args.out or in_path
        _write_csv(out_path, fieldnames, out_rows)

    before = len(rows)
    after = len(out_rows)
    removed = before - after
    print(f'Dedup complete: {before} -> {after} rows (removed {removed})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

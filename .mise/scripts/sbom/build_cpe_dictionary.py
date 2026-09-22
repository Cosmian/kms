#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a local SQLite index of the NVD CPE dictionary for SBOM vendor verification.

Parses downloaded nvdcpe-2.0-chunk-*.json files (NVD CPE API 2.0 dump) and creates
a SQLite database containing (part, vendor, product, version) rows indexed by product
and (vendor, product).
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import time
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Build a local SQLite index of the NVD CPE 2.0 dictionary.',
    )
    parser.add_argument(
        '--source-dir',
        type=Path,
        required=True,
        help='Directory containing nvdcpe-2.0-chunk-*.json files.',
    )
    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='Path for the resulting SQLite database.',
    )
    return parser.parse_args()


def build_cpe_dictionary(source_dir: Path, output_path: Path) -> None:
    """Read all nvdcpe-2.0-chunk-*.json in source_dir and build the SQLite index."""
    if not source_dir.is_dir():
        print(f"ERROR: --source-dir {source_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    chunk_files = sorted(source_dir.glob('nvdcpe-2.0-chunk-*.json'))
    if not chunk_files:
        print(
            f"ERROR: No nvdcpe-2.0-chunk-*.json files found in {source_dir}",
            file=sys.stderr,
        )
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    start_time = time.time()
    conn = sqlite3.connect(output_path)
    conn.execute('PRAGMA synchronous = OFF')
    conn.execute('PRAGMA journal_mode = MEMORY')

    conn.execute(
        'CREATE TABLE cpe_entries (part TEXT, vendor TEXT, product TEXT, version TEXT)'
    )

    total_inserted = 0
    skipped_entries = 0
    split_pattern = re.compile(r'(?<!\\):')

    batch: list[tuple[str, str, str, str]] = []
    batch_size = 5000

    conn.execute('BEGIN')

    for chunk_idx, chunk_file in enumerate(chunk_files, 1):
        try:
            with open(chunk_file, encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as exc:
            print(f"ERROR reading {chunk_file}: {exc}", file=sys.stderr)
            conn.close()
            sys.exit(1)

        products = data.get('products', [])
        for item in products:
            cpe_obj = item.get('cpe', {})
            cpe_name = cpe_obj.get('cpeName')
            if not cpe_name:
                continue

            fields = split_pattern.split(cpe_name)
            if len(fields) < 6:
                skipped_entries += 1
                continue

            part = fields[2]
            vendor = fields[3]
            product = fields[4]
            version = fields[5]

            batch.append((part, vendor, product, version))
            if len(batch) >= batch_size:
                conn.executemany(
                    'INSERT INTO cpe_entries (part, vendor, product, version) VALUES (?, ?, ?, ?)',
                    batch,
                )
                total_inserted += len(batch)
                batch.clear()

    if batch:
        conn.executemany(
            'INSERT INTO cpe_entries (part, vendor, product, version) VALUES (?, ?, ?, ?)',
            batch,
        )
        total_inserted += len(batch)
        batch.clear()

    conn.commit()

    conn.execute('CREATE INDEX idx_cpe_product ON cpe_entries(product)')
    conn.execute('CREATE INDEX idx_cpe_vendor_product ON cpe_entries(vendor, product)')
    conn.commit()
    conn.close()

    elapsed = time.time() - start_time
    print(
        f"✓ Processed {len(chunk_files)} chunk files, inserted {total_inserted} rows "
        f"({skipped_entries} malformed skipped) in {elapsed:.2f}s -> {output_path}"
    )


def main() -> None:
    args = _parse_args()
    build_cpe_dictionary(args.source_dir, args.output)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
loc_diff.py — Show lines added / deleted / net vs a base branch,
grouped by root folder and then by crate/ subfolders.

Usage:
    python3 loc_diff.py [BASE_REF]

    BASE_REF defaults to "origin/develop".
"""
import subprocess
import sys
from collections import defaultdict


def main() -> None:
    base = sys.argv[1] if len(sys.argv) > 1 else 'origin/develop'

    result = subprocess.run(
        ['git', 'diff', f"{base}...HEAD", '--numstat'],
        capture_output=True,
        text=True,
        check=True,
    )

    root_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    sub_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])

    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) != 3:
            continue
        added_s, deleted_s, path = parts
        if added_s == '-':  # binary file
            continue
        added, deleted = int(added_s), int(deleted_s)
        segs = path.split('/')
        root = segs[0] if len(segs) > 1 else '.'
        root_stats[root][0] += added
        root_stats[root][1] += deleted
        if root == 'crate' and len(segs) > 2:
            sub = segs[1]
            sub_stats[sub][0] += added
            sub_stats[sub][1] += deleted

    def _row(label: str, added: int, deleted: int) -> str:
        net = added - deleted
        sign = '+' if net >= 0 else ''
        return f"  {label:<38} {added:>7}  {deleted:>7}  {sign}{net:>7}"

    header = f"  {'Folder':<38} {'Added':>7}  {'Deleted':>7}  {'Net':>8}"
    sep = f"  {'-' * 38} {'-' * 7}  {'-' * 7}  {'-' * 8}"

    print(f"\n=== By root folder  (vs {base}) ===")
    print(header)
    print(sep)
    for r, (a, d) in sorted(root_stats.items(), key=lambda x: -(x[1][0] - x[1][1])):
        print(_row(r, a, d))

    print(f"\n=== crate/ subfolders ===")
    print(header.replace('Folder', 'Subfolder'))
    print(sep)
    for s, (a, d) in sorted(sub_stats.items(), key=lambda x: -(x[1][0] - x[1][1])):
        print(_row(f"crate/{s}", a, d))

    total_added = sum(v[0] for v in root_stats.values())
    total_deleted = sum(v[1] for v in root_stats.values())
    print(f"\n  Lines changed: {total_added:,} additions & {total_deleted:,} deletions")


if __name__ == '__main__':
    main()

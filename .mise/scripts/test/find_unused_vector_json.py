#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Find and remove JSON files in test_data/vectors/ that are not referenced by any
non-regression test vector manifest.

Rules:
  - test_data/vectors/jose/ : all JSON files are used (auto-discovered at runtime).
  - Every other sub-directory that contains a manifest.toml:
      Used JSON files = those listed as `request = "..."` in the manifest steps.
      Unused JSON files = any *.json file in the directory NOT in that set.
  - Sub-directories that contain NO manifest.toml are entirely unused.
"""

import os
import sys
import re
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent.parent / 'test_data' / 'vectors'
# jose/ uses runtime discovery — skip it entirely
SKIP_DIRS = {'jose'}


def collect_manifest_requests(manifest_path: Path) -> set[str]:
    """Return the set of JSON filenames referenced via `request = "..."` in a manifest."""
    text = manifest_path.read_text()
    # Match   request = "filename.json"   (with any surrounding whitespace)
    return set(re.findall(r'request\s*=\s*"([^"]+\.json)"', text))


def main(dry_run: bool = False) -> None:
    unused: list[Path] = []
    no_manifest_dirs: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(VECTORS_DIR):
        dir_ = Path(dirpath)

        # Skip the root vectors/ directory itself
        if dir_ == VECTORS_DIR:
            continue

        # Skip explicitly excluded dirs (jose/) at any depth
        rel = dir_.relative_to(VECTORS_DIR)
        if any(part in SKIP_DIRS for part in rel.parts):
            dirnames.clear()  # don't recurse
            continue

        # We only care about leaf directories that contain JSON files
        json_files = {f for f in filenames if f.endswith('.json')}
        if not json_files:
            continue

        manifest = dir_ / 'manifest.toml'
        if not manifest.exists():
            # The whole directory is unreferenced
            no_manifest_dirs.append(dir_)
            for f in sorted(json_files):
                unused.append(dir_ / f)
        else:
            referenced = collect_manifest_requests(manifest)
            for f in sorted(json_files):
                if f not in referenced:
                    unused.append(dir_ / f)

    # ── Report ────────────────────────────────────────────────────────────────
    if no_manifest_dirs:
        print(f"\n{'=' * 60}")
        print('Directories with JSON files but NO manifest.toml:')
        for d in sorted(no_manifest_dirs):
            print(f"  {d.relative_to(VECTORS_DIR)}/")

    if unused:
        print(f"\n{'=' * 60}")
        print(f"Unused JSON files ({len(unused)} total):")
        for f in unused:
            print(f"  {f.relative_to(VECTORS_DIR)}")
    else:
        print('\nNo unused JSON files found.')
        return

    if dry_run:
        print(
            f"\n[DRY RUN] Would remove {len(unused)} file(s). Re-run without --dry-run to delete."
        )
        return

    print(f"\nRemoving {len(unused)} file(s)...")
    removed = 0
    for f in unused:
        try:
            f.unlink()
            print(f"  REMOVED  {f.relative_to(VECTORS_DIR)}")
            removed += 1
        except OSError as exc:
            print(f"  ERROR    {f.relative_to(VECTORS_DIR)}: {exc}", file=sys.stderr)

    print(f"\nDone. {removed}/{len(unused)} file(s) removed.")


if __name__ == '__main__':
    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv
    if dry_run:
        print('Running in DRY-RUN mode (no files will be deleted).')
    main(dry_run=dry_run)

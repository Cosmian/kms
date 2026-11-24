#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reject staged changes that are not plain content edits of an exact allowlist of files.

Run in a Git work tree after a generated patch was applied to the index (commit-generated.yml), before any
credential is used. Only modifications or additions of regular files at exactly the listed paths pass:
deletions, renames, mode/type changes (symlink, gitlink, executable bit flips on existing files) and every
other path fail.

Usage: validate_generated_changes.py ALLOWED_FILE   (one repository-relative path per line)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REGULAR_MODES = {'100644', '100755'}


def read_allowed(path: Path) -> set[str]:
    allowed = set()
    for line in path.read_text().splitlines():
        entry = line.strip()
        if not entry:
            continue
        parts = entry.split('/')
        if (
            entry.startswith('/')
            or '' in parts
            or '.' in parts
            or '..' in parts
            or any(c in entry for c in '*?[\\')
        ):
            raise ValueError(f'invalid allowlist entry: {entry!r}')
        allowed.add(entry)
    if not allowed:
        raise ValueError('empty allowlist')
    return allowed


def staged_changes() -> list[tuple[str, str, str, str]]:
    """(old_mode, new_mode, status, path) of the index against HEAD, rename detection off."""
    raw = subprocess.run(
        [
            'git',
            'diff',
            '--cached',
            '--raw',
            '-z',
            '--no-renames',
            '--no-abbrev',
            'HEAD',
        ],
        check=True,
        capture_output=True,
    ).stdout.split(b'\0')
    changes, i = [], 0
    while i + 1 < len(raw) and raw[i]:
        meta = raw[i].decode().lstrip(':').split()
        changes.append(
            (meta[0], meta[1], meta[4], raw[i + 1].decode('utf-8', 'surrogateescape'))
        )
        i += 2
    return changes


def validate(allowed: set[str], changes: list[tuple[str, str, str, str]]) -> list[str]:
    errors = []
    for old_mode, new_mode, status, path in changes:
        if path not in allowed:
            errors.append(f'{path}: not in the allowed file list')
        elif status not in ('A', 'M'):
            errors.append(
                f'{path}: status {status} (only modification or addition is allowed)'
            )
        elif new_mode not in REGULAR_MODES:
            errors.append(f'{path}: mode {new_mode} is not a regular file')
        elif status == 'M' and old_mode != new_mode:
            errors.append(f'{path}: mode change {old_mode} -> {new_mode}')
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        errors = validate(read_allowed(Path(argv[1])), staged_changes())
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f'validate_generated_changes: {exc}', file=sys.stderr)
        return 1
    for error in errors:
        print(f'REJECTED {error}', file=sys.stderr)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))

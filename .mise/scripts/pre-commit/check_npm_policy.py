#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail when the Web UI npm supply-chain policy (#1265) is weakened.

Checks ui/package.json and ui/.npmrc; see CONTRIBUTING.md "Supply-chain / dependency policy".
With --warn-stale (needs npm and the network) it also lists cooldown exclusions that are
no longer needed because the excluded version is now older than the cooldown.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

UI = Path(__file__).resolve().parents[3] / 'ui'
REQUIRED_NPMRC = {
    'minimum-release-age': re.compile(r'^[1-9]\d*$'),
    'strict-dep-builds': re.compile(r'^true$'),
}
MIN_RELEASE_AGE_MINUTES = 10080
EXCLUDE_KEY = 'minimum-release-age-exclude[]'
EXACT_VERSION = re.compile(
    r'(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*@\d+\.\d+\.\d+(-[\w.]+)?'
)
ADVISORY = re.compile(r'\b(GHSA(-[0-9a-z]{4}){3}|CVE-\d{4}-\d{4,})\b')


def npmrc_settings() -> dict[str, str]:
    settings = {}
    for line in (UI / '.npmrc').read_text(encoding='utf-8').splitlines():
        key, sep, value = line.partition('=')
        if sep and not line.lstrip().startswith(('#', ';')):
            settings[key.strip()] = value.strip()
    return settings


def release_age_excludes() -> list[tuple[str, str, str]]:
    """(key, value, comment above) per cooldown exclusion; adjacent entries share one comment."""
    entries, comments = [], []
    for line in (UI / '.npmrc').read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith(('#', ';')):
            comments.append(stripped)
            continue
        key, sep, value = stripped.partition('=')
        if sep and key.strip().startswith('minimum-release-age-exclude'):
            entries.append((key.strip(), value.strip(), ' '.join(comments)))
            continue
        comments = []
    return entries


def check_excludes() -> list[str]:
    errors = []
    for key, value, comment in release_age_excludes():
        if key != EXCLUDE_KEY or not EXACT_VERSION.fullmatch(value):
            errors.append(
                f"ui/.npmrc: {key}={value}: only exact versions may skip the cooldown, "
                f"one '{EXCLUDE_KEY}=<name>@<version>' line each"
            )
        if not ADVISORY.search(comment):
            errors.append(
                f"ui/.npmrc: {key}={value} needs a comment above it citing the advisory it fixes (GHSA-… or CVE-…)"
            )
    return errors


def stale_excludes() -> list[str]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=MIN_RELEASE_AGE_MINUTES)
    stale = []
    for _key, spec, _comment in release_age_excludes():
        name, _, version = spec.rpartition('@')
        times = json.loads(
            subprocess.run(
                ['npm', 'view', name, 'time', '--json'],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        published = times.get(version)
        if (
            published
            and datetime.fromisoformat(published.replace('Z', '+00:00')) < cutoff
        ):
            stale.append(
                f"ui/.npmrc: {spec} is older than the cooldown now; remove its exclusion"
            )
    return stale


def check() -> list[str]:
    errors = []
    pkg = json.loads((UI / 'package.json').read_text(encoding='utf-8'))
    pnpm = pkg.get('pnpm', {})
    if pnpm.get('onlyBuiltDependencies'):
        errors.append(
            'ui/package.json: pnpm.onlyBuiltDependencies must stay empty; '
            'list packages whose install scripts are not needed in pnpm.ignoredBuiltDependencies instead'
        )
    if not re.fullmatch(
        r'pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}', pkg.get('packageManager', '')
    ):
        errors.append(
            'ui/package.json: packageManager must be "pnpm@<version>+sha512.<hex>"'
        )
    for name, spec in pnpm.get('overrides', {}).items():
        if spec.lstrip().startswith('>'):
            errors.append(
                f"ui/package.json: override {name!r} uses an unbounded range {spec!r}; use ^ or ~"
            )

    settings = npmrc_settings()
    for key, pattern in REQUIRED_NPMRC.items():
        if not pattern.match(settings.get(key, '')):
            errors.append(f"ui/.npmrc: {key} is missing or invalid")
    age = settings.get('minimum-release-age', '0')
    if age.isdigit() and int(age) < MIN_RELEASE_AGE_MINUTES:
        errors.append(
            f"ui/.npmrc: minimum-release-age must be at least {MIN_RELEASE_AGE_MINUTES} minutes (7 days)"
        )
    return errors + check_excludes()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        '--warn-stale',
        action='store_true',
        help='also warn about exclusions no longer needed',
    )
    args = parser.parse_args()
    problems = check()
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    if args.warn_stale:
        for warning in stale_excludes():
            print(f"WARNING: {warning}", file=sys.stderr)
    sys.exit(1 if problems else 0)

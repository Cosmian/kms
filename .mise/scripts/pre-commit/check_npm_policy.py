#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail when the Web UI npm supply-chain policy (#1265) is weakened.

Checks ui/package.json and ui/.npmrc; see CONTRIBUTING.md "Supply-chain / dependency policy".
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

UI = Path(__file__).resolve().parents[3] / 'ui'
REQUIRED_NPMRC = {
    'minimum-release-age': re.compile(r'^[1-9]\d*$'),
    'strict-dep-builds': re.compile(r'^true$'),
}
MIN_RELEASE_AGE_MINUTES = 10080


def npmrc_settings() -> dict[str, str]:
    settings = {}
    for line in (UI / '.npmrc').read_text(encoding='utf-8').splitlines():
        key, sep, value = line.partition('=')
        if sep and not line.lstrip().startswith(('#', ';')):
            settings[key.strip()] = value.strip()
    return settings


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
    return errors


if __name__ == '__main__':
    problems = check()
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
    sys.exit(1 if problems else 0)

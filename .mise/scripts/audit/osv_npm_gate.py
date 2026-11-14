#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Decide which OSV-Scanner findings on ui/pnpm-lock.yaml fail the npm audit.

Without --base every finding fails (daily develop run, tags). With --base only the
findings the change introduces fail: an advisory the base branch already ships is
reported, since blocking the change would not remove it. MAL-* (malicious package)
findings always fail: removing malware never needs a release younger than the 7-day
cooldown. See CONTRIBUTING.md "Supply-chain / dependency policy".
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    ids: frozenset[str]
    severity: str

    def __str__(self) -> str:
        ids = ', '.join(sorted(self.ids))
        return f"{self.package}@{self.version}: {ids} (CVSS {self.severity or '?'})"


def load(report: Path) -> list[Finding]:
    """One finding per (package, advisory group) of an `osv-scanner --format json` report."""
    text = report.read_text(encoding='utf-8')
    if not text.strip():
        return []
    findings = []
    for result in json.loads(text).get('results') or []:
        for pkg in result.get('packages') or []:
            for group in pkg.get('groups') or []:
                findings.append(
                    Finding(
                        package=pkg['package']['name'],
                        version=pkg['package']['version'],
                        ids=frozenset(group.get('ids', []) + group.get('aliases', [])),
                        severity=group.get('max_severity', ''),
                    )
                )
    return findings


def annotate(level: str, message: str) -> None:
    print(f"{level.upper()}: {message}")
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        print(f"::{level}::{message}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('head', type=Path, help='OSV JSON report of the change')
    parser.add_argument('--base', type=Path, help='OSV JSON report of the base branch')
    args = parser.parse_args()

    head = load(args.head)
    if args.base is None:
        known = set()
    else:
        known = {(f.package, i) for f in load(args.base) for i in f.ids}

    blocking = 0
    for finding in head:
        if any(i.startswith('MAL-') for i in finding.ids):
            annotate('error', f"malicious package: {finding}")
            blocking += 1
        elif args.base is not None and any(
            (finding.package, i) in known for i in finding.ids
        ):
            annotate('warning', f"already on the base branch, not blocking: {finding}")
        else:
            annotate('error', f"advisory: {finding}")
            blocking += 1
    return 1 if blocking else 0


if __name__ == '__main__':
    sys.exit(main())

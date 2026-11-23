#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advisory coverage gate: lock file, production dependency graph, ignore lists and OpenVEX must agree.

Inputs (all produced by `mise run sbom:check-advisories`):
  --root DIR              repository root (Cargo.lock, deny.toml, .cargo/audit.toml, sbom/openvex.json)
  --audit-json FILE       output of `cargo audit --json`
  --audit-exit-status N   exit status of that `cargo audit` run (default 0)
  --production-tree FILE  `cargo tree --edges normal --prefix none --format '{p}|{f}'` of the shipped crates,
                          one per build variant (repeatable)
  --policy-only           only validate the lock file and the ignore/OpenVEX consistency (needs --root only)

A package present in Cargo.lock but absent from every production tree is labeled `lock-only/non-runtime`.
That label never waives an advisory: any vulnerability reported by cargo audit fails the check.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

# name -> first patched version of the advisories this change remediates (RUSTSEC-2026-0523/0524/0538/0486).
PATCHED_FLOORS = {
    'quinn-proto': (0, 11, 19),
    'quinn-udp': (0, 5, 16),
    'rustix': (1, 1, 6),
}
# The QUIC stack is not shipped: no variant may compile it in, whatever its version.
FORBIDDEN_RUNTIME = ('quinn', 'quinn-proto', 'quinn-udp')
ADVISORY_ID = re.compile(r'^(RUSTSEC|GHSA|CVE)-')
# `{p}|{f}` lines; `{p}` is `name vX.Y.Z` plus optional `(path)`/`(proc-macro)`, cargo appends ` (*)` to repeats.
TREE_LINE = re.compile(
    r'^(?P<name>[^\s|]+) v(?P<version>[^\s|]+)(?: \([^)|]*\))*\|(?P<features>[^()]*?)(?: \(\*\))?$'
)
VEX_STATUSES = {'not_affected', 'affected', 'fixed', 'under_investigation'}


def version_tuple(version: str) -> tuple[int, ...]:
    core = re.split(r'[-+]', version, maxsplit=1)[0]
    return tuple(int(part) for part in core.split('.'))


def locked_packages(root: Path) -> set[tuple[str, str]]:
    lock = tomllib.loads((root / 'Cargo.lock').read_text())
    return {(p['name'], p['version']) for p in lock.get('package', [])}


def check_lock(locked: set[tuple[str, str]]) -> list[str]:
    errors = []
    for name, version in sorted(locked):
        floor = PATCHED_FLOORS.get(name)
        if floor and version_tuple(version) < floor:
            errors.append(
                f'Cargo.lock: {name} {version} is below the patched version {".".join(map(str, floor))} '
                '(present in the lock file even if not compiled)'
            )
    return errors


def ignored_ids(path: Path) -> set[str]:
    entries = tomllib.loads(path.read_text()).get('advisories', {}).get('ignore', [])
    ids = set()
    for entry in entries:
        value = entry.get('id') if isinstance(entry, dict) else entry
        if isinstance(value, str) and ADVISORY_ID.match(value):
            ids.add(value)
    return ids


def purl_cargo(purl: str) -> tuple[str, str] | None:
    match = re.fullmatch(r'pkg:cargo/([^@/?#]+)@([^?#]+)(?:[?#].*)?', purl)
    return (match.group(1), match.group(2)) if match else None


def check_policy(root: Path) -> list[str]:
    errors = []
    deny_ids = ignored_ids(root / 'deny.toml')
    audit_ids = ignored_ids(root / '.cargo' / 'audit.toml')
    if deny_ids != audit_ids:
        errors.append(
            f'advisory ignore lists differ: deny.toml only {sorted(deny_ids - audit_ids)}, '
            f'.cargo/audit.toml only {sorted(audit_ids - deny_ids)}'
        )

    locked = locked_packages(root)
    errors += check_lock(locked)

    statements = json.loads((root / 'sbom' / 'openvex.json').read_text()).get(
        'statements', []
    )
    seen_status: dict[tuple[str, str], str] = {}
    for index, st in enumerate(statements):
        name = st.get('vulnerability', {}).get('name', f'<statement {index}>')
        status = st.get('status')
        if status not in VEX_STATUSES:
            errors.append(f'openvex {name}: invalid status {status!r}')
        elif status == 'not_affected' and not (
            st.get('justification') or st.get('impact_statement')
        ):
            errors.append(
                f'openvex {name}: not_affected needs a justification or impact_statement'
            )
        elif status == 'affected' and not st.get('action_statement'):
            errors.append(f'openvex {name}: affected needs an action_statement')
        elif status == 'under_investigation' and not st.get('status_notes'):
            errors.append(f'openvex {name}: under_investigation needs status_notes')
        products = [p.get('@id', '') for p in st.get('products', [])]
        if not products:
            errors.append(f'openvex {name}: no product')
        for product in products:
            cargo = purl_cargo(product)
            if cargo and cargo not in locked:
                errors.append(
                    f'openvex {name}: stale product {product} (not in Cargo.lock)'
                )
            previous = seen_status.setdefault((name, product), status)
            if previous != status:
                errors.append(
                    f'openvex {name}: contradictory statuses {previous} / {status} for {product}'
                )

    for advisory_id in sorted(deny_ids):
        covered = any(
            advisory_id == st.get('vulnerability', {}).get('name')
            or advisory_id in st.get('vulnerability', {}).get('aliases', [])
            for st in statements
        )
        if not covered:
            errors.append(
                f'{advisory_id} is ignored in deny.toml but has no OpenVEX statement'
            )
    return errors


def parse_tree(text: str) -> list[tuple[str, str, set[str]]]:
    packages = []
    for line in text.splitlines():
        if not line.strip():
            continue
        match = TREE_LINE.match(line)
        if not match:
            raise ValueError(f'unparsable cargo tree line: {line!r}')
        features = {f for f in match['features'].split(',') if f}
        packages.append((match['name'], match['version'], features))
    if not packages:
        raise ValueError('empty cargo tree output')
    return packages


def check_graph(
    label: str, packages: list[tuple[str, str, set[str]]]
) -> tuple[list[str], list[str]]:
    """(errors, notes). rustix is a genuine runtime dependency (tempfile via native-tls): patched is fine."""
    errors, notes = [], []
    for name, version, features in packages:
        if name in FORBIDDEN_RUNTIME:
            errors.append(
                f'{label}: {name} {version} is compiled into the shipped binaries (production runtime graph)'
            )
        floor = PATCHED_FLOORS.get(name)
        if floor and version_tuple(version) < floor:
            errors.append(
                f'{label}: vulnerable {name} {version} is in the production runtime graph'
            )
        elif name == 'rustix':
            notes.append(f'  [production] {label}: {name} {version} (patched)')
        if name == 'reqwest' and 'http3' in features:
            errors.append(
                f'{label}: reqwest {version} enables the http3 feature (pulls quinn)'
            )
    return errors, sorted(set(notes))


def audit_findings(report: dict) -> list[tuple[str, dict, str, str]]:
    """(kind, advisory, name, version) of every vulnerability and informational warning."""
    findings = []
    vulns = report['vulnerabilities']
    for item in vulns['list']:
        findings.append(
            (
                'vulnerability',
                item['advisory'],
                item['package']['name'],
                item['package']['version'],
            )
        )
    for kind, items in report.get('warnings', {}).items():
        for item in items:
            findings.append(
                (
                    kind,
                    item.get('advisory') or {},
                    item['package']['name'],
                    item['package']['version'],
                )
            )
    if bool(vulns['found']) != bool(vulns['list']):
        raise ValueError('inconsistent vulnerabilities.found / list')
    return findings


def check_audit(
    report_text: str, exit_status: int, runtime_names: set[str]
) -> tuple[list[str], list[str]]:
    """Returns (errors, report lines). Malformed input is an error, never a clean result."""
    try:
        findings = audit_findings(json.loads(report_text))
    except (ValueError, KeyError, TypeError) as exc:
        return [f'cargo audit report is malformed: {exc!r}'], []
    errors, lines = [], []
    for kind, advisory, name, version in findings:
        scope = 'production' if name in runtime_names else 'lock-only/non-runtime'
        advisory_id = advisory.get('id', '?')
        lines.append(f'  [{scope}] {kind}: {advisory_id} {name} {version}')
        if kind == 'vulnerability':
            errors.append(
                f'cargo audit: {advisory_id} affects {name} {version} ({scope}); scope does not waive it'
            )
    if exit_status != 0 and not errors:
        errors.append(
            f'cargo audit exited with status {exit_status} without a reported vulnerability (database or network failure?)'
        )
    return errors, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--policy-only', action='store_true')
    parser.add_argument('--audit-json', type=Path)
    parser.add_argument('--audit-exit-status', type=int, default=0)
    parser.add_argument('--production-tree', type=Path, action='append', default=[])
    args = parser.parse_args(argv)

    errors = check_policy(args.root)
    lines: list[str] = []
    if not args.policy_only:
        if not args.audit_json or not args.production_tree:
            parser.error(
                '--audit-json and at least one --production-tree are required without --policy-only'
            )
        runtime_names: set[str] = set()
        for tree in args.production_tree:
            try:
                packages = parse_tree(tree.read_text())
            except (OSError, ValueError) as exc:
                errors.append(f'{tree}: {exc}')
                continue
            runtime_names |= {name for name, _, _ in packages}
            graph_errors, notes = check_graph(tree.stem, packages)
            errors += graph_errors
            lines += notes
        try:
            report_text = args.audit_json.read_text()
        except OSError as exc:
            errors.append(f'{args.audit_json}: {exc}')
        else:
            audit_errors, audit_lines = check_audit(
                report_text, args.audit_exit_status, runtime_names
            )
            errors += audit_errors
            lines += audit_lines
    for line in lines:
        print(line)
    for error in errors:
        print(f'FAIL {error}', file=sys.stderr)
    if not errors:
        print('Advisory coverage OK')
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())

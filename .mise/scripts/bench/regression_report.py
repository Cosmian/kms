#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Performance regression report between two benchmarks published on package.cosmian.com.

Fetches `<base-url>/kms/<version>/benchmarks/<dir>/{env.json,load_*.json,criterion.json}`
for both versions (falling back to the flat `benchmarks/` layout used by older releases),
compares every load-test point and Criterion benchmark, and prints a markdown report.

Usage: regression_report.py <base_version> <new_version> [--dir ckms_bench]
           [--threshold 5] [--base-url https://package.cosmian.com] [--output FILE] [--fail] [--all]
Exit status: 1 when --fail is given and at least one regression is found, or when data is missing.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys


def fetch(url: str) -> str | None:
    """GET url via curl (uses the system CA store; python.org builds on macOS have none)."""
    r = subprocess.run(
        ['curl', '-sSL', '--max-time', '60', '-w', '\n%{http_code}', url],
        capture_output=True,
        text=True,
    )
    if r.returncode:
        sys.exit(f"ERROR: curl failed for {url}: {r.stderr.strip()}")
    body, _, code = r.stdout.rpartition('\n')
    if code == '404':
        return None
    if code != '200':
        sys.exit(f"ERROR: GET {url} -> HTTP {code}")
    return body


def jsonl(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_version(base_url: str, version: str, subdir: str) -> dict:
    """Return {'env': dict, 'load': {key: row}, 'crit': {id: ns}, 'url': str}."""
    root = f"{base_url}/kms/{version}/benchmarks"
    for url in (f"{root}/{subdir}", root):
        index = fetch(f"{url}/")
        if index and ('load_' in index or 'criterion.json' in index):
            break
    else:
        sys.exit(
            f"ERROR: no benchmark data published for {version} under {root}/{subdir}/"
        )
    files = re.findall(r'href="(load_[^"/]+\.json|criterion\.json|env\.json)"', index)
    out = {'env': {}, 'load': {}, 'crit': {}, 'url': url}
    for name in files:
        text = fetch(f"{url}/{name}")
        if text is None:
            continue
        if name == 'env.json':
            out['env'] = json.loads(text)
        elif name == 'criterion.json':
            for row in jsonl(text):
                if row.get('reason') == 'benchmark-complete':
                    # Criterion ids embed the version ("group/5.25.0/name", maybe "v5.25.0"): drop it to align versions.
                    cid = '/'.join(
                        p
                        for p in row['id'].split('/')
                        if not re.fullmatch(r'v?\d+\.\d+\.\d+\S*', p)
                    )
                    m = row['median']
                    out['crit'][cid] = (
                        m['estimate'],
                        m['lower_bound'],
                        m['upper_bound'],
                    )
        else:
            for row in jsonl(text):
                out['load'][
                    (row['protocol'], row['operation'], row['concurrency'])
                ] = row
    if not out['load'] and not out['crit']:
        sys.exit(
            f"ERROR: {url} lists no usable load_*.json / criterion.json for {version}"
        )
    return out


# A healthy load sweep sustains hundreds of req/s at concurrency 1; below this the point collapsed
# (server regression, timeouts or a harness/server mismatch: the report cannot tell which).
MIN_RPS = 10.0


def pct(old: float, new: float) -> float:
    return (new - old) / old * 100.0 if old else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument('base')
    ap.add_argument('new')
    ap.add_argument('--dir', default='ckms_bench')
    ap.add_argument('--threshold', type=float, default=5.0)
    ap.add_argument('--base-url', default='https://package.cosmian.com')
    ap.add_argument('--output')
    ap.add_argument('--fail', action='store_true')
    ap.add_argument(
        '--all',
        action='store_true',
        help='list every compared benchmark, not only regressions',
    )
    a = ap.parse_args()

    old, new = (load_version(a.base_url, v, a.dir) for v in (a.base, a.new))
    th = a.threshold
    lines = [
        f"# Performance regression report: {a.base} -> {a.new}",
        '',
        f"Threshold: {th:g}% (a regression is a throughput drop or a latency/time increase beyond it).",
        '',
    ]

    # Comparisons are only meaningful on the same machine and parameters.
    keys = (
        'cpu_model',
        'cpu_logical_cores',
        'mem_gb',
        'variant',
        'build_mode',
        'bench_time_s',
        'bench_concurrency',
        'bench_warmup_s',
        'http_workers',
    )
    diff = [k for k in keys if old['env'].get(k) != new['env'].get(k)]
    if diff:
        lines += [
            '> **WARNING: environments differ, results are not comparable:** '
            + ', '.join(
                f"`{k}` ({old['env'].get(k)} vs {new['env'].get(k)})" for k in diff
            ),
            '',
        ]

    regress = 0
    noise = 0
    invalid = 0

    def section(title: str, header: str, rows: list[tuple[str, str]]) -> None:
        """rows: (status, markdown row); status is OK / REGRESSION / noise / COLLAPSE.

        Lists regressions and collapsed points, or every row with --all."""
        nonlocal regress, noise, invalid
        bad = sum(1 for s, _ in rows if s == 'REGRESSION')
        noisy = sum(1 for s, _ in rows if s == 'noise')
        broken = sum(1 for s, _ in rows if s == 'COLLAPSE')
        regress += bad
        noise += noisy
        invalid += broken
        shown = [r for s, r in rows if a.all or s in ('REGRESSION', 'COLLAPSE')]
        lines.extend(
            [
                f"## {title}",
                '',
                f"{len(rows)} compared 1 to 1, **{bad} regression(s)**, {noisy} above threshold but within noise"
                + (
                    f", **{broken} COLLAPSE** (a side below {MIN_RPS:g} req/s: unexplained throughput collapse, investigate)."
                    if broken
                    else '.'
                ),
                '',
            ]
        )
        if shown:
            lines.extend([header, '|' + '---|' * (header.count('|') - 1), *shown, ''])

    # Load tests: every (protocol, operation, concurrency) present in both versions.
    # Regression = throughput drop or p95 increase beyond the threshold.
    rows = []
    for k in sorted(old['load'].keys() & new['load'].keys()):
        o, n = old['load'][k], new['load'][k]
        d_tp, d_p95 = pct(o['throughput_rps'], n['throughput_rps']), pct(
            o['p95_ms'], n['p95_ms']
        )
        invalid_point = min(o['throughput_rps'], n['throughput_rps']) < MIN_RPS
        if invalid_point:
            status = 'COLLAPSE'
        else:
            status = 'REGRESSION' if max(-d_tp, d_p95) > th else 'OK'
        rows.append(
            (
                status,
                f"| {k[0]} | {k[1]} | {k[2]} | {o['throughput_rps']:.0f} -> {n['throughput_rps']:.0f} "
                f"({d_tp:+.1f}%) | {o['p95_ms']:.3f} -> {n['p95_ms']:.3f} ms ({d_p95:+.1f}%) | {status} |",
            )
        )
    section(
        'Load tests',
        '| Protocol | Operation | Concurrency | Throughput (req/s) | p95 latency | Status |',
        rows,
    )

    # Criterion: lower median time is better. A slowdown beyond the threshold only counts as a
    # regression when the confidence intervals do not overlap (new lower bound > old upper bound).
    rows = []
    for k in sorted(old['crit'].keys() & new['crit'].keys()):
        (o, _, o_hi), (n, n_lo, _) = old['crit'][k], new['crit'][k]
        d = pct(o, n)
        status = 'OK' if d <= th else ('REGRESSION' if n_lo > o_hi else 'noise')
        rows.append(
            (
                status,
                f"| {k} | {o / 1e3:.1f} -> {n / 1e3:.1f} us ({d:+.1f}%) | {status} |",
            )
        )
    section('Criterion micro-benchmarks', '| Benchmark | Median time | Status |', rows)

    missing = [('load', k) for k in old['load'].keys() ^ new['load'].keys()] + [
        ('criterion', k) for k in old['crit'].keys() ^ new['crit'].keys()
    ]
    # Encryption and signature algorithms must be compared 1 to 1: a gap there is a hard failure.
    strict = [
        m for m in missing if re.search(r'encrypt|sign', str(m[1]), re.IGNORECASE)
    ]
    # A category with data on either side but nothing in common means the keys do not line up.
    nothing_matched = [
        c
        for c in ('load', 'crit')
        if (old[c] or new[c]) and not old[c].keys() & new[c].keys()
    ]
    if missing:
        lines[3:3] = [
            f"> **WARNING: {len(missing)} benchmark(s) exist in only one version and were NOT compared"
            + (
                f", including {len(strict)} encryption/signature one(s)"
                if strict
                else ''
            )
            + (
                f" ({', '.join(nothing_matched)}: nothing matched at all, ids do not line up)"
                if nothing_matched
                else ''
            )
            + '.** See the list at the end of this report.',
            '',
        ]
        lines += ['## Not comparable (present in only one version)', '']
        lines += [f"- {kind}: `{k}`" for kind, k in sorted(missing, key=str)] + ['']
    lines += [
        '## Sources',
        '',
        f"- {a.base}: {old['url']}/",
        f"- {a.new}: {new['url']}/",
        '',
    ]

    report = '\n'.join(lines)
    print(report)
    if a.output:
        with open(a.output, 'w', encoding='utf-8') as f:
            f.write(report)
    return 1 if a.fail and (regress or invalid or nothing_matched or strict) else 0


if __name__ == '__main__':
    sys.exit(main())

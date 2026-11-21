#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Classify the files a pull request changes against .github/ci-paths.toml (stdlib only).

  ci_changes.py [--base REF] [--head REF]   print the units to run/skip, emit the $GITHUB_OUTPUT lines
  ci_changes.py --all                       not a pull request: every unit runs, no git diff
  test_ci_changes.py                        unit tests of this module on the real config (`mise run dev:ci-changes --self-test`)

The lines `skip=[...]`, `suites-matrix=[...]`, `run-test=<bool>` and `run-windows=<bool>` are appended to
$GITHUB_OUTPUT when set (and always printed): workflow jobs gate themselves with
`!contains(fromJSON(skip), '<unit>')`, the `test-suites` job of test_all.yml takes its legs from the matrix and main.yml
skips a whole reusable-workflow call when its `run-<caller>` is false. Fail-safe (strict units excepted): an empty diff, a file matching
`full`, or a file matching no unit and not `ignore`d skips nothing.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO = Path(
    subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
)
CONFIG = REPO / '.github' / 'ci-paths.toml'

VARIANTS = ('fips', 'non-fips')


@dataclass(frozen=True)
class Config:
    full: re.Pattern[str]
    ignore: re.Pattern[str]
    units: dict[str, list[re.Pattern[str]]]
    strict: frozenset[str]  # units that `full` and unmatched files never force
    variants: dict[
        str, list[str]
    ]  # suite unit -> variants of its matrix legs, in unit order
    bench: dict[
        str, dict[str, str]
    ]  # suite unit -> variant -> HSM models benchmarked after the tests
    callers: dict[str, list[str]]  # main.yml caller job -> its unit keys, in unit order


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def compile_pattern(key: str, value: object) -> re.Pattern[str]:
    if not isinstance(value, str):
        fail(f"{key}: expected a regex string")
    try:
        return re.compile(str(value), re.VERBOSE)
    except re.error as exc:
        fail(f"{key}: invalid regex: {exc}")
        raise  # unreachable, fail() exits


def load_config(path: Path) -> Config:
    with path.open('rb') as handle:
        raw = tomllib.load(handle)
    for key in ('full', 'ignore', 'units'):
        if key not in raw:
            fail(f"{path.name}: missing `{key}`")
    sets = {
        name: compile_pattern(f"sets.{name}", value)
        for name, value in raw.get('sets', {}).items()
    }
    units: dict[str, list[re.Pattern[str]]] = {}
    variants: dict[str, list[str]] = {}
    bench: dict[str, dict[str, str]] = {}
    strict: set[str] = set()
    for unit, spec in raw['units'].items():
        unknown = set(spec) - {'sets', 'files', 'variants', 'bench', 'strict'}
        if unknown:
            fail(f"units.{unit}: unknown key(s) {sorted(unknown)}")
        if not {'sets', 'files'} & set(spec):
            fail(f"units.{unit}: needs `sets` or `files`")
        if 'strict' in spec:
            if spec['strict'] is not True:
                fail(f"units.{unit}: `strict` must be true")
            if 'files' not in spec:
                fail(f"units.{unit}: a `strict` unit needs `files`")
            strict.add(unit)
        if 'variants' in spec:
            legs = spec['variants']
            if (
                not isinstance(legs, list)
                or not legs
                or any(v not in VARIANTS for v in legs)
                or len(set(legs)) != len(legs)
            ):
                fail(
                    f"units.{unit}: `variants` must be a non-empty list of distinct values among {list(VARIANTS)}"
                )
            variants[unit] = list(legs)
        models = spec.get('bench', {})
        if (
            not isinstance(models, dict)
            or not all(isinstance(m, str) for m in models.values())
            or set(models) - set(variants.get(unit, []))
        ):
            fail(
                f"units.{unit}: `bench` must map variants of the unit to a string of HSM models"
            )
        if models:
            bench[unit] = dict(models)
        patterns = []
        for name in spec.get('sets', []):
            if name not in sets:
                fail(f"units.{unit}: `sets` names unknown set `{name}`")
            patterns.append(sets[name])
        if 'files' in spec:
            patterns.append(compile_pattern(f"units.{unit}.files", spec['files']))
        units[unit] = patterns
    callers: dict[str, list[str]] = {}
    for name, pats in raw.get('callers', {}).items():
        if not isinstance(pats, list) or not all(isinstance(p, str) for p in pats):
            fail(f"callers.{name}: expected a list of unit patterns")
        for pat in pats:
            if not any(fnmatch.fnmatchcase(u, pat) for u in units):
                fail(f"callers.{name}: `{pat}` matches no unit")
        callers[name] = [
            u for u in units if any(fnmatch.fnmatchcase(u, p) for p in pats)
        ]
    return Config(
        full=compile_pattern('full', raw['full']),
        ignore=compile_pattern('ignore', raw['ignore']),
        units=units,
        variants=variants,
        bench=bench,
        strict=frozenset(strict),
        callers=callers,
    )


def changed_files(base: str, head: str) -> list[str]:
    def git(*args: str) -> str:
        return subprocess.run(
            ['git', *args], check=True, capture_output=True, text=True, cwd=REPO
        ).stdout

    merge = git('merge-base', base, head).strip()
    out = git('diff', '--name-only', '--no-renames', merge, head)
    return [line for line in out.splitlines() if line]


def classify(cfg: Config, files: list[str]) -> tuple[list[str], str]:
    if not files:
        return [], 'empty diff: run everything'
    triggered: set[str] = set()
    orphans = []
    for f in files:
        hits = {u for u, pats in cfg.units.items() if any(p.search(f) for p in pats)}
        triggered |= hits
        if not hits and not cfg.ignore.search(f):
            orphans.append(f)
    # `full` and orphans run everything except the strict units, which run only on their own files
    forced = next((f for f in files if cfg.full.search(f)), None)
    if forced:
        return sorted(cfg.strict - triggered), f"{forced} matches full: run everything"
    if orphans:
        return (
            sorted(cfg.strict - triggered),
            f"{orphans[0]} matches no unit and is not ignored: run everything",
        )
    return (
        sorted(set(cfg.units) - triggered),
        f"{len(triggered)} of {len(cfg.units)} units triggered",
    )


def outputs(cfg: Config, skipped: list[str]) -> dict[str, str]:
    """$GITHUB_OUTPUT values: `skip`, `suites-matrix` (legs of the running suite units) and one `run-<caller>` per caller."""
    compact = {'separators': (',', ':')}
    legs = [
        {
            'suite': unit,
            'variant': variant,
            'bench': cfg.bench.get(unit, {}).get(variant, ''),
        }
        for unit, variants in cfg.variants.items()
        if unit not in skipped
        for variant in variants
    ]
    result = {
        'skip': json.dumps(skipped, **compact),
        'suites-matrix': json.dumps(legs, **compact),
    }
    for caller, units in cfg.callers.items():
        result[f"run-{caller}"] = str(any(u not in skipped for u in units)).lower()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--base', default='HEAD^1')
    parser.add_argument('--head', default='HEAD')
    parser.add_argument(
        '--all', action='store_true', help='not a pull request: run everything'
    )
    args = parser.parse_args()

    cfg = load_config(CONFIG)
    if args.all:
        files, skipped, reason = [], [], 'not a pull request: run everything'
    else:
        files = changed_files(args.base, args.head)
        skipped, reason = classify(cfg, files)

    print(f"Changed files ({len(files)}):")
    for f in files:
        print(f"  {f}")
    print(reason)
    for unit in cfg.units:
        print(f'{"SKIP" if unit in skipped else "RUN "} {unit}')

    lines = [f"{key}={value}" for key, value in outputs(cfg, skipped).items()]
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
    for line in lines:
        print(line)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Classify the files a pull request changes against .github/ci-paths.toml (stdlib only).

  ci_changes.py [--base REF] [--head REF]   print the units to run/skip, emit `skip=<JSON list>`
  ci_changes.py --self-test                 assert the real config on representative change sets

The output line `skip=[...]` is appended to $GITHUB_OUTPUT when set (and always printed) so workflow jobs can
gate themselves with `!contains(fromJSON(...), '<unit>')`. Fail-safe: an empty diff, a file matching `full`, or a
file matching no unit and not `ignore`d skips nothing.
"""

from __future__ import annotations

import argparse
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


@dataclass(frozen=True)
class Config:
    full: re.Pattern[str]
    ignore: re.Pattern[str]
    units: dict[str, list[re.Pattern[str]]]


def fail(message: str) -> None:
    print(f'ERROR: {message}', file=sys.stderr)
    sys.exit(1)


def compile_pattern(key: str, value: object) -> re.Pattern[str]:
    if not isinstance(value, str):
        fail(f'{key}: expected a regex string')
    try:
        return re.compile(str(value), re.VERBOSE)
    except re.error as exc:
        fail(f'{key}: invalid regex: {exc}')
        raise  # unreachable, fail() exits


def load_config(path: Path) -> Config:
    with path.open('rb') as handle:
        raw = tomllib.load(handle)
    for key in ('full', 'ignore', 'units'):
        if key not in raw:
            fail(f'{path.name}: missing `{key}`')
    sets = {
        name: compile_pattern(f'sets.{name}', value)
        for name, value in raw.get('sets', {}).items()
    }
    units: dict[str, list[re.Pattern[str]]] = {}
    for unit, spec in raw['units'].items():
        unknown = set(spec) - {'sets', 'files'}
        if unknown:
            fail(f'units.{unit}: unknown key(s) {sorted(unknown)}')
        if not spec:
            fail(f'units.{unit}: needs `sets` or `files`')
        patterns = []
        for name in spec.get('sets', []):
            if name not in sets:
                fail(f'units.{unit}: `sets` names unknown set `{name}`')
            patterns.append(sets[name])
        if 'files' in spec:
            patterns.append(compile_pattern(f'units.{unit}.files', spec['files']))
        units[unit] = patterns
    return Config(
        full=compile_pattern('full', raw['full']),
        ignore=compile_pattern('ignore', raw['ignore']),
        units=units,
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
    for f in files:
        if cfg.full.search(f):
            return [], f'{f} matches full: run everything'
    triggered: set[str] = set()
    orphans = []
    for f in files:
        hits = {u for u, pats in cfg.units.items() if any(p.search(f) for p in pats)}
        triggered |= hits
        if not hits and not cfg.ignore.search(f):
            orphans.append(f)
    if orphans:
        return [], f'{orphans[0]} matches no unit and is not ignored: run everything'
    return (
        sorted(set(cfg.units) - triggered),
        f'{len(triggered)} of {len(cfg.units)} units triggered',
    )


def self_test() -> None:
    cfg = load_config(CONFIG)
    everything = set(cfg.units)

    def run(files: list[str]) -> set[str]:
        return everything - set(classify(cfg, files)[0])

    assert classify(cfg, [])[0] == []
    assert run(['documentation/docs/index.md', 'CHANGELOG/x.md']) == set()
    assert run(['ui/src/App.tsx']) == {'ui', 'windows-ui'}
    assert run(['.mise/scripts/test/test_iris.sh']) == {'interop:iris'}
    for files in (
        ['crate/kmip/src/lib.rs'],
        ['crate/server_database/src/stores/sql/query.sql'],
        ['.mise/lib/common.sh'],
        ['test_data'],
        ['brand/new.txt'],
    ):
        assert run(files) == everything, files

    xks = run(['crate/server/src/routes/aws_xks/mod.rs'])
    assert {
        'cloud',
        'xks-remote',
        'db:sqlite',
        'no-nix',
        'cargo-clippy',
        'windows-cargo-test',
    } <= xks
    assert not {'db:psql', 'hsm', 'ui'} & xks

    pg = run(['crate/server_database/src/stores/sql/pgsql.rs'])
    assert {'db:psql', 'db:openbao', 'interop:ssh-secrets', 'db:sqlite'} <= pg
    assert not {'db:mysql', 'interop:ase'} & pg

    utimaco = run(['crate/hsm/utimaco/src/lib.rs'])
    assert {'hsm', 'windows-hsm-idemia'} <= utimaco
    assert not {'pkcs11', 'db:psql'} & utimaco
    print('self-test OK')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--base', default='HEAD^1')
    parser.add_argument('--head', default='HEAD')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return

    cfg = load_config(CONFIG)
    files = changed_files(args.base, args.head)
    skipped, reason = classify(cfg, files)

    print(f'Changed files ({len(files)}):')
    for f in files:
        print(f'  {f}')
    print(reason)
    for unit in cfg.units:
        print(f'{"SKIP" if unit in skipped else "RUN "} {unit}')

    line = f'skip={json.dumps(skipped, separators=(",", ":"))}'
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')
    print(line)


if __name__ == '__main__':
    main()

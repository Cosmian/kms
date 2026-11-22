#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Classify the files a pull request changes against .github/ci-paths.toml (stdlib only).

  ci_changes.py [--base REF] [--head REF]   print the units to run/skip, emit the $GITHUB_OUTPUT line
  ci_changes.py --all --event EVENT         schedule, tag or workflow_dispatch: no git diff, every unit of that event
  test_ci_changes.py                        unit tests of this module on the real config (`mise run dev:ci-changes --self-test`)

  --no-secrets   Cosmian/kms secrets unavailable (other repository or fork PR): drop the `upstream` units
  --fork-pr      pull request from a fork: drop the `no-fork-pr` units
  --dependabot   Dependabot pull request: keep only the `dependabot` units

The line `suites-matrix=[...]` is appended to $GITHUB_OUTPUT when set (and always printed): the legs of the running
units, which the `test-suites` job of test_all.yml runs through test-group.yml. Fail-safe (strict units excepted): an empty
diff, a file matching `full`, or a file matching no unit and not `ignore`d skips nothing.
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

VARIANTS = ('fips', 'non-fips')
EVENTS = ('pull_request', 'schedule', 'tag', 'workflow_dispatch')
SETUPS = ('nix', 'plain', 'windows')
UNIT_KEYS = {
    'sets',
    'files',
    'variants',
    'bench',
    'strict',
    'runners',
    'setup',
    'timeout',
    'lock',
    'environment',
    'events',
    'upstream',
    'no-fork-pr',
    'dependabot',
}


@dataclass(frozen=True)
class Legs:
    variants: tuple[str, ...]  # ('',) when the unit declares none
    runners: tuple[str, ...]
    setup: str
    timeout: int
    lock: str
    environment: str
    events: frozenset[str]
    upstream: bool
    no_fork_pr: bool
    dependabot: bool


@dataclass(frozen=True)
class Config:
    full: re.Pattern[str]
    ignore: re.Pattern[str]
    units: dict[str, list[re.Pattern[str]]]
    strict: frozenset[str]  # units that `full` and unmatched files never force
    bench: dict[
        str, dict[str, str]
    ]  # suite unit -> variant -> HSM models benchmarked after the tests
    legs: dict[str, Legs]  # every unit -> its legs, in unit order


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


def distinct(value: object, allowed: tuple[str, ...] | None) -> bool:
    """A non-empty list of distinct strings, all among `allowed` when given."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(v, str) and v and (allowed is None or v in allowed)
            for v in value
        )
        and len(set(value)) == len(value)
    )


def load_unit(unit: str, spec: dict[str, object]) -> Legs:
    """Validate the leg keys of one unit and apply their defaults."""
    if 'variants' in spec and not distinct(spec['variants'], VARIANTS):
        fail(
            f"units.{unit}: `variants` must be a non-empty list of distinct values among {list(VARIANTS)}"
        )
    if 'runners' in spec and not distinct(spec['runners'], None):
        fail(
            f"units.{unit}: `runners` must be a non-empty list of distinct runner labels"
        )
    if 'events' in spec and not distinct(spec['events'], EVENTS):
        fail(
            f"units.{unit}: `events` must be a non-empty list of distinct values among {list(EVENTS)}"
        )
    setup = spec.get('setup', 'nix')
    if setup not in SETUPS:
        fail(f"units.{unit}: `setup` must be one of {list(SETUPS)}")
    timeout = spec.get('timeout', 360)
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 1 <= timeout <= 360
    ):
        fail(f"units.{unit}: `timeout` must be an integer between 1 and 360")
    for key in ('lock', 'environment'):
        if key in spec and not (isinstance(spec[key], str) and spec[key]):
            fail(f"units.{unit}: `{key}` must be a non-empty string")
    for key in ('upstream', 'no-fork-pr', 'dependabot'):
        if key in spec and spec[key] is not True:
            fail(f"units.{unit}: `{key}` must be true")
    runners = tuple(spec.get('runners', ['ubuntu-24.04']))
    if (setup == 'windows') != all(r.startswith('windows-') for r in runners):
        fail(
            f'units.{unit}: `runners` must be windows-* runners exactly when setup = "windows"'
        )
    if setup == 'nix' and not all(r.startswith('ubuntu-') for r in runners):
        fail(f'units.{unit}: setup = "nix" needs ubuntu-* runners')
    return Legs(
        variants=tuple(spec.get('variants', [''])),
        runners=runners,
        setup=setup,
        timeout=timeout,
        lock=spec.get('lock', ''),
        environment=spec.get('environment', ''),
        events=frozenset(spec.get('events', EVENTS)),
        upstream='upstream' in spec,
        no_fork_pr='no-fork-pr' in spec,
        dependabot='dependabot' in spec,
    )


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
    legs: dict[str, Legs] = {}
    bench: dict[str, dict[str, str]] = {}
    strict: set[str] = set()
    for unit, spec in raw['units'].items():
        unknown = set(spec) - UNIT_KEYS
        if unknown:
            fail(f"units.{unit}: unknown key(s) {sorted(unknown)}")
        if not {'sets', 'files'} & set(spec):
            fail(f"units.{unit}: needs `sets` or `files`")
        if 'strict' in spec:
            if spec['strict'] is not True:
                fail(f"units.{unit}: `strict` must be true")
            strict.add(unit)
        legs[unit] = load_unit(unit, spec)
        models = spec.get('bench', {})
        if (
            not isinstance(models, dict)
            or not all(isinstance(m, str) for m in models.values())
            or set(models) - set(spec.get('variants', []))
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
    return Config(
        full=compile_pattern('full', raw['full']),
        ignore=compile_pattern('ignore', raw['ignore']),
        units=units,
        strict=frozenset(strict),
        bench=bench,
        legs=legs,
    )


def changed_files(base: str, head: str) -> list[str]:
    def git(*args: str) -> str:
        return subprocess.run(
            ['git', *args], check=True, capture_output=True, text=True, cwd=REPO
        ).stdout

    merge = git('merge-base', base, head).strip()
    # -z: raw NUL-separated paths; without it git quotes non-ASCII names ("calf\303\251.rs"), which match no pattern.
    out = git('diff', '--name-only', '-z', '--no-renames', merge, head)
    return [path for path in out.split('\0') if path]


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


def running(
    cfg: Config,
    skipped: list[str],
    event: str,
    secrets: bool,
    fork_pr: bool,
    dependabot: bool,
) -> list[str]:
    """Units with legs: not skipped by the diff, `event` in their events, not `upstream` without secrets,
    not `no-fork-pr` on a fork PR, and `dependabot` when `dependabot` is set."""
    return [
        unit
        for unit, leg in cfg.legs.items()
        if unit not in skipped
        and event in leg.events
        and (secrets or not leg.upstream)
        and not (fork_pr and leg.no_fork_pr)
        and (leg.dependabot or not dependabot)
    ]


def outputs(
    cfg: Config,
    skipped: list[str],
    event: str = 'pull_request',
    secrets: bool = True,
    fork_pr: bool = False,
    dependabot: bool = False,
) -> dict[str, str]:
    """$GITHUB_OUTPUT values: `suites-matrix`, the legs of the running units."""
    legs = [
        {
            'suite': unit,
            'variant': variant,
            'runner': runner,
            'setup': leg.setup,
            'bench': cfg.bench.get(unit, {}).get(variant, ''),
            'timeout': leg.timeout,
            'lock': leg.lock,
            'environment': leg.environment,
        }
        for unit in running(cfg, skipped, event, secrets, fork_pr, dependabot)
        for leg in [cfg.legs[unit]]
        for runner in leg.runners
        for variant in leg.variants
    ]
    return {'suites-matrix': json.dumps(legs, separators=(',', ':'))}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    # CI passes --base HEAD^1 (the base tip of the PR test merge commit); locally diff from the PR's base branch,
    # so every commit of the branch counts, not only the last one.
    parser.add_argument(
        '--base', default=f'origin/{os.environ.get("GITHUB_BASE_REF") or "develop"}'
    )
    parser.add_argument('--head', default='HEAD')
    parser.add_argument(
        '--all', action='store_true', help='not a pull request: ignore the diff'
    )
    parser.add_argument(
        '--event',
        choices=EVENTS[1:],
        help='event of an --all run (default: pull request)',
    )
    parser.add_argument(
        '--no-secrets',
        action='store_true',
        help='Cosmian/kms secrets unavailable: drop the upstream units',
    )
    parser.add_argument(
        '--fork-pr', action='store_true', help='pull request from a fork'
    )
    parser.add_argument(
        '--dependabot', action='store_true', help='Dependabot pull request'
    )
    args = parser.parse_args()
    if args.all != (args.event is not None) or (
        args.all and (args.fork_pr or args.dependabot)
    ):
        parser.error(
            '--all needs --event; --event, --fork-pr and --dependabot belong to one mode only'
        )

    cfg = load_config(CONFIG)
    if args.all:  # nightly, tag and dispatch never read the diff
        files, skipped, reason = [], [], 'not a pull request: run everything'
    else:
        files = changed_files(args.base, args.head)
        skipped, reason = classify(cfg, files)
    event = args.event or 'pull_request'

    print(f"Changed files ({len(files)}):")
    for f in files:
        print(f"  {f}")
    print(reason)
    run = set(
        running(cfg, skipped, event, not args.no_secrets, args.fork_pr, args.dependabot)
    )
    for unit in cfg.units:
        print(f'{"RUN " if unit in run else "SKIP"} {unit}')

    lines = [
        f"{key}={value}"
        for key, value in outputs(
            cfg, skipped, event, not args.no_secrets, args.fork_pr, args.dependabot
        ).items()
    ]
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
    for line in lines:
        print(line)


if __name__ == '__main__':
    main()

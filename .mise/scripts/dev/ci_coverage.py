#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CI coverage guards (stdlib only).

  ci_coverage.py tasks [--strict]          mise tasks that no CI job reaches
  ci_coverage.py ignored-tests [--strict] [--ci]
                                           #[ignore] Rust tests that no `cargo test --ignored` in any MISE script runs
                                           (--ci: only in the scripts a CI workflow reaches)

"Reached by CI" is a static approximation, see the helpers below. It over-approximates (a task named in a
non-comment, non-print line of a reachable file counts as called) so the inventories only list what is
certainly not wired. Dynamic task names or test filters built at runtime are not resolved.
"""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(
    subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
)
TASKS_DIR = REPO / '.mise' / 'tasks'
CI_GLOBS = [
    '.github/workflows/*.yml',
    '.github/workflows/*.yaml',
    '.github/actions/**/*.yml',
    '.github/reusable_scripts/**/*.sh',
]
# A line that only prints or documents a command must not count as calling it.
NON_CALL_LINE = re.compile(r'^\s*(#|echo\b|printf\b|print_[a-z]+\b)')
SCRIPT_REF = re.compile(r'\.mise/(?:scripts|lib)/[\w./-]+\.(?:sh|py)')
TASK_FILE_REF = re.compile(r'\.mise/tasks/([\w./-]+)')
MISE_RUN = re.compile(r'\bmise\s+(?:run|r)\s+((?:-\S+\s+)*)([A-Za-z0-9_:-]+)')
LEAVES_CALL = re.compile(r"run_test_leaves\s+\"\$\(dirname \"\$0\"\)\"\s+(.+)")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding='utf-8', errors='replace').splitlines()


def call_lines(path: Path) -> list[str]:
    """Lines of `path` that can actually execute something (no comment, echo or print line)."""
    return [ln for ln in read_lines(path) if not NON_CALL_LINE.match(ln)]


def task_id_of(path: Path) -> str:
    """`.mise/tasks/test/db/_default` -> `test:db`, `.mise/tasks/test/db/psql` -> `test:db:psql`."""
    parts = list(path.relative_to(TASKS_DIR).parts)
    if parts[-1] == '_default':
        parts.pop()
    return ':'.join(parts)


def load_tasks() -> dict[str, dict]:
    out = subprocess.check_output(
        ['mise', 'tasks', 'ls', '--json', '--hidden'], cwd=REPO, text=True
    )
    return {t['name']: t for t in json.loads(out)}


# ── CI roots ─────────────────────────────────────────────────────────────────────────────────────


def ci_files() -> list[Path]:
    return sorted({p for g in CI_GLOBS for p in REPO.glob(g) if p.is_file()})


def yaml_suite_ids(lines: list[str]) -> set[str]:
    """Ids of every `suite:`/`suites:` value of a test_all.yml matrix (inline or folded block), as `test:<id>`."""
    ids: set[str] = set()
    i = 0
    while i < len(lines):
        m = re.match(r'^(\s*)(?:-\s+)?(?:.*[{,]\s*)?suites?:\s*(.*)$', lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2)
        chunk = [rest]
        if rest.strip() in ('>', '>-', '|', '|-'):
            chunk = []
            i += 1
            while i < len(lines) and (
                not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > indent
            ):
                chunk.append(lines[i])
                i += 1
        else:
            i += 1
        for tok in re.findall(r'[a-z0-9][a-z0-9:-]*', ' '.join(chunk)):
            ids.add(f"test:{tok}")
    return ids


def ci_roots(tasks: dict[str, dict]) -> set[str]:
    roots: set[str] = set()
    for f in ci_files():
        lines = [ln for ln in read_lines(f) if not ln.lstrip().startswith('#')]
        roots |= yaml_suite_ids(lines)
        for ln in lines:
            for m in MISE_RUN.finditer(ln):
                roots.add(m.group(2))
            m = re.match(
                r'^\s*-?\s*task:\s*([A-Za-z0-9_:-]+)', ln
            )  # packaging matrices: `task: test:k8s:plugin`
            if m:
                roots.add(m.group(1))
            for m in TASK_FILE_REF.finditer(ln):
                roots.add(task_id_of(TASKS_DIR / m.group(1)))
    return {r for r in roots if r in tasks}


# ── Reachability ─────────────────────────────────────────────────────────────────────────────────


def referenced_scripts(path: Path, seen: set[Path]) -> set[Path]:
    """`path` plus every `.mise/scripts/*` and `.mise/lib/*` file it names, transitively."""
    if path in seen or not path.is_file():
        return seen
    seen.add(path)
    for ln in call_lines(path):
        for m in SCRIPT_REF.finditer(ln):
            referenced_scripts(REPO / m.group(0), seen)
    return seen


def task_files(task: dict) -> set[Path]:
    return referenced_scripts(Path(task['file']), set())


def task_edges(
    tid: str, task: dict, tasks: dict[str, dict], files: set[Path]
) -> set[str]:
    edges: set[str] = set()
    for key in ('depends', 'depends_post', 'wait_for'):
        for dep in task.get(key) or []:
            name = (dep if isinstance(dep, str) else dep[0]).split()[0]
            edges.add(name)
    for f in files:
        for ln in call_lines(f):
            for m in MISE_RUN.finditer(ln):
                edges.add(m.group(2))
            for m in TASK_FILE_REF.finditer(ln):
                edges.add(task_id_of(TASKS_DIR / m.group(1)))
            m = LEAVES_CALL.search(ln)
            if m and f == Path(task['file']):
                group = f.parent.relative_to(TASKS_DIR).parts
                for leaf in shlex.split(m.group(1)):
                    leaf_parts = [p for p in leaf.split('/') if p != '_default']
                    edges.add(':'.join([*group, *leaf_parts]))
    return {e for e in edges if e in tasks and e != tid}


def reachable(tasks: dict[str, dict]) -> tuple[set[str], set[Path]]:
    """Task ids CI runs directly or through other tasks, and every file those tasks execute."""
    todo = sorted(ci_roots(tasks))
    seen: set[str] = set()
    files: set[Path] = set(ci_files())
    while todo:
        tid = todo.pop()
        if tid in seen:
            continue
        seen.add(tid)
        tfiles = task_files(tasks[tid])
        files |= tfiles
        todo.extend(task_edges(tid, tasks[tid], tasks, tfiles) - seen)
    return seen, files


# ── 1. tasks not called in CI ────────────────────────────────────────────────────────────────────


def cmd_tasks(strict: bool) -> int:
    tasks = load_tasks()
    called, _ = reachable(tasks)
    missing = sorted(set(tasks) - called)
    print(
        f"{len(missing)} of {len(tasks)} mise tasks are not called by any CI workflow (directly or via another task):\n"
    )
    width = max((len(t) for t in missing), default=0)
    for tid in missing:
        print(f"  {tid:<{width}}  {tasks[tid].get('description') or ''}")
    return 1 if strict and missing else 0


# ── 2. #[ignore] Rust tests not called in CI ─────────────────────────────────────────────────────


def blank_non_code(src: str) -> str:
    """`src` with comments, string and char literals replaced by spaces (same offsets, newlines kept)."""
    out = list(src)
    i, n = 0, len(src)

    def blank(a: int, b: int) -> None:
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '

    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif src.startswith('/*', i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith('/*', j):
                    depth, j = depth + 1, j + 2
                elif src.startswith('*/', j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif (
            c == 'r'
            and re.match(r'r#*"', src[i : i + 40])
            and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_'))
        ):
            hashes = len(re.match(r'r(#*)', src[i:]).group(1))
            end = src.find('"' + '#' * hashes, i + 2 + hashes)
            j = n if end < 0 else end + 1 + hashes
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'":
            m = re.match(
                r"'(?:\\.[^']*|[^\\'])'", src[i : i + 12]
            )  # char literal, not a lifetime
            if m:
                blank(i, i + m.end())
                i += m.end()
            else:
                i += 1
        else:
            i += 1
    return ''.join(out)


IGNORE_ATTR = re.compile(r'\s*ignore\b')
TOKEN = re.compile(r'#\s*\[|\bmod\s+(\w+)\s*\{|\bfn\s+(\w+)|\{|\}')


def ignored_in(path: Path) -> list[tuple[list[str], str, int, str]]:
    """(inline mod path, fn name, line, reason) of each unconditionally `#[ignore]`d fn in `path`."""
    src = path.read_text(encoding='utf-8', errors='replace')
    code = blank_non_code(src)
    found, stack, pending = [], [], None
    for m in TOKEN.finditer(code):
        tok = m.group(0)
        if tok.startswith('#'):
            depth, j = 1, m.end()
            while j < len(code) and depth:
                depth += (code[j] == '[') - (code[j] == ']')
                j += 1
            attr = code[m.end() : j - 1]
            if IGNORE_ATTR.match(
                attr
            ):  # cfg_attr(cond, ignore) is conditional: CI runs it without --ignored
                reason = re.search(
                    r'ignore\s*=\s*"((?:[^"\\]|\\.)*)"', src[m.end() : j - 1], re.S
                )
                text = re.sub(r'\\\n\s*', '', reason.group(1)) if reason else ''
                pending = (src.count('\n', 0, m.start()) + 1, ' '.join(text.split()))
        elif m.group(1):
            stack.append(m.group(1))
        elif m.group(2):
            if pending:
                found.append(
                    ([s for s in stack if s], m.group(2), pending[0], pending[1])
                )
                pending = None
        elif tok == '{':
            stack.append('')
        else:
            if stack:
                stack.pop()
    return found


def crate_of(path: Path, crates: dict[Path, str]) -> tuple[Path, str] | None:
    for parent in path.parents:
        if parent in crates:
            return parent, crates[parent]
    return None


def module_path(path: Path, crate_dir: Path) -> tuple[list[str], str]:
    """File-derived module path and target kind (`lib` for src/, otherwise the integration binary name)."""
    rel = path.relative_to(crate_dir).parts
    if rel[0] == 'src':
        mods = list(rel[1:])
        mods[-1] = Path(mods[-1]).stem
        if mods[-1] in ('lib', 'main', 'mod'):
            mods.pop()
        return mods, 'lib'
    if rel[0] == 'tests':
        name = Path(rel[1]).stem
        mods = [Path(p).stem for p in rel[2:] if Path(p).stem != 'mod']
        return mods, name
    return [], 'other'


class CargoRun:
    """One `cargo test ... --ignored` command found in a CI-reachable file."""

    VALUED = {
        '-p',
        '--package',
        '--features',
        '-F',
        '--test',
        '--bin',
        '--manifest-path',
        '--profile',
        '--target-dir',
        '--skip',
        '--test-threads',
    }

    def __init__(self, tokens: list[str]) -> None:
        for k, t in enumerate(
            tokens
        ):  # `| tee log` and redirections are not test filters
            if t in ('|', '&', '>', '>>') or re.fullmatch(r'\d*>&?\d*', t):
                tokens = tokens[:k]
                break
        self.exact = '--exact' in tokens
        self.packages: set[str] = set()
        self.test_bin: str | None = None
        self.lib_only = '--lib' in tokens
        self.filters: list[re.Pattern[str]] = []
        self.opaque_filter = False
        start, seen_cargo = 0, False
        for k, t in enumerate(tokens):
            seen_cargo = (
                seen_cargo or t == 'cargo'
            )  # `cargo +toolchain test`: tokens sit between the two words
            if t == 'run_cargo_test' or (t == 'test' and seen_cargo):
                start = k + 1
                break
        k = start
        while k < len(tokens):
            t = tokens[k]
            value = tokens[k + 1] if k + 1 < len(tokens) else ''
            if t in ('-p', '--package'):
                self.packages.add(value)
                k += 2
            elif t == '--test':
                self.test_bin = value
                k += 2
            elif t in self.VALUED:
                k += 2
            elif t.startswith('-') or t in ('&&', '||', '|', ';', '&', '2>&1', '>'):
                k += 1
            elif re.fullmatch(r'[\w:${}]+', t) and re.search(
                r'[A-Za-z]', re.sub(r'\$\{[^}]*\}|\$\w+', '', t)
            ):
                rx = re.sub(r'\\\$\\\{[^}]*\\\}|\\\$\w+', r'[\\w:]*', re.escape(t))
                self.filters.append(re.compile(rx))
                k += 1
            else:
                self.opaque_filter = (
                    True  # "$@" or a bare variable: filters we cannot see
                )
                k += 1

    def covers(self, pkg: str, kind: str, qualified: str) -> bool:
        if self.opaque_filter and not self.filters:
            return False
        if self.packages and pkg not in self.packages:
            return False
        if self.test_bin and kind != self.test_bin:
            return False
        if self.lib_only and kind != 'lib':
            return False
        if not self.filters:
            return True
        match = (
            (lambda rx: rx.fullmatch(qualified))
            if self.exact
            else (lambda rx: rx.search(qualified))
        )
        return any(match(rx) for rx in self.filters)


def cargo_runs(files: set[Path]) -> list[CargoRun]:
    runs = []
    for f in sorted(files):
        if not f.is_file():
            continue
        logical, buf = [], ''
        for ln in call_lines(f):
            buf += (
                ln.rstrip('\\').rstrip() + ' '
                if ln.rstrip().endswith('\\')
                else ln + '\n'
            )
            if not ln.rstrip().endswith('\\'):
                logical.append(buf)
                buf = ''
        for cmd in logical:
            if '--ignored' not in cmd:
                continue
            for part in re.split(r'\n|&&|\|\||;', cmd):
                if '--ignored' in part:
                    try:
                        toks = shlex.split(part, comments=False, posix=True)
                    except ValueError:
                        toks = part.split()
                    runs.append(CargoRun(toks))
    return runs


def mise_files() -> set[Path]:
    """Every tracked task, script and lib under .mise/ that can hold a cargo command."""
    names = subprocess.check_output(
        ['git', 'ls-files', '.mise'], cwd=REPO, text=True
    ).split('\n')
    return {REPO / n for n in names if n and Path(n).suffix in ('', '.sh', '.py')}


def cmd_ignored(strict: bool, ci_only: bool) -> int:
    files = reachable(load_tasks())[1] if ci_only else mise_files()
    runs = cargo_runs(files)
    scope = 'reachable from CI' if ci_only else 'in the MISE scripts'
    manifests = subprocess.check_output(
        ['git', 'ls-files', '*Cargo.toml'], cwd=REPO, text=True
    ).split()
    crates = {}
    for mf in manifests:
        m = re.search(
            r'^\[package\][^\[]*?^name\s*=\s*"([^"]+)"',
            (REPO / mf).read_text(),
            re.M | re.S,
        )
        if m:
            crates[(REPO / mf).parent] = m.group(1)
    uncovered, total = defaultdict(list), 0
    for rs in subprocess.check_output(
        ['git', 'ls-files', '*.rs'], cwd=REPO, text=True
    ).split():
        path = REPO / rs
        if not path.is_file():
            continue
        crate = crate_of(path, crates)
        if not crate or '#' not in path.read_text(encoding='utf-8', errors='replace'):
            continue
        hits = ignored_in(path)
        if not hits:
            continue
        crate_dir, pkg = crate
        file_mods, kind = module_path(path, crate_dir)
        for inline_mods, fn, line, reason in hits:
            total += 1
            qualified = '::'.join([*file_mods, *inline_mods, fn])
            if not any(r.covers(pkg, kind, qualified) for r in runs):
                uncovered[reason or '(no reason)'].append(
                    f"{rs}:{line}  {pkg}  {qualified}"
                )
    missing = sum(len(v) for v in uncovered.values())
    print(
        f"{missing} of {total} #[ignore] Rust tests are not run by any `cargo test --ignored` {scope}:\n"
    )
    for reason, items in sorted(uncovered.items(), key=lambda kv: -len(kv[1])):
        print(f"## {reason}  ({len(items)})")
        for it in sorted(items):
            print(f"  {it}")
        print()
    return 1 if strict and missing else 0


def main(argv: list[str]) -> int:
    allowed = {'--strict'} | ({'--ci'} if argv[1:2] == ['ignored-tests'] else set())
    if (
        len(argv) < 2
        or argv[1] not in ('tasks', 'ignored-tests')
        or set(argv[2:]) - allowed
    ):
        print(__doc__, file=sys.stderr)
        return 2
    strict = '--strict' in argv[2:]
    return (
        cmd_tasks(strict)
        if argv[1] == 'tasks'
        else cmd_ignored(strict, '--ci' in argv[2:])
    )


if __name__ == '__main__':
    sys.exit(main(sys.argv))

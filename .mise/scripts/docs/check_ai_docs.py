#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Check (and auto-fix) consistency of the AI instruction files.

Files in scope: AGENTS.md, CONTRIBUTING.md, .github/copilot-instructions.md,
.github/instructions/*.instructions.md and .github/skills/**.

Checks:
  C1  instruction tables in AGENTS.md / copilot-instructions.md match the
      `applyTo` frontmatter of every instruction file          (FIXABLE)
  C2  instruction + skill frontmatter is complete and consistent
  C3  every skill is listed in .github/skills/README.md
  C4  every `/slash-command` reference names an existing skill
  C5  relative Markdown links (and #anchors) resolve
  C6  `.github/...` paths quoted in backticks exist

Usage:
  python3 .mise/scripts/docs/check_ai_docs.py            # check only
  python3 .mise/scripts/docs/check_ai_docs.py --fix      # apply fixable corrections
  python3 .mise/scripts/docs/check_ai_docs.py --self-test

Output: `ERROR <relpath>:<line>: <message>` or `FIXED <relpath>: <message>`.
Exit 0 only when nothing is printed (a FIXED line fails so the files get re-staged).
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Iterator

SCRIPT_DIR = Path(__file__).resolve().parent


def _find_repo_root() -> Path:
    """Walk up from script dir looking for a directory with Cargo.toml + crate/."""
    p = SCRIPT_DIR
    for _ in range(12):
        if (p / 'Cargo.toml').exists() and (p / 'crate').is_dir():
            return p
        p = p.parent
    raise RuntimeError(f"Could not find repo root from {SCRIPT_DIR}")


ROW_RE = re.compile(r'^\|\s*`([a-z0-9-]+)\.instructions\.md`\s*\|')
SLASH_RE = re.compile(r'^/([a-z][a-z0-9-]*)(\s.*)?$')
GH_PATH_RE = re.compile(r'^\.github/[A-Za-z0-9_./-]+$')
LINK_RE = re.compile(r'\]\(([^)\s]+)(?:\s+"[^"]*")?\)')
SPAN_RE = re.compile(r'`([^`]+)`')
HEADING_RE = re.compile(r'^#{1,6}\s')
# `/skill-name` is the documented placeholder in AGENTS.md section 9 and skills/README.md.
SLASH_ALLOWLIST = {'skill-name'}


# ── helpers ────────────────────────────────────────────────────────────────


def parse_frontmatter(path: Path) -> dict[str, str]:
    """Return the `key: value` pairs of a leading `---` frontmatter block."""
    lines = path.read_text(encoding='utf-8').splitlines()
    if not lines or lines[0].strip() != '---':
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == '---':
            break
        key, sep, value = line.partition(':')
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
            value = value[1:-1]
        out[key.strip()] = value
    return out


def split_globs(s: str) -> list[str]:
    """Split a comma-separated glob list on commas outside `{...}`."""
    parts: list[str] = []
    depth = 0
    cur = ''
    for ch in s:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(cur)
            cur = ''
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def canonical_cell(globs: list[str]) -> str:
    """Render globs as the canonical table cell."""
    return ', '.join(f'`{g}`' for g in globs)


def slugify(heading: str) -> str:
    """GitHub heading anchor."""
    s = re.sub(r'[^\w\- ]', '', heading.strip().lower())
    return s.replace(' ', '-')


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (1-based lineno, line) outside fenced code blocks."""
    in_fence = False
    for no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith('```'):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield no, line


def strip_inline_code(line: str) -> str:
    """Remove backtick spans."""
    return SPAN_RE.sub('', line)


def heading_slugs(path: Path) -> set[str]:
    """All anchors of a Markdown file, with GitHub's -N suffix for duplicates."""
    seen: dict[str, int] = {}
    slugs: set[str] = set()
    for _, line in iter_lines(path.read_text(encoding='utf-8')):
        if HEADING_RE.match(line):
            base = slugify(line.lstrip('#'))
            n = seen.get(base, 0)
            seen[base] = n + 1
            slugs.add(base if n == 0 else f'{base}-{n}')
    return slugs


def split_cells(line: str) -> list[str]:
    """Split a Markdown table row into stripped cells."""
    return [c.strip() for c in line.strip().strip('|').split('|')]


# ── repo model ─────────────────────────────────────────────────────────────


class Repo:
    """Paths and parsed metadata of the AI files."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.skills_dir = root / '.github' / 'skills'
        self.instr_dir = root / '.github' / 'instructions'
        self.instructions = sorted(self.instr_dir.glob('*.instructions.md'))
        self.skills = sorted(
            d.name
            for d in self.skills_dir.iterdir()
            if d.is_dir() and d.name != 'shared'
        )
        self.table_files = [
            root / 'AGENTS.md',
            root / '.github' / 'copilot-instructions.md',
        ]
        self.slash_files = [
            root / 'AGENTS.md',
            root / '.github' / 'copilot-instructions.md',
            root / 'CONTRIBUTING.md',
            self.skills_dir / 'README.md',
            *sorted(self.skills_dir.glob('*/SKILL.md')),
        ]
        self.link_files = [
            root / 'AGENTS.md',
            root / 'CONTRIBUTING.md',
            root / '.github' / 'copilot-instructions.md',
            *sorted(self.instr_dir.glob('*.md')),
            *sorted(self.skills_dir.rglob('*.md')),
        ]

    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()


# ── checks ─────────────────────────────────────────────────────────────────


def check_tables(repo: Repo, fix: bool) -> list[str]:
    """C1: instruction tables vs frontmatter `applyTo`."""
    out: list[str] = []
    meta = {
        p.name.removesuffix('.instructions.md'): parse_frontmatter(p)
        for p in repo.instructions
    }
    expected = {
        n: split_globs(m['applyTo']) for n, m in meta.items() if m.get('applyTo')
    }
    for path in repo.table_files:
        rel = repo.rel(path)
        lines = path.read_text(encoding='utf-8').split('\n')
        first = next((i for i, ln in enumerate(lines) if ROW_RE.match(ln)), None)
        if first is None:
            out.append(f'ERROR {rel}:1: no instruction table found')
            continue
        lo = first
        while lo > 0 and lines[lo - 1].lstrip().startswith('|'):
            lo -= 1
        hi = first
        while hi + 1 < len(lines) and lines[hi + 1].lstrip().startswith('|'):
            hi += 1
        ncols = len(split_cells(lines[lo]))
        new_block: list[str] = []
        listed: set[str] = set()
        changed = False

        def report(lineno: int, msg: str) -> None:
            if fix:
                out.append(f'FIXED {rel}: {msg}')
            else:
                out.append(f'ERROR {rel}:{lineno}: {msg} (fixable: rerun with --fix)')

        for i in range(lo, hi + 1):
            line = lines[i]
            m = ROW_RE.match(line)
            if not m:
                new_block.append(line)
                continue
            name = m.group(1)
            if name not in meta:
                report(
                    i + 1,
                    f'row `{name}.instructions.md` has no instruction file; deleted',
                )
                changed = True
                continue
            listed.add(name)
            cells = split_cells(line)
            if name not in expected:
                new_block.append(line)  # C2 reports the missing applyTo
                continue
            actual = [
                g for span in SPAN_RE.findall(cells[1]) for g in split_globs(span)
            ]
            if actual != expected[name]:
                report(
                    i + 1,
                    f'row `{name}.instructions.md` applyTo differs from frontmatter',
                )
                cells[1] = canonical_cell(expected[name])
                line = '| ' + ' | '.join(cells) + ' |'
                changed = True
            new_block.append(line)
        for name in sorted(set(expected) - listed):
            cells = [f'`{name}.instructions.md`', canonical_cell(expected[name])]
            if ncols >= 3:
                desc = meta[name].get('description')
                if not desc:
                    out.append(
                        f'ERROR {rel}:{hi + 1}: `{name}.instructions.md` needs a frontmatter description for its table row'
                    )
                    continue
                cells.append(desc)
            report(hi + 1, f'row for `{name}.instructions.md` missing; appended')
            new_block.append('| ' + ' | '.join(cells) + ' |')
            changed = True
        if changed and fix:
            lines[lo : hi + 1] = new_block
            path.write_text('\n'.join(lines), encoding='utf-8')
    return out


def check_frontmatter(repo: Repo) -> list[str]:
    """C2: frontmatter completeness and skill layout."""
    out: list[str] = []
    for p in repo.instructions:
        fm = parse_frontmatter(p)
        for key in ('name', 'description', 'applyTo'):
            if not fm.get(key):
                out.append(f'ERROR {repo.rel(p)}:1: missing frontmatter `{key}`')
    for s in repo.skills:
        skill = repo.skills_dir / s / 'SKILL.md'
        rel = repo.rel(skill)
        if not skill.exists():
            out.append(
                f'ERROR {repo.rel(skill.parent)}:1: skill directory has no SKILL.md'
            )
            continue
        fm = parse_frontmatter(skill)
        if fm.get('name') != s:
            out.append(
                f'ERROR {rel}:1: frontmatter name {fm.get("name")!r} != directory {s!r}'
            )
        if not fm.get('description'):
            out.append(f'ERROR {rel}:1: missing frontmatter `description`')
    for p in sorted(repo.skills_dir.glob('*.md')):
        if p.name != 'README.md':
            out.append(
                f'ERROR {repo.rel(p)}:1: loose file in .github/skills/ (move to <skill>/SKILL.md)'
            )
    return out


def check_skill_index(repo: Repo) -> list[str]:
    """C3: every skill appears in skills/README.md."""
    readme = repo.skills_dir / 'README.md'
    text = readme.read_text(encoding='utf-8')
    return [
        f'ERROR {repo.rel(readme)}:1: skill `{s}` is not listed in the index'
        for s in repo.skills
        if not re.search('`/' + re.escape(s) + r'[` \[]', text)
    ]


def check_slash_refs(repo: Repo) -> list[str]:
    """C4: `/command` spans must name a skill."""
    out: list[str] = []
    known = set(repo.skills) | SLASH_ALLOWLIST
    for p in repo.slash_files:
        for no, line in iter_lines(p.read_text(encoding='utf-8')):
            for span in SPAN_RE.findall(line):
                m = SLASH_RE.match(span)
                if m and m.group(1) not in known:
                    out.append(f'ERROR {repo.rel(p)}:{no}: unknown skill /{m.group(1)}')
    return out


def check_links(repo: Repo) -> list[str]:
    """C5: relative links and anchors."""
    out: list[str] = []
    slug_cache: dict[Path, set[str]] = {}
    for p in repo.link_files:
        for no, line in iter_lines(p.read_text(encoding='utf-8')):
            for target in LINK_RE.findall(strip_inline_code(line)):
                if target.startswith(('http:', 'https:', 'mailto:')):
                    continue
                path_part, _, anchor = target.partition('#')
                base = repo.root if path_part.startswith('/') else p.parent
                dest = (base / path_part.lstrip('/')).resolve() if path_part else p
                if not dest.exists():
                    out.append(f'ERROR {repo.rel(p)}:{no}: broken link {target}')
                elif anchor and dest.suffix == '.md':
                    if dest not in slug_cache:
                        slug_cache[dest] = heading_slugs(dest)
                    if anchor not in slug_cache[dest]:
                        out.append(f'ERROR {repo.rel(p)}:{no}: broken anchor {target}')
    return out


def check_gh_paths(repo: Repo) -> list[str]:
    """C6: backticked `.github/...` paths exist."""
    out: list[str] = []
    for p in repo.link_files:
        for no, line in iter_lines(p.read_text(encoding='utf-8')):
            for span in SPAN_RE.findall(line):
                if GH_PATH_RE.match(span) and not (repo.root / span).exists():
                    out.append(f'ERROR {repo.rel(p)}:{no}: path does not exist: {span}')
    return out


# ── main ───────────────────────────────────────────────────────────────────


def self_test() -> None:
    """Built-in asserts for the pure helpers."""
    assert split_globs('a/**, b/*.{ts,tsx}') == ['a/**', 'b/*.{ts,tsx}']
    assert slugify('Build & test cheatsheet') == 'build--test-cheatsheet'
    assert slugify('8.1 UI-specific rules') == '81-ui-specific-rules'
    assert slugify('🚀 Quick start') == '-quick-start'
    assert canonical_cell(['x', 'y']) == '`x`, `y`'
    assert strip_inline_code('a `[b](c.md)` d') == 'a  d'
    assert ROW_RE.match('| `rust.instructions.md` | `**/*.rs` | x |')
    assert SLASH_RE.match('/kms-pr-review [PR#]') and not SLASH_RE.match('/tmp/x')
    print('self-test OK')


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    ap.add_argument(
        '--fix', action='store_true', help='apply fixable corrections in place'
    )
    ap.add_argument(
        '--self-test', action='store_true', help='run built-in asserts and exit'
    )
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    repo = Repo(_find_repo_root())
    issues = (
        check_tables(repo, args.fix)
        + check_frontmatter(repo)
        + check_skill_index(repo)
        + check_slash_refs(repo)
        + check_links(repo)
        + check_gh_paths(repo)
    )
    for line in issues:
        print(line, file=sys.stderr if line.startswith('ERROR') else sys.stdout)
    if issues:
        sys.exit(1)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
update_log_index.py — Smart updater for log-reference.md

Compares documented log call-sites against actual source, then merges:
  • Removes (or flags) stale entries no longer in source
  • Updates the File column when a log call moved to a different file
  • Appends new entries with auto-extracted variable names

Usage:
  python3 scripts/update_log_index.py
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Path resolution ────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
AGENT_DIR  = SCRIPT_DIR.parent
DOC_FILE   = AGENT_DIR / "documentation" / "docs" / "configuration" / "log-reference.md"


def _find_repo_root() -> Path:
    """Walk up from script dir looking for a directory with Cargo.toml + crate/."""
    p = SCRIPT_DIR
    for _ in range(12):
        if (p / "Cargo.toml").exists() and (p / "crate").is_dir():
            return p
        p = p.parent
    raise RuntimeError(f"Could not find repo root from {SCRIPT_DIR}")


REPO_ROOT  = _find_repo_root()
CARGO_TOML = REPO_ROOT / "Cargo.toml"

# ── Crate list ─────────────────────────────────────────────────────────────

RUST_CRATES = [
    "crate/server",
    "crate/server_database",
    "crate/crypto",
    "crate/kmip",
    "crate/interfaces",
    "crate/access",
    "crate/hsm/base_hsm",
    "crate/clients/clap",
    "crate/clients/ckms",
    "crate/clients/client",
    "crate/clients/client_utils",
    "crate/clients/pkcs11/provider",
    "crate/clients/pkcs11/module",
    "crate/clients/cng",
]

UI_CRATE = "ui/src"   # normalized (no trailing slash)

# Crates that only exist on specific platforms.
# When the crate directory is absent on the current OS (e.g. Windows-only crates on Linux CI),
# their doc entries are never flagged as stale to avoid false positives.
PLATFORM_SPECIFIC_CRATES: frozenset[str] = frozenset({"crate/clients/cng"})  # Windows-only

# ── ANSI colours ───────────────────────────────────────────────────────────

RED    = "\033[91m"
ORANGE = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

_USE_COLOR = True   # set to False via --no-color

def _red(s):    return f"{RED}{s}{RESET}" if _USE_COLOR else s
def _orange(s): return f"{ORANGE}{s}{RESET}" if _USE_COLOR else s
def _green(s):  return f"{GREEN}{s}{RESET}" if _USE_COLOR else s
def _bold(s):   return f"{BOLD}{s}{RESET}" if _USE_COLOR else s
def _dim(s):    return f"{DIM}{s}{RESET}" if _USE_COLOR else s

# ── Severity ordering ──────────────────────────────────────────────────────

SEVERITY = {"error": 0, "warn": 1, "info": 2, "debug": 3, "trace": 4, "log": 5}

# ── DocEntry ───────────────────────────────────────────────────────────────

@dataclass
class DocEntry:
    crate_path: str
    file_rel:   str
    level:      str
    message:    str    # raw string, backticks stripped
    variables:  str    # raw Variables cell content
    notes:      str    # raw Notes cell content
    line_idx:   int    # 0-based index in the original lines list

    @property
    def norm_message(self) -> str:
        return _normalize_msg(self.message)

    def quad_key(self) -> tuple:
        return (self.crate_path, self.file_rel, self.level, self.norm_message)

    def triple_key(self) -> tuple:
        return (self.crate_path, self.level, self.norm_message)

    def short(self) -> str:
        msg = self.message[:55] + "…" if len(self.message) > 55 else self.message
        return f"{self.crate_path:<35}  {self.level:<5}  {self.file_rel}"


def _normalize_msg(msg: str) -> str:
    """Normalise for comparison: {e:?} → {e}, ${uid} → {uid}."""
    s = re.sub(r'\{(\w+):[^}]*\}', r'{\1}', msg.strip())   # Rust format spec
    s = re.sub(r'\$\{([^}]+)\}', r'{\1}', s)               # JS template literal
    return s

# ── MergeResult ────────────────────────────────────────────────────────────

@dataclass
class MergeResult:
    deleted:  list = field(default_factory=list)  # DocEntry
    flagged:  list = field(default_factory=list)  # DocEntry  (→ [REMOVED])
    moved:    list = field(default_factory=list)  # (DocEntry, new_file: str)
    mult_upd: list = field(default_factory=list)  # (DocEntry, old_mult: int, new_mult: int)
    added:    list = field(default_factory=list)  # (crate, file, level, msg, mult)

# ── Version helpers ────────────────────────────────────────────────────────

def _read_version() -> str:
    if not CARGO_TOML.exists():
        return "develop"
    text = CARGO_TOML.read_text(encoding="utf-8")
    m = re.search(
        r'\[workspace\.package\].*?^version\s*=\s*"([^"]+)"',
        text, re.DOTALL | re.MULTILINE,
    )
    if m:
        return m.group(1)
    m2 = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m2.group(1) if m2 else "develop"


def _bump_version(v: str) -> str:
    """Increment minor: 5.23.0 → 5.24.0"""
    parts = v.split(".")
    if len(parts) >= 2:
        try:
            parts[-2] = str(int(parts[-2]) + 1)
            parts[-1] = "0"
            return ".".join(parts)
        except ValueError:
            pass
    return v

# ── Interactive prompts ────────────────────────────────────────────────────

def _prompt(question: str, default: str = "") -> str:
    try:
        ans = input(question).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return ans if ans else default


def _print_disclaimer() -> None:
    """Always-visible accuracy warning printed before the interactive prompts."""
    print()
    print(_orange("┌─────────────────────────────────────────────────────────┐"))
    print(_orange("│  ⚠  ACCURACY DISCLAIMER                                 │"))
    print(_orange("│                                                          │"))
    print(_orange("│  This script uses heuristic regex extraction — it may   │"))
    print(_orange("│  produce FALSE POSITIVES (flag a valid entry as stale)  │"))
    print(_orange("│  or FALSE NEGATIVES (miss a call-site entirely).        │"))
    print(_orange("│                                                          │"))
    print(_orange("│  Known limitations:                                      │"))
    print(_orange("│  • Complex macro bodies (nested calls, cfg-gated blocks) │"))
    print(_orange("│  • Messages built at runtime (format! + concat)          │"))
    print(_orange("│  • UI console calls with non-identifier second args      │"))
    print(_orange("│                                                          │"))
    print(_orange("│  Always review the report before accepting deletions.    │"))
    print(_orange("│  Flag instead of delete when unsure — safer.            │"))
    print(_orange("└─────────────────────────────────────────────────────────┘"))


def _phase0_prompts() -> tuple[str, bool]:
    """Returns (version_str, silent_delete: bool)."""
    _print_disclaimer()
    current = _read_version()
    bumped  = _bump_version(current)

    print()
    print(_bold("── Version ──────────────────────────────────────────────"))
    print(f"  Current version : {_bold(current)}")
    print(f"  Bump to {bumped} only for pre-release work (GitHub links will point to {bumped}).")
    ans = _prompt(f"  Bump version to {bumped}? [y/N]: ", "n").strip().lower()
    version = bumped if ans == "y" else current

    bumping = (version == bumped)

    print()
    print(_bold("── Stale entries ────────────────────────────────────────"))
    print("  Entries in the doc that no longer exist in source:")
    if bumping:
        print("  y  Delete them silently (default — version bump implies a clean slate)")
        print("  n  Flag with [REMOVED] in the Notes column — safer, reversible")
        ans2 = _prompt("  Delete stale entries? [Y/n]: ", "y").strip().lower()
        silent_delete = (ans2 != "n")
    else:
        print("  n  Flag with [REMOVED] in the Notes column — safer, reversible (default)")
        print("  y  Delete them silently")
        ans2 = _prompt("  Delete stale entries? [y/N]: ", "n").strip().lower()
        silent_delete = (ans2 == "y")

    print()
    return version, silent_delete

# ── Markdown parser ────────────────────────────────────────────────────────

_LEVEL_ROW_RE  = re.compile(r'^\|\s*`(error|warn|info|debug|trace|log)`\s*\|')
_CRATE_RE      = re.compile(r'Crate path:\s*`([^`]+)`')
_LINK_RE       = re.compile(r'^\[([^\]]+)\]\([^)]+\)$')
_MULT_RE       = re.compile(r'×(\d+) in this file')
_TABLE_SEP_RE  = re.compile(r'^\|[\s\-:]+\|[\s\-:]+\|[\s\-:]+\|')  # |---|---|...|


def _split_table_row(line: str) -> list[str]:
    """
    Split a markdown table row on | characters that are NOT inside backtick spans.

    Handles single-backtick `…` and double-backtick `` … `` (and any N-backtick)
    spans correctly, so log messages containing | are not split mid-cell.
    """
    parts: list[str] = []
    current: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == '`':
            # Count the run of backticks that opens (or closes) a span.
            j = i + 1
            while j < n and line[j] == '`':
                j += 1
            tick_str = line[i:j]
            # Find the matching closing run of the same length.
            close = line.find(tick_str, j)
            if close >= 0:
                # Consume the entire span (no | splitting inside).
                current.append(line[i : close + len(tick_str)])
                i = close + len(tick_str)
            else:
                # Unmatched backtick run — emit literally.
                current.append(tick_str)
                i = j
        elif ch == '|':
            parts.append(''.join(current))
            current = []
            i += 1
        else:
            current.append(ch)
            i += 1
    parts.append(''.join(current))
    return parts


def _strip_cell(raw: str) -> str:
    """Strip backticks or Markdown link wrapper from a table cell."""
    s = raw.strip()
    lm = _LINK_RE.match(s)
    if lm:
        return lm.group(1)
    # Handle `` content `` wrapping (used when message itself contains a backtick).
    if s.startswith('`` ') and s.endswith(' ``'):
        return s[3:-3]
    # Strip outermost backtick pair only; inner backticks are part of the message.
    if len(s) >= 2 and s[0] == '`' and s[-1] == '`':
        return s[1:-1]
    return s


def parse_doc(path: Path) -> tuple[list[str], list[DocEntry], dict[str, int]]:
    """Return (original_lines, doc_entries, crate_sep_idx).

    crate_sep_idx maps crate_path → line index of its table separator (|---|...|).
    Used to insert new rows even when a crate section has no existing data rows.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    entries: list[DocEntry] = []
    crate_sep_idx: dict[str, int] = {}
    current_crate: Optional[str] = None

    for i, line in enumerate(lines):
        cm = _CRATE_RE.search(line)
        if cm:
            current_crate = cm.group(1).rstrip("/")
            continue

        if current_crate and _TABLE_SEP_RE.match(line) and current_crate not in crate_sep_idx:
            crate_sep_idx[current_crate] = i
            continue

        if current_crate and _LEVEL_ROW_RE.match(line):
            parts = _split_table_row(line)
            if len(parts) < 7:
                continue
            level     = _strip_cell(parts[1])
            message   = _strip_cell(parts[2])
            file_raw  = _strip_cell(parts[3])
            variables = parts[4].strip()
            notes     = parts[5].strip()
            entries.append(DocEntry(
                crate_path=current_crate,
                file_rel=file_raw,
                level=level,
                message=message,
                variables=variables,
                notes=notes,
                line_idx=i,
            ))

    return lines, entries, crate_sep_idx

# ── Test-file detection ────────────────────────────────────────────────────

def _is_test_file(rel: str) -> bool:
    p = Path(rel)
    if any(part in ("tests", "test") for part in p.parts[:-1]):
        return True
    name = p.name
    return any([
        name.endswith("_tests.rs"),
        name.startswith("tests_"),
        name.startswith("test_"),
        name in ("tests_shared.rs", "test_helpers.rs"),
        "additional_redis_findex_tests" in name,
    ])

# ── Rust string + paren-depth extraction ──────────────────────────────────

def _skip_rust_string(text: str, i: int) -> int:
    """Advance past the double-quoted Rust string starting at position i."""
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return i + 1
        i += 1
    return i


def _extract_body(text: str, start: int) -> str:
    """
    Extract macro call body from start (after opening paren) to closing paren.

    Handles: nested parens, double-quoted strings, raw strings r#\"…\"#,
    line comments // …, and block comments /* … */.
    """
    depth = 1
    i = start
    while i < len(text) and depth > 0:
        c = text[i]
        # Line comment — skip to end of line.
        if c == '/' and i + 1 < len(text) and text[i + 1] == '/':
            while i < len(text) and text[i] != '\n':
                i += 1
            continue
        # Block comment — skip to */.
        if c == '/' and i + 1 < len(text) and text[i + 1] == '*':
            i += 2
            while i + 1 < len(text) and not (text[i] == '*' and text[i + 1] == '/'):
                i += 1
            i += 2
            continue
        # Raw string  r#\"…\"#  (any number of hashes).
        if c == 'r' and i + 1 < len(text) and text[i + 1] == '#':
            j = i + 1
            hashes = 0
            while j < len(text) and text[j] == '#':
                hashes += 1
                j += 1
            if j < len(text) and text[j] == '"':
                j += 1  # skip opening "
                end_marker = '"' + '#' * hashes
                end = text.find(end_marker, j)
                if end >= 0:
                    i = end + len(end_marker)
                    continue
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == '"':
            i = _skip_rust_string(text, i)
            continue
        i += 1
    return text[start : i - 1]


def _first_string_from_body(body: str) -> Optional[str]:
    """
    Extract the log message string from a macro call body.
    Handles: target: "...", "message" syntax by skipping the target string.
    """
    stripped = body.strip()
    skip_first = stripped.startswith("target:") or stripped.startswith("module_path!")

    skipped = 0
    i = 0
    while i < len(body):
        if body[i] != '"':
            i += 1
            continue
        # Found a string literal
        j = i + 1
        chars: list[str] = []
        while j < len(body):
            if body[j] == "\\":
                nxt = body[j + 1] if j + 1 < len(body) else ""
                if   nxt == "\n": pass               # actual newline = line continuation, discard
                elif nxt == "n":  chars.append("\\"); chars.append("n")   # \n → keep as literal \n
                elif nxt == "t":  chars.append("\\"); chars.append("t")   # \t → keep as literal \t
                elif nxt == '"':  chars.append('"')                        # \" → " (unescape)
                elif nxt == "\\": chars.append("\\")                       # \\ → \ (unescape)
                else:             chars.append(body[j : j + 2])            # keep raw
                j += 2
                continue
            if body[j] == '"':
                break
            chars.append(body[j])
            j += 1
        content = "".join(chars)
        if skipped == 0 and skip_first:
            skipped += 1
            i = j + 1
            continue
        return content
    return None


_MACRO_RE = re.compile(r'\b(trace|debug|info|warn|error)!\s*\(')


def extract_rust_logs(crate_path: str) -> list[tuple[str, str, str]]:
    """Return [(file_rel, level, message)] from Rust source (test files excluded)."""
    crate_dir = REPO_ROOT / crate_path
    if not crate_dir.exists():
        return []

    results: list[tuple[str, str, str]] = []
    for rs_file in sorted(crate_dir.rglob("*.rs")):
        try:
            rel = str(rs_file.relative_to(crate_dir))
        except ValueError:
            continue
        if _is_test_file(rel):
            continue

        text = rs_file.read_text(encoding="utf-8", errors="replace")
        for match in _MACRO_RE.finditer(text):
            level = match.group(1)
            body  = _extract_body(text, match.end())
            msg   = _first_string_from_body(body)
            if msg is not None:
                msg = re.sub(r"\\\n\s*", "", msg)   # collapse line continuations
                results.append((rel, level, msg))

    return results

# ── Web UI extractor ───────────────────────────────────────────────────────

_CONSOLE_RE = re.compile(r'\bconsole\.(error|warn|info|debug|log)\s*\(')


def _extract_ui_message(body: str) -> Optional[str]:
    """
    First string argument from a console.* call body.

    Synthesizes a {var} suffix for a single simple-identifier second argument:
      console.error("prefix:", e)          →  "prefix: {e}"
      console.error("prefix:", err.msg)    →  "prefix:"          (no synthesis)
      console.error(`template ${uid}`)     →  "template ${uid}"  (raw; _normalize_msg handles $)
    """
    body = body.strip()
    first_msg: Optional[str] = None
    rest = ""

    if body.startswith("`"):
        m = re.match(r'`((?:[^`\\]|\\.)*)`', body)
        if m:
            first_msg = m.group(1)   # keep raw ${...}; _normalize_msg handles it
            rest = body[m.end():]
    elif body.startswith('"'):
        m = re.match(r'"((?:[^"\\]|\\.)*)"', body)
        if m:
            first_msg = m.group(1)
            rest = body[m.end():]
    elif body.startswith("'"):
        m = re.match(r"'((?:[^'\\]|\\.)*)'", body)
        if m:
            first_msg = m.group(1)
            rest = body[m.end():]

    if first_msg is None:
        return None

    # Synthesize {identifier} for simple-identifier second arg only.
    # Stops at `.`, `?`, `[`, `(` etc. — those are expressions, not plain vars.
    rest_stripped = rest.lstrip(" ,")
    id_m = re.match(r'^([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[,)]', rest_stripped)
    if id_m:
        first_msg = first_msg.rstrip() + " {" + id_m.group(1) + "}"

    return first_msg


def _skip_js_string(text: str, i: int, quote: str) -> int:
    i += 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return i


def extract_ui_logs() -> list[tuple[str, str, str]]:
    """Return [(file_rel_to_ui_src, level, message)] from ui/src/."""
    ui_dir = REPO_ROOT / "ui" / "src"
    if not ui_dir.exists():
        return []

    results: list[tuple[str, str, str]] = []
    all_ts = sorted(list(ui_dir.rglob("*.ts")) + list(ui_dir.rglob("*.tsx")))
    for ts_file in all_ts:
        rel = str(ts_file.relative_to(ui_dir))
        if any(x in rel.lower() for x in ("test", "spec", "__mocks__")):
            continue
        if "node_modules" in rel:
            continue

        text = ts_file.read_text(encoding="utf-8", errors="replace")
        for match in _CONSOLE_RE.finditer(text):
            level = match.group(1)
            depth = 1
            i = match.end()
            while i < len(text) and depth > 0:
                c = text[i]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif c in ('"', "'"):
                    i = _skip_js_string(text, i, c)
                    continue
                elif c == "`":
                    i += 1
                    while i < len(text) and text[i] != "`":
                        if text[i] == "\\":
                            i += 2
                            continue
                        i += 1
                    i += 1
                    continue
                i += 1
            body = text[match.end() : i - 1]
            msg = _extract_ui_message(body)
            if msg is not None:
                results.append((rel, level, msg))

    return results

# ── Source aggregation ─────────────────────────────────────────────────────

def _extract_all_sources() -> dict[str, list[tuple[str, str, str]]]:
    print(_dim("  Extracting source logs..."), end="", flush=True)
    result: dict[str, list[tuple[str, str, str]]] = {}
    for cp in RUST_CRATES:
        result[cp] = extract_rust_logs(cp)
    result[UI_CRATE] = extract_ui_logs()
    total = sum(len(v) for v in result.values())
    print(_dim(f" {total} call-sites found."))
    return result


def _build_source_index(
    source: dict[str, list[tuple[str, str, str]]]
) -> tuple[set, set, dict, dict]:
    """
    Returns:
      quad_set   – {(crate, file, level, norm_msg)}
      triple_set – {(crate, level, norm_msg)}
      move_map   – {(crate, level, norm_msg): latest_file_seen}
      mult_map   – {(crate, file, level, norm_msg): occurrence_count}
    """
    quad_set:   set   = set()
    triple_set: set   = set()
    move_map:   dict  = {}
    mult_map:   dict  = {}

    for crate_path, entries in source.items():
        for (file_rel, level, msg) in entries:
            nm   = _normalize_msg(msg)
            quad = (crate_path, file_rel, level, nm)
            tri  = (crate_path, level, nm)
            quad_set.add(quad)
            triple_set.add(tri)
            move_map[tri] = file_rel
            mult_map[quad] = mult_map.get(quad, 0) + 1

    return quad_set, triple_set, move_map, mult_map

# ── Three-way merge ────────────────────────────────────────────────────────

def _stored_mult(notes: str) -> int:
    """Read the ×N multiplicity stored in the Notes cell (default 1)."""
    m = _MULT_RE.search(notes)
    return int(m.group(1)) if m else 1


def merge(
    doc_entries: list[DocEntry],
    source: dict[str, list[tuple[str, str, str]]],
    silent_delete: bool,
) -> MergeResult:
    quad_set, triple_set, move_map, mult_map = _build_source_index(source)
    result = MergeResult()

    doc_quad_set:   set = set()
    for e in doc_entries:
        doc_quad_set.add(e.quad_key())

    # ── Check each existing doc entry ──────────────────────────────────────
    doc_quad_seen: set = set()   # for deduplication of doc entries
    for e in doc_entries:
        qk = e.quad_key()
        # Deduplicate: if we've seen the same (crate, file, level, msg) before,
        # treat the later occurrence as stale so it gets removed.
        if qk in doc_quad_seen:
            if silent_delete:
                result.deleted.append(e)
            else:
                result.flagged.append(e)
            continue
        doc_quad_seen.add(qk)
        tk = e.triple_key()

        if qk in quad_set:
            # Present in source at same location — check multiplicity
            src_mult = mult_map.get(qk, 1)
            doc_mult = _stored_mult(e.notes)
            if src_mult != doc_mult:
                result.mult_upd.append((e, doc_mult, src_mult))
        elif tk in triple_set and move_map.get(tk) != e.file_rel:
            # Same (crate, level, message) but different file → MOVED
            # Only flag as moved if the OLD location is truly gone from source
            if qk not in quad_set:
                result.moved.append((e, move_map[tk]))
        else:
            # Not found anywhere → STALE
            # Platform-specific crates absent on this OS are never stale.
            if e.crate_path in PLATFORM_SPECIFIC_CRATES and not (REPO_ROOT / e.crate_path).exists():
                continue
            if silent_delete:
                result.deleted.append(e)
            else:
                result.flagged.append(e)

    # Build set of "new files" for moved entries so we don't double-count them
    moved_new_quads: set = {
        (e.crate_path, new_file, e.level, e.norm_message)
        for (e, new_file) in result.moved
    }

    # ── Find new source entries not covered by any doc entry ───────────────
    for crate_path, entries in source.items():
        # Deduplicate within this crate: (file, level, norm_msg) → (raw_msg, count)
        seen: dict[tuple, tuple] = {}
        for (file_rel, level, msg) in entries:
            nm = _normalize_msg(msg)
            k  = (file_rel, level, nm)
            if k not in seen:
                seen[k] = (msg, 0)
            seen[k] = (seen[k][0], seen[k][1] + 1)

        for (file_rel, level, nm), (raw_msg, mult) in seen.items():
            qk = (crate_path, file_rel, level, nm)
            if qk in doc_quad_set:
                continue      # already documented
            if qk in moved_new_quads:
                continue      # handled as a "move" of an existing entry
            result.added.append((crate_path, file_rel, level, raw_msg, mult))

    return result

# ── Variable name extraction ───────────────────────────────────────────────

def _extract_var_names(message: str) -> str:
    """Extract {name} placeholders → '`name1`, `name2`' or '—'"""
    seen: list[str] = []
    used: set[str]  = set()
    for m in re.finditer(r'\{(\w+)', message):
        n = m.group(1)
        if n not in used:
            used.add(n)
            seen.append(f"`{n}`")
    return ", ".join(seen) if seen else "—"

# ── Document rewriter ──────────────────────────────────────────────────────

def _wrap_in_backticks(s: str) -> str:
    """Wrap s for a markdown table cell; use double backticks if s contains one."""
    if '`' not in s:
        return f"`{s}`"
    if '``' not in s:
        return f"`` {s} ``"
    # Last resort: strip backticks to avoid corrupting the table structure.
    return f"`{s.replace('`', '')}`"


def _fmt_row(level: str, msg: str, file_rel: str, variables: str, notes: str) -> str:
    return f"| {_wrap_in_backticks(level)} | {_wrap_in_backticks(msg)} | {_wrap_in_backticks(file_rel)} | {variables} | {notes} |"


def _build_new_row(crate_path: str, file_rel: str, level: str, msg: str, mult: int) -> str:
    variables = _extract_var_names(msg)
    notes     = f"×{mult} in this file" if mult > 1 else "—"
    return _fmt_row(level, msg, file_rel, variables, notes)


def _update_mult_in_notes(notes: str, new_mult: int) -> str:
    """Update the ×N multiplicity marker in a Notes cell."""
    m = _MULT_RE.search(notes)
    if new_mult == 1:
        # Count dropped back to 1 — remove the multiplicity note entirely.
        if m:
            stripped = (notes[:m.start()] + notes[m.end():]).strip(" ;")
            return stripped if stripped else "—"
        return notes  # already no marker
    if m:
        return notes[:m.start()] + f"×{new_mult} in this file" + notes[m.end():]
    # No ×N marker yet (doc defaulted to 1, source now has more) — insert it.
    clean = notes.strip()
    if clean in ("—", "-", ""):
        return f"×{new_mult} in this file"
    return clean + f"; ×{new_mult} in this file"


def rewrite_doc(
    lines:         list[str],
    doc_entries:   list[DocEntry],
    result:        MergeResult,
    crate_sep_idx: dict[str, int],
) -> list[str]:
    """Apply merge result to original lines and return the new line list."""

    deleted_idx  = {e.line_idx for e in result.deleted}
    flagged_map  = {e.line_idx: e for e in result.flagged}
    moved_map    = {e.line_idx: new_file for (e, new_file) in result.moved}
    mult_upd_map = {e.line_idx: new_mult for (e, _, new_mult) in result.mult_upd}

    # Find last table-row line per crate for new-entry insertion
    last_row_idx: dict[str, int] = {}
    for e in doc_entries:
        cp = e.crate_path
        if cp not in last_row_idx or e.line_idx > last_row_idx[cp]:
            last_row_idx[cp] = e.line_idx

    # Group and sort new entries by crate
    new_by_crate: dict[str, list[tuple]] = {}
    for (cp, file_rel, level, msg, mult) in result.added:
        new_by_crate.setdefault(cp, []).append((level, msg, file_rel, mult))
    for cp in new_by_crate:
        new_by_crate[cp].sort(key=lambda x: (SEVERITY.get(x[0], 99), x[1].lower()))

    # Build line-idx → [rows_to_insert_after] map
    insertions: dict[int, list[str]] = {}
    missing_crates: list[str] = []
    for cp, rows in new_by_crate.items():
        insert_after = last_row_idx.get(cp)
        if insert_after is not None:
            new_rows = [_build_new_row(cp, f, lv, msg, mult) for (lv, msg, f, mult) in rows]
            insertions.setdefault(insert_after, []).extend(new_rows)
        else:
            # Crate section exists with a table header but no data rows yet.
            sep_idx = crate_sep_idx.get(cp)
            if sep_idx is not None:
                new_rows = [_build_new_row(cp, f, lv, msg, mult) for (lv, msg, f, mult) in rows]
                insertions.setdefault(sep_idx, []).extend(new_rows)
            else:
                missing_crates.append(cp)

    if missing_crates:
        print(f"\n  ⚠  New entries for unknown crates (add sections manually): {missing_crates}")

    # Reconstruct line by line
    output: list[str] = []
    for i, line in enumerate(lines):
        if i in deleted_idx:
            # Still emit any new entries queued for insertion after this (now-deleted) anchor.
            if i in insertions:
                output.extend(insertions[i])
            continue   # stale — drop

        if i in flagged_map:
            # Prepend [REMOVED] to the Notes column
            parts = _split_table_row(line)
            if len(parts) >= 7:
                notes = parts[5].strip()
                if "[REMOVED]" not in notes:
                    parts[5] = f" [REMOVED] {notes} " if notes not in ("-", "—", "") else " [REMOVED] "
                line = "|".join(parts)

        if i in moved_map:
            # Update File column with new path
            parts = _split_table_row(line)
            if len(parts) >= 7:
                parts[3] = f" `{moved_map[i]}` "
                line = "|".join(parts)

        if i in mult_upd_map:
            # Update ×N count in Notes column
            parts = _split_table_row(line)
            if len(parts) >= 7:
                parts[5] = " " + _update_mult_in_notes(parts[5].strip(), mult_upd_map[i]) + " "
                line = "|".join(parts)

        output.append(line)

        if i in insertions:
            output.extend(insertions[i])

    return output

# ── Colorized report ───────────────────────────────────────────────────────

def _print_report(result: MergeResult, version: str, silent_delete: bool) -> None:
    print()
    print(_bold("══════════════════════════════════════════════════════"))
    print(_bold(f"  Log Index Update Report  (v{version})"))
    print(_bold("══════════════════════════════════════════════════════"))

    # ── Red: stale ─────────────────────────────────────────────────────────
    stale_all = result.deleted + result.flagged
    if stale_all:
        action = "deleted" if silent_delete else "flagged [REMOVED]"
        print()
        print(_red(f"❌  STALE — {action}: {len(stale_all)} entries"))
        for e in stale_all:
            tag = "DEL" if silent_delete else "FLG"
            msg_short = e.message[:58] + "…" if len(e.message) > 58 else e.message
            print(_red(f"   [{tag}]  {e.crate_path:<35}  {e.level:<5}  {e.file_rel}"))
            print(_red(f"          \"{msg_short}\""))
    else:
        print(_green("   ✓  No stale entries."))

    # ── Orange: moved ──────────────────────────────────────────────────────
    if result.moved:
        print()
        print(_orange(f"🚚  MOVED: {len(result.moved)} entries"))
        for (e, new_file) in result.moved:
            msg_short = e.message[:55] + "…" if len(e.message) > 55 else e.message
            print(_orange(f"   {e.crate_path:<35}  {e.level:<5}"))
            print(_orange(f"   {e.file_rel}  →  {new_file}"))
            print(_orange(f"   \"{msg_short}\""))
    else:
        print(_green("   ✓  No moved entries."))

    # ── Orange: multiplicity updates ───────────────────────────────────────
    if result.mult_upd:
        print()
        print(_orange(f"🔢  MULTIPLICITY UPDATED: {len(result.mult_upd)} entries"))
        for (e, old_m, new_m) in result.mult_upd:
            print(_orange(f"   {e.crate_path:<35}  {e.level:<5}  {e.file_rel}"))
            print(_orange(f"   ×{old_m} → ×{new_m}  \"{e.message[:55]}\""))

    # ── Green: new ─────────────────────────────────────────────────────────
    if result.added:
        print()
        print(_green(f"✅  NEW (added): {len(result.added)} entries"))
        for (cp, file_rel, level, msg, mult) in result.added:
            mult_tag = _dim(f" (×{mult} in file)") if mult > 1 else ""
            msg_short = msg[:60] + "…" if len(msg) > 60 else msg
            print(_green(f"   {cp:<35}  {level:<5}  {file_rel}{mult_tag}"))
            print(_green(f"   \"{msg_short}\""))
    else:
        print(_green("   ✓  No new entries."))

    # ── Summary ────────────────────────────────────────────────────────────
    print()
    print(_bold("──────────────────────────────────────────────────────"))
    parts: list[str] = []
    if stale_all:    parts.append(_red(f"{len(stale_all)} stale"))
    if result.moved: parts.append(_orange(f"{len(result.moved)} moved"))
    if result.mult_upd: parts.append(_orange(f"{len(result.mult_upd)} ×N updated"))
    if result.added: parts.append(_green(f"{len(result.added)} new"))
    if parts:
        print("  " + " · ".join(parts))
    else:
        print(_green("  Everything is up to date. No changes needed."))

    if result.added:
        print()
        print(_bold("  ⚠  New entries have variable names only (no descriptions)."))
        print("     Please open log-reference.md and add descriptions + notes")
        print("     where meaningful (security flags, operator guidance).")
    print()

# ── Main ───────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Update log-reference.md from source call-sites.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # interactive (default)\n"
            "  python3 scripts/update_log_index.py\n\n"
            "  # CI / bot: safe defaults, no prompts, no colour\n"
            "  python3 scripts/update_log_index.py --non-interactive --no-color\n\n"
            "  # bot: also delete stale entries\n"
            "  python3 scripts/update_log_index.py --non-interactive --delete-stale --no-color\n"
        ),
    )
    p.add_argument(
        "--non-interactive", action="store_true",
        help="Skip all prompts; use flag values directly (for CI/bots).",
    )
    p.add_argument(
        "--bump-version", action="store_true", default=False,
        help="Bump the minor version. Only meaningful with --non-interactive.",
    )
    p.add_argument(
        "--delete-stale", action="store_true", default=False,
        help="Delete stale entries instead of flagging with [REMOVED]. Only meaningful with --non-interactive.",
    )
    p.add_argument(
        "--no-color", action="store_true",
        help="Suppress ANSI colour codes (useful for CI logs).",
    )
    p.add_argument(
        "--check", action="store_true",
        help=(
            "Report changes without writing the file. "
            "Exits 1 if any changes are detected. "
            "Implies --non-interactive."
        ),
    )
    return p.parse_args()


def main() -> None:
    global _USE_COLOR
    args = _parse_args()
    if args.no_color:
        _USE_COLOR = False
    check_only = args.check
    if check_only:
        args.non_interactive = True   # --check implies --non-interactive

    print(_bold(f"\n  Log Index Updater{'  [check-only]' if check_only else ''}"))
    print(_dim(f"  Doc : {DOC_FILE}"))
    print(_dim(f"  Repo: {REPO_ROOT}"))

    if not DOC_FILE.exists():
        print(_red(f"\nERROR: {DOC_FILE} not found."))
        sys.exit(1)

    # Phase 0: prompts or CLI args
    if args.non_interactive:
        current = _read_version()
        version = _bump_version(current) if args.bump_version else current
        silent_delete = args.delete_stale
    else:
        if args.bump_version or args.delete_stale:
            print(_orange("  ⚠  --bump-version / --delete-stale are only used with --non-interactive; ignoring."))
        version, silent_delete = _phase0_prompts()
    print(_dim(f"  Version: {version}  |  Stale strategy: {'delete' if silent_delete else 'flag [REMOVED]'}"))
    print()

    # Phase 1: parse doc
    print(_dim("  Parsing log-reference.md..."), end="", flush=True)
    lines, doc_entries, crate_sep_idx = parse_doc(DOC_FILE)
    print(_dim(f" {len(doc_entries)} entries found."))

    # Phase 2: extract source
    source = _extract_all_sources()

    # Phase 3: merge
    print(_dim("  Merging..."), end="", flush=True)
    result = merge(doc_entries, source, silent_delete)
    n_changes = len(result.deleted) + len(result.flagged) + len(result.moved) + len(result.added) + len(result.mult_upd)
    print(_dim(f" {n_changes} change(s) detected."))

    # Phase 4: rewrite
    if n_changes > 0:
        if check_only:
            print(_dim("  Check mode — file not modified."))
        else:
            print(_dim("  Writing log-reference.md..."), end="", flush=True)
            new_lines = rewrite_doc(lines, doc_entries, result, crate_sep_idx)
            DOC_FILE.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            print(_dim(" Done."))
    else:
        print(_dim("  No changes — file not modified."))

    # Phase 5: report
    _print_report(result, version, silent_delete)

    # Exit 1 when changes exist so pre-commit (and CI) can detect drift.
    # In write mode: the file was already updated — user should re-stage it.
    # In check mode: nothing was written — indicates the index is out of date.
    if n_changes > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

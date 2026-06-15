"""
MkDocs hooks for the KMS documentation.

on_config:        read KMS version from Cargo.toml → config.extra.kms_version
on_page_markdown: transform plain file paths in log-reference.md table cells
                  into GitHub source links at build time.
"""

import re
from pathlib import Path


# ── on_config ─────────────────────────────────────────────────────────────

def on_config(config):
    """Called once before the build. Reads version and patches config."""
    hooks_dir = Path(__file__).parent   # documentation/
    repo_root  = hooks_dir.parent       # repo root
    cargo_toml = repo_root / "Cargo.toml"

    version = _read_workspace_version(cargo_toml)
    config.extra["kms_version"] = version or "develop"
    return config


def _read_workspace_version(cargo_toml: Path) -> str | None:
    if not cargo_toml.exists():
        return None
    text = cargo_toml.read_text(encoding="utf-8")
    m = re.search(
        r'\[workspace\.package\].*?^version\s*=\s*"([^"]+)"',
        text, re.DOTALL | re.MULTILINE,
    )
    if m:
        return m.group(1)
    m2 = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return m2.group(1) if m2 else None


# ── on_page_markdown ───────────────────────────────────────────────────────

_FILE_CELL_RE = re.compile(r'^`([^`]+\.(rs|ts|tsx|js|toml|py|md|sh))`$')
_CRATE_PATH_RE = re.compile(r'Crate path:\s*`([^`]+)`')


def on_page_markdown(markdown, **kwargs):
    """
    Pre-process log-reference.md: turn plain `src/foo.rs` File column cells
    into Markdown links pointing to the exact file on GitHub.

    Runs at build time — output is static HTML, no JS required.

    State machine: tracks current_crate_path as it moves through sections,
    then rewrites column 3 of every 5-column table data row.
    """
    page   = kwargs.get("page")
    config = kwargs.get("config")

    if page is None or "log-reference" not in page.file.src_uri:
        return markdown

    version    = config.extra.get("kms_version", "develop") if config else "develop"
    github_base = f"https://github.com/Cosmian/kms/blob/{version}"

    lines = markdown.splitlines()
    out   = []
    current_crate_path = None

    for line in lines:
        # Track crate path from "Crate path: `xxx`" lines
        m = _CRATE_PATH_RE.search(line)
        if m:
            current_crate_path = m.group(1).rstrip("/")

        # Rewrite File column in 5-column table data rows
        if current_crate_path and line.startswith("|"):
            parts = line.split("|")
            # A 5-column row has 7 parts: ['', col1, col2, col3, col4, col5, '']
            if len(parts) == 7:
                file_col = parts[3].strip()
                fm = _FILE_CELL_RE.match(file_col)
                if fm:
                    file_rel  = fm.group(1)
                    full_url  = f"{github_base}/{current_crate_path}/{file_rel}"
                    parts[3]  = f" [{file_rel}]({full_url}) "
                    line = "|".join(parts)

        out.append(line)

    return "\n".join(out)


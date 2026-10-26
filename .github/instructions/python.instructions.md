---
name: 'Python Scripts'
description: 'Python scripting conventions for documentation generation and test helper scripts in the Eviden KMS project'
applyTo: '**/*.py'
---

# Python script conventions

## Scope in this repository

Python is used for:

- **Documentation generation scripts** (`documentation/theme/scripts/`): generate SUMMARY.md, process mdBook tabs.
- **Test helpers** (`test_data/`): SPIFFE/SPIRE identity test, PyKMIP integration helpers.
- **KMIP test vector extraction** (`kmip/v1.0/XML/`): parse XML test vectors.

Python is **not** the primary language of this project. Keep Python usage minimal and confined to these areas.

## Runtime

- Target **Python 3.10+**; avoid Python 2 syntax.
- Use a shebang when scripts are intended to be run directly:

  ```python
  #!/usr/bin/env python3
  ```

## Dependencies

- Declare third-party packages in a `requirements*.in` next to the calling script and commit the hash-pinned `.txt` compiled from it with `pip-compile --generate-hashes`; install with `pip install --require-hashes -r`. Full procedure: `dependencies.instructions.md`.
- Prefer the Python standard library over third-party packages for simple scripting tasks.
- For PyKMIP tests, dependencies are managed by the MISE `test:pykmip` task.

## Error handling

- Use `sys.exit(1)` with an error message to `stderr` for fatal errors:

  ```python
  import sys
  print(f"ERROR: {message}", file=sys.stderr)
  sys.exit(1)
  ```

- Never silently swallow exceptions — log them or re-raise.

## Style

- Follow **PEP 8** style.
- Use f-strings for string formatting (Python 3.6+).
- Keep scripts short and focused; extract functions for logic over 20 lines.
- Add a `if __name__ == "__main__":` guard for executable scripts.

## Type annotations

- Add type annotations to function signatures for non-trivial scripts.
- Use `from __future__ import annotations` for forward references.

## Documentation

- Add a module-level docstring explaining the purpose of the script.
- Complex functions require docstrings.

## Security

- Never hardcode credentials or tokens.
- Validate and sanitize all file paths derived from user input or environment variables.
- Use `subprocess.run(..., check=True)` instead of `os.system()`.

## Refactor

### Tooling

- Regroup `.mise/scripts/test/` into one subfolder per `.mise/tasks/test/` task group (`obs`, `cloud`, `hsm`, `pkcs11`, `interop`, `pki`, `spire`, `ui`, `pkg`, `k8s`, `db`) plus `vectors`; file names are unchanged and all references (tasks, CI paths, workflows, docs, test fixtures) are updated. See `.mise/scripts/test/README.md`.
- Python lockfile checks (`requirements-txt-fixer`, `pip-audit-lockfiles`, typos) and Dependabot follow the lockfiles into their new folders.
- `find_unused_vector_json.py` now resolves `test_data/vectors` from the repository root.

## Documentation

- Add `.mise/scripts/test/README.md` describing the folder layout and placement rules.

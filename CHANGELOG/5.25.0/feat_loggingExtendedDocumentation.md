## Documentation

### Logging

- Add `documentation/docs/configuration/log-reference.md` — a comprehensive log
  call-site directory listing every production log call-site across all KMS components
  (server, CLI, PKCS#11 provider, CNG module, Web UI), grouped by domain and crate, with
  per-level filter and full `RUST_LOG` target names.
- Add interactive level-filter UI (`documentation/docs/javascripts/log_filter.js`) for
  the log-reference page — per-domain search bar + severity badge buttons, no external
  dependencies.
- Link the new page from `documentation/docs/configuration/logging.md`.

## CI

- Add `log-index-check` CI job to `main_base.yml` that fails the build when
  `log-reference.md` is out of sync with source call-sites, with an inline fix hint.

## Build

- Extend `scripts/update_log_index.py` integration: add `mise run docs:log-index-check`
  task and `--skip-log-index` flag to `generate_docs.sh` (step 6 of 6).
- Add `update-log-index` pre-commit hook that auto-syncs `log-reference.md` on every
  commit touching `.rs`, `.ts`, or `.tsx` files and blocks until the diff is reviewed
  and re-staged.

---

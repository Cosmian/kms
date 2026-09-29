---
name: 'Test Vectors'
description: 'Keep test vector directories, the runner registration, and the README count in sync'
applyTo: 'test_data/vectors/**, crate/test_kms_server/**/*.rs'
---

# Test vector sync

A test vector change spans the data directory, the runner, and the README.

## Checklist

- [ ] Directory created: `test_data/vectors/<category>/<name>/`
- [ ] `manifest.toml` and TTLV-JSON step files written
- [ ] Test function added to `crate/test_kms_server/src/vector_runner.rs`
- [ ] `crate/test_kms_server/README.md` row added + total count updated
- [ ] Run `/kms-test-vector` for the guided workflow

> Rule 4.10 of `/kms-sync-rules`.

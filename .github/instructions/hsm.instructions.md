---
name: 'HSM Backend'
description: 'Keep the PKCS#11 loader, HSM model enum, wizard, test vectors, and CI matrix in sync when adding an HSM backend'
applyTo: 'crate/hsm/**/*.rs'
---

# HSM backend sync

A new HSM backend spans the loader crate, the model enum, the wizard, test vectors, and the CI
matrix.

## Checklist

- [ ] PKCS#11 loader crate in `crate/hsm/<model>/`
- [ ] HSM model enum updated in `crate/server/src/config/` or `crate/hsm/base_hsm/`
- [ ] Wizard step in `crate/server/src/config/wizard/hsm_wizard.rs`
- [ ] Test vectors in `test_data/vectors/hsm/<model>/`
- [ ] CI added to `.github/workflows/test_all.yml` (software HSMs: list the leaf in `.mise/tasks/test/hsm/_default` and add the model to `test-hsm`'s `bench`; real hardware: add a `test-hsm-hardware` cell with `lock` and its secrets in `test-group.yml`, plus `skip` it in `test-hsm`), and the upstream `env:` gate (`print_error` when `CI=true` and a secret is unset, then `skip_test`) in `.mise/tasks/test/hsm/<model>` for hardware HSMs

> Rule 4.13 of `/kms-sync-rules`.

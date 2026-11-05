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
- [ ] CI leg declared in the `#SUITE` header of `.mise/tasks/test/hsm/<model>` (`ci=`, `scope=`, `lock=` for shared hardware, `bench=`); `mise run ci:plan` generates the matrix, `test_all.yml` only maps the secrets of a `scope=upstream` HSM

> Rule 4.13 of `/kms-sync-rules`.

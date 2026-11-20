## CI

- Make `mise run test:cloud:google-cse-remote` local only: it reads `~/.cosmian/cse.cosmian.com.toml` (or `CKMS_CSE_CONF`) and always skips in CI; remove the `CSE_CKMS_CONF_TOML` secret plumbing from `test-group.yml` and `test_all.yml` ([#1435](https://github.com/Cosmian/kms/issues/1435))

## Testing

- Delete `crate/server/src/tests/google_cse/cse_test.sh`, which held an OAuth client secret and refresh token in clear text; `init_kms_cse.sh` now reads a local ckms config instead of embedding one ([#1435](https://github.com/Cosmian/kms/issues/1435))

---

Refs #1435

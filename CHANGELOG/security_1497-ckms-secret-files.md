## Bug Fixes

### Hardening
- `ckms` writes `ckms.toml`, exported keys/objects, PKCS#12 bundles, decrypted files and KEM shared secrets readable by their owner only (0600 on Unix; existing files are reset); `ckms.toml` is replaced atomically, so a failed save never leaves it empty ([#1497](https://github.com/Cosmian/kms/issues/1497))

### CLI
- `ckms login`/`logout` save only the obtained tokens; one-off `--url`, `--accept-invalid-certs`, `--header` and proxy flags are no longer written to `ckms.toml`, and `ckms` warns when certificate verification is disabled ([#1497](https://github.com/Cosmian/kms/issues/1497))

---

Closes #1497

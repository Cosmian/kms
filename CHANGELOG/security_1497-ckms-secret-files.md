## Bug Fixes

### Hardening
- `ckms` writes `ckms.toml`, exported keys/objects, PKCS#12 bundles, decrypted files and KEM shared secrets readable by their owner only (0600 on Unix; existing files are reset) ([#1497](https://github.com/Cosmian/kms/issues/1497))

---

Closes #1497

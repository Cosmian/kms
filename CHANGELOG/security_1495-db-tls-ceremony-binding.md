## Bug Fixes

### Hardening
- MySQL `ssl-mode=VERIFY_CA`/`VERIFY_IDENTITY` with `ssl-ca` trusts only that CA; the system CA store is no longer consulted. `ssl-ca` must hold the root CA of the server chain ([#1495](https://github.com/Cosmian/kms/issues/1495))

---

Closes #1495

## Bug Fixes

### Hardening
- MySQL `ssl-mode=VERIFY_CA`/`VERIFY_IDENTITY` with `ssl-ca` trusts only that CA; the system CA store is no longer consulted. `ssl-ca` must hold the root CA of the server chain ([#1495](https://github.com/Cosmian/kms/issues/1495))
- A Crypto Officer ceremony record is accepted only for the user it was sealed for, and revocation erases it (SQL backends also erase records revoked by older releases at startup), so a database writer can no longer move an activation to another user or revive a revoked one. Redis: re-run the Crypto Officer disable for users revoked before the upgrade ([#1495](https://github.com/Cosmian/kms/issues/1495))

---

Closes #1495

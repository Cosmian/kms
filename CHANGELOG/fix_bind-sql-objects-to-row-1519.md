## Breaking Changes

### Database
- Bind the objects wrapped by the server `key_encryption_key` to their database row ([#1519](https://github.com/Cosmian/kms/issues/1519)). The wrapped plaintext now carries the vendor attribute `x-cosmian-stored-uid`, and the server refuses to read an object whose binding is missing or names another row. At every start with a `key_encryption_key`, the server wraps again, bound to their row, the existing objects it wraps (SQLite, PostgreSQL, MySQL and Redis-with-Findex), so a database needs no manual migration. Action: stop every instance of the previous release before starting this version, because rows written by the previous release are refused until the next restart of this version. The previous release can read bound objects, but returns the `x-cosmian-stored-uid` attribute in the key value (`tables.md`, `Downgrade (row binding)`).
- With an RSA-OAEP `key_encryption_key`, the bound plaintext (168 bytes with a UUID) must fit in one RSA-OAEP block: a 2048-bit KEK limits the UID of a stored key to about 58 characters. Use a longer KEK for longer UIDs. The binding does not stop a database writer who forges a ciphertext with the public key; AES KEKs are not concerned.

## Bug Fixes

### Hardening
- Refuse a KEK-wrapped object copied from one database row to another, including by a database writer who swaps the `objects.object` column of two rows or moves a wrapped blob to a row they own ([#1519](https://github.com/Cosmian/kms/issues/1519)). The binding covers the UID only: a database writer who can change `owner` can also add `read_access` rows.
- Warn at startup that, without a `key_encryption_key`, objects are stored in clear and are not bound to their row.

## Documentation

- Document the row binding and its downgrade verdict in `Database tables` and `Configurations`, and the accepted residual risk of the replay of a revoked Crypto Officer activation by a database writer, in `Role Management and Key Ceremony` and `Database tables`.

---

Closes #1519

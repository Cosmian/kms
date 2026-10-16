# Fix UI problems

## Bug Fixes

### Web UI

- Show a friendly "revoke first" message instead of the raw `422: Wrong_Key_Lifecycle_State: DENIED` error when destroying a non-revoked object ([#1207](https://github.com/Cosmian/kms/issues/1207))

## Documentation

- Database configuration page: remove the non-working MySQL `--mysql-user-cert-file` example (use `ssl-client-identity` in the database URL instead), fix the migration table name (`parameters`), fix heading levels and admonition rendering, and keep a single Redis section ([#1136](https://github.com/Cosmian/kms/issues/1136))
- Home page: list every integration instead of duplicated entries and `...`

---

Closes #1207
Closes #1136

## Bug Fixes

### Hardening
- Rate limiter: idle per-IP keys are purged every minute, so the key map no longer grows with every new peer address ([#1500](https://github.com/Cosmian/kms/issues/1500))
- Every response carries `Strict-Transport-Security`, `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`; the Web UI (index page and static assets) is served with a `Content-Security-Policy` restricting scripts, styles, images, connections, objects and base URI to the server itself ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The public `GET /version` no longer reports the OpenSSL build string; the `(FIPS)` / `(non-FIPS)` flavour is kept. `GET /server-info` still gives the full detail to authenticated users ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The server logs a warning naming each secret passed as a command-line flag (visible in the process list); use the `KMS_*` environment variable or the configuration file instead. Values are never logged ([#1500](https://github.com/Cosmian/kms/issues/1500))
- `cosmian_kms` secret backend: only `localhost`, `127.0.0.1` and `::1` hosts use plain `http`; `localhost.evil.com` and similar hosts now use `https` ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The server-only vendor attributes `x-cosmian-split-key-source` and `x-cosmian-share-wrapping-key` can no longer be written by clients (`SetAttribute`, `AddAttribute`, `ModifyAttribute`, `Import`, `Register`, `Create`, `CreateKeyPair`), so `JoinSplitKey` cannot be steered by forged attributes ([#1500](https://github.com/Cosmian/kms/issues/1500))
- With `crypto_officer.require_ceremony`, only Crypto Officer candidates and the `default_username` provisioning identity trigger a ceremony split in `CreateSplitKey`; any other caller holding `Create` gets an ordinary split that they own ([#1500](https://github.com/Cosmian/kms/issues/1500))
- `Locate` rejects an `OffsetItems` above 1,000,000 ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The algorithm policy also checks the Key Wrapping Specification of `Get` requests, as it does for `Export` ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The API-token middleware parses the `Authorization` header before reading the token key from the database, so unauthenticated requests no longer trigger a database lookup ([#1500](https://github.com/Cosmian/kms/issues/1500))
- `/ui/logout` accepts `POST` only (it changes state); the Web UI calls it with `POST`. A `GET /ui/logout` now returns 405 ([#1500](https://github.com/Cosmian/kms/issues/1500))

---

Closes #1500

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
- `private_key_sign` (Google CSE) refuses SHA-1 RSA signatures in FIPS builds with an explicit error; RSA verification failures log signature and data lengths, not their bytes; decrypted Google CSE key buffers are zeroized ([#1500](https://github.com/Cosmian/kms/issues/1500))
- Google CSE tokens naming a reserved service identity (such as the AWS XKS service identity) are rejected on every token path ([#1500](https://github.com/Cosmian/kms/issues/1500))
- The AWS XKS key-access migration runs once per database instead of at every start, so tagging an object `aws-xks` no longer re-grants it to the XKS service identity after each restart ([#1500](https://github.com/Cosmian/kms/issues/1500))
- HSM: a startup warning is logged when an instance sets `hsm_admin = "*"`; `HsmInstanceParams` `Debug` no longer prints slot passwords; waiting for a pooled HSM session fails after 30 s instead of waiting indefinitely ([#1500](https://github.com/Cosmian/kms/issues/1500))
- SQLite database and migration-lock files are created readable by their owner only (0600) and existing files are tightened; the unused MySQL `upsert-object` query is removed ([#1500](https://github.com/Cosmian/kms/issues/1500))
- Redis with Findex: new databases derive their master key with a random per-database salt stored in `kms_kdf_salt`; existing databases keep the legacy salt. A database created by this version cannot be read by an older release ([#1500](https://github.com/Cosmian/kms/issues/1500))
- OTLP: `https://` endpoints are rejected at startup because TLS transport is not compiled into the OTLP exporter; use an `http://` endpoint on a local or sidecar OpenTelemetry Collector with `--otlp-allow-insecure`, and let the collector forward over TLS ([#1500](https://github.com/Cosmian/kms/issues/1500))
- Kubernetes operator: `KMSSecret` status no longer publishes the unsalted SHA-256 of the secret (`status.lastSecretHash` is removed and cleared on the next reconcile); restarts are decided by a constant-time comparison with the managed Secret. An annotated pod with invalid injection annotations is rejected by the mutating webhook instead of being admitted without the init container ([#1500](https://github.com/Cosmian/kms/issues/1500))
- `ckms` Auth Verifier login requires an https server URL except for loopback hosts; the PKCS#11 module rejects a null `CKM_AES_CBC` parameter and checks the IV length before reading it ([#1500](https://github.com/Cosmian/kms/issues/1500))
- Monitoring stack: no default credentials, the P12 password is passed via `KMS_TLS_P12_PASSWORD`, VictoriaMetrics is published on `127.0.0.1` only, images are pinned by digest, and `resources/kms.toml` no longer enables a placeholder Redis master password ([#1500](https://github.com/Cosmian/kms/issues/1500))

## CI

- Package signing moves to isolated `sign-packages`, `sign-apk` and `sign-k8s-plugin` jobs; build jobs hold no GPG key. Every workflow job declares job-level permissions, workflow inputs are passed through `env:` instead of being expanded in `run:` scripts, and `cargo-deny` denies unknown registries and git sources ([#1500](https://github.com/Cosmian/kms/issues/1500))

---

Closes #1500

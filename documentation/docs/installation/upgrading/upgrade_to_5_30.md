# Upgrading to 5.30

This page is for operators moving a running KMS from a 5.x release to 5.30. 5.30 closes the security advisories COSMIAN-2026-049 to COSMIAN-2026-083 (listed in `SECURITY.md`) and follows KMIP 2.1 strictly: there is no legacy mode and no compatibility exception that contradicts the specification. The defaults are now the secure ones. The database is upgraded automatically at startup (see [Database Migrations](./database_migrations.md)); the work for operators is in the configuration, the identities, the integrations and the clients. Each area below lists what 5.30 does and what to do on an existing installation, and "No action if …" means the row only concerns a setup you may not have.

## Before you upgrade

1. **Inventory the KMIP clients and integrations** that talk to the server, and for each one note which operations it sends (create/register, locate/get, encrypt/decrypt/MAC, rotate, revoke/destroy). The [client changes](#client-changes) table below tells you which of them can break.
2. **Take a cold backup of the database** with the server stopped. For SQLite, copy the whole `sqlite_path` directory (`cp -a`). For the other backends, use the backend's own dump tool.
3. **Plan recovery as "restore the backup with the old binary".** Opening a database written by 5.30 with a 5.x server is not supported, even if a pre-runner binary does not refuse startup. Restore the pre-upgrade backup before starting the 5.x binary. Keys and changes made after that backup are not retained.
4. **Check your source database version.** SQL databases created on KMS `5.0.0` or later and Redis-with-Findex databases (*non-FIPS only*) created on `5.12.0` or later upgrade automatically at startup. Older databases are refused at startup and require export and re-import; see [Database Migrations](./database_migrations.md#supported-source-versions).
5. **If you use Set Constraints, configure a Crypto Officer first** (see the table below): `[roles] crypto_officer_users`.
6. **Stop every node before starting 5.30: there is no rolling upgrade.** A 5.x node running against a database already used by 5.30 does not honour the new object-state triggers (PostgreSQL) nor the Usage Limits accounting; see [database tables](../../configuration/database/tables.md).
7. **Upgrade `ckms` together with the server.** A 5.29.0 `ckms certificates validate` exits 0 against a 5.30 server even for an invalid chain: 5.30 answers with an `Invalid` validity indicator instead of an error, and the 5.29.0 client prints it without failing.

## Server configuration and startup

| From 5.30 | What to do on an existing installation |
|---|---|
| The new `insecure_allow_unauthenticated` parameter (`--insecure-allow-unauthenticated`, `KMS_INSECURE_ALLOW_UNAUTHENTICATED`, Helm `kms.insecureAllowUnauthenticated`) defaults to `false`: the server starts on a non-loopback address only when an authentication method is configured. The Docker image, the packaged `kms.toml` and the Helm chart bind `0.0.0.0` (COSMIAN-2026-072, [#1486](https://github.com/Cosmian/kms/issues/1486)). | Configure an authentication method. For a development server only, set `insecure_allow_unauthenticated = true`. |
| `ui_session_salt` must be random: at least 32 random bytes, as hex or base64. A passphrase stops the server at startup with `ui_session_salt must be random` (COSMIAN-2026-078, [#1487](https://github.com/Cosmian/kms/issues/1487)). | No action if you do not set `ui_session_salt`. Otherwise generate one with `openssl rand -hex 32`. |
| `google_cse_disable_tokens_validation` and `azure_ekm_disable_client_auth` stop the server at startup unless it is built with the `insecure` feature; release builds are not ([#1534](https://github.com/Cosmian/kms/pull/1534)). | Remove both options from production configurations. |
| `auth_verifier_url`, `auth_verifier_jwks_uri` and `vault_auth_verifier_url` must use `https://`; `http://` is accepted only for loopback hosts. Redirects are no longer followed and the connection has a 5 s connect and 10 s total timeout ([#1487](https://github.com/Cosmian/kms/issues/1487)). | Switch the verifier URLs to `https://`, and add the verifier CA to the server trust if it is private. |
| `vault_auth_verifier_url` receives standard Vault paths: the KMS calls `GET <url>/v1/auth/token/lookup-self` and forwards `/v1/auth/*` unchanged. 5.29.0 called `/auth/token/lookup-self` and stripped `/v1` ([#863](https://github.com/Cosmian/kms/issues/863)). | Upgrade the Cosmian Auth Verifier together with the KMS, or point the option to OpenBao or Vault. No action if you do not use the Vault API. |
| `scep_allow_renewal_without_challenge` now defaults to `false`: `GetCACaps` no longer advertises `Renewal` and `RenewalReq` is rejected ([#1493](https://github.com/Cosmian/kms/issues/1493)). | Set it to `true` if your devices renew without a challenge. No action if you do not use SCEP. |
| A FIPS build stops at startup when the non-validated OpenSSL `default` provider is active, for example through `OPENSSL_CONF` ([#1367](https://github.com/Cosmian/kms/issues/1367)). | Remove the `default` provider activation from the environment of a FIPS server. |
| MySQL `ssl-mode=VERIFY_CA` or `VERIFY_IDENTITY` with `ssl-ca` now trusts only the CA given in `ssl-ca`, not the system store ([#1495](https://github.com/Cosmian/kms/issues/1495)). | Make `ssl-ca` hold the root CA of the database server chain. |
| CRL Distribution Points resolving to private or internal addresses are rejected; the blocked ranges are extended (including `100.64.0.0/10` and `0.0.0.0/8`) (COSMIAN-2026-082, [#1493](https://github.com/Cosmian/kms/issues/1493)). | No action if your CRL Distribution Points are public. Otherwise publish the CRLs on a public address. |
| OTLP `https://` endpoints are rejected at startup, because TLS transport is not compiled into the exporter ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Send telemetry to a local or sidecar OpenTelemetry Collector with an `http://` endpoint and `--otlp-allow-insecure`, and let the collector forward over TLS. |

## Authentication and identities

Access grants, ownership and `[roles]` lists are keyed on identities, so review the identities your users now get before you hand the upgraded server back to them.

| From 5.30 | What to do on an existing installation |
|---|---|
| Users of the second and later `jwt_auth_provider` entries get the identity `email#<jwt_issuer_uri>`; the UI OIDC identity does too, unless its issuer is the first provider's (COSMIAN-2026-074, [#1516](https://github.com/Cosmian/kms/pull/1516), [#1486](https://github.com/Cosmian/kms/issues/1486)). | Rewrite the access grants, the ownership expectations and the `[roles]` lists of those users in that form. No action with a single identity provider. |
| JWT and UI OIDC logins require `email_verified: true` (COSMIAN-2026-074). | Make the identity provider emit `email_verified`. Microsoft Entra ID access tokens omit it and are rejected. |
| An identity equal to `default_username` is rejected with 401 for a client-certificate CN, JWT, Auth Verifier, SAML subject and UI session user, over HTTP and over the KMIP socket. Only the API token and the unauthenticated mode act as `default_username` (COSMIAN-2026-075). | Choose a `default_username` distinct from every real identity. |
| Auth Verifier tokens of the admin realm (`_`) are rejected, and so are tokens of any realm other than `auth_verifier_realm` when it is set (COSMIAN-2026-073). | Issue the tokens of your clients in the realm named by `auth_verifier_realm`. |
| The UI OIDC `id_token` must carry `exp`, `iss`, `aud` and `sub`. | Check that your identity provider emits the four claims. |
| `X-Vault-Token` counts as configured authentication on every scope (KMIP, `/v1/crypto`, `/tokenize`, MS-DKE, KV, SSH). With `vault_api_enabled = true` and `vault_auth_verifier_url` (both in the `[vault]` table of `kms.toml`) as the only authentication method, a request without credentials is rejected on every scope instead of running as `default_username` as on 5.29.0 (COSMIAN-2026-061, [#1437](https://github.com/Cosmian/kms/issues/1437)). | Give such clients a Vault token (`X-Vault-Token`), or configure another authentication method, for example an mTLS client certificate. |
| The Web UI uses an `auth_session` cookie, with a key derived from `ui_session_salt`, in place of the `actix-session`/`actix-identity` cookie. Sessions expire after 1 h idle or 24 h total and are revoked at logout. `POST /ui/login_as` is throttled to 10 per minute per IP and 5 per minute per user, then answers `429` (COSMIAN-2026-076, COSMIAN-2026-077, COSMIAN-2026-078, [#1480](https://github.com/Cosmian/kms/issues/1480), [#1487](https://github.com/Cosmian/kms/issues/1487)). | Expect every Web UI user to sign in again after the upgrade. Space out scripted `login_as` calls. |
| mTLS revocation is enforced once `clients_crl_dir` (`--clients-crl-dir`) is set: a certificate that cannot be checked against its CRL is rejected. The option is opt-in (COSMIAN-2026-079). | No action if you do not set `clients_crl_dir`. Otherwise keep the CRL files in that directory current. |

## Database and storage

The database upgrade needs no manual step except where a row below says so. The matrix of tested source releases is in [Migration matrix by database backend](#migration-matrix-by-database-backend); the nightly `mise run test:db:upgrade` gate that produces it is described there too.

| From 5.30 | What to do on an existing installation |
|---|---|
| A new startup migration step, `StoredStateSync` (SQLite, PostgreSQL, MySQL/MariaDB, Redis-Findex), rewrites the lifecycle `State` stored in each object's attributes and key-block attributes to the value of the `objects.state` column. It scans every `objects` row once at the first 5.30 start and skips unparsable rows with a warning. API output is unchanged ([#1539](https://github.com/Cosmian/kms/pull/1539)). | No manual step. Allow a longer first start on a large database, and restore the pre-upgrade backup to go back to 5.29.0. |
| For objects created before 5.13.0, Get Attributes reports `KeyFormatType` as the format a Get returns (`Raw` for symmetric keys, `PKCS1` for RSA keys) and `State` from the enforced object state (`Active`, `Destroyed`). No data changes. | Update the clients that compare these two attributes. |
| Redis-Findex certificates re-certified on 5.12.x have their Findex entries rebuilt from the stored record, so Locate by a user tag that the record had already lost no longer finds them. | Locate those certificates by another attribute, or re-add the tag. |
| KEK-wrapped objects are bound to their row (`x-cosmian-stored-uid`). With an RSA-OAEP key encryption key of 2048 bits, stored-key UIDs are limited to about 58 characters ([#1519](https://github.com/Cosmian/kms/issues/1519)). | Stop every 5.29.0 instance before starting 5.30; do not run both versions on one database. |
| Split-key shares, derived keys, joined keys, `Certify` key pairs and KV secret versions are now stored wrapped under `key_encryption_key`. 5.29.0 cannot join shares created by 5.30 (COSMIAN-2026-062, [#1437](https://github.com/Cosmian/kms/issues/1437)). | Join or re-split before downgrading. |
| Usage Limits accounting decrements the Count. | A downgrade is degraded (5.29.0 grants the full Total again) and a mixed-version operation is unsupported. |
| An AES-GCM invocation counter (table `gcm_invocations`) limits a key to 2^32 invocations: `Encrypt`, `MAC` and GCM wrapping then answer `Permission_Denied`. | Rotate a key before it reaches the limit. A downgrade is degraded: encryptions 5.29.0 performs are not counted. |
| The versioned migration runner rejects databases stamped by a newer KMS, and databases older than `5.0.0` (SQL) or `5.12.0` (Redis-Findex) ([#1270](https://github.com/Cosmian/kms/issues/1270) to [#1272](https://github.com/Cosmian/kms/issues/1272)). | For older databases, export and re-import (see [Database Migrations](./database_migrations.md#supported-source-versions)). |
| New tables `cluster_nodes`, `ui_session_revocations`, `gcm_invocations` and `kms_cron_leases` are created automatically. | On a multi-region PostgreSQL/Spock deployment, run `SELECT spock.repset_add_table('default', 'ui_session_revocations');` on every node. |
| When the database rejects `GET_LOCK` (Percona XtraDB Cluster strict mode, MariaDB Galera), the scheduled jobs (CRL refresh, key rotation, expiry warnings) take a replicated 300 s lease in `kms_cron_leases`. Old and new nodes do not exclude each other until every node runs 5.30 ([#1511](https://github.com/Cosmian/kms/issues/1511), [#1535](https://github.com/Cosmian/kms/pull/1535)). | Upgrade every node, accept that jobs may run twice during a rolling upgrade, and keep the database nodes NTP-synchronised. |
| Crypto Officer ceremony records are bound to their user, and revoked records are erased ([#1495](https://github.com/Cosmian/kms/issues/1495)). | On Redis, run Crypto Officer disable again for the users revoked before the upgrade. |
| New Redis-Findex databases derive their master key with a random per-database salt stored in `kms_kdf_salt`; existing databases keep the legacy salt ([#1528](https://github.com/Cosmian/kms/pull/1528)). | No action on an existing database. A database created empty by 5.30 cannot be read by an older release. |
| SQLite database and migration-lock files are created with mode 0600, and existing files are tightened ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Run the server with the OS user that owns the files; other OS users lose read access. |
| The AWS XKS key-access migration runs once per database: tagging an object `aws-xks` no longer grants it again to the XKS service identity after each restart ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Grant access explicitly to an object you tag `aws-xks` after the upgrade. |

## Migration matrix by database backend

Result of `mise run test:db:upgrade` (both the `non-fips` and `fips` images, every release from 5.9.0): a database filled by a published 5.x image (every object kind and KMIP operation reachable through `ckms`), opened by the 5.30 server, then checked after the upgrade, after a restart, and after restoring the pre-upgrade backup with the old image. Each cell runs twice: without and with a key encryption key (KEK) configured on the server.

| Source release | SQLite | PostgreSQL | MySQL | Redis-with-Findex (non-FIPS) |
|---|---|---|---|---|
| 5.9.0 to 5.11.2 | ✅ | ✅ | ✅ | ❌ refused by design |
| 5.12.0 to 5.12.1 | ✅ | ✅ | ✅ | ✅ |
| 5.13.0 to 5.29.0 | ✅ | ✅ | ✅ | ✅ |

- ✅ the upgrade, restart and restore checks all passed.
- ❌ refused by design: Redis-with-Findex databases written before 5.12.0 are rejected at startup (see [Database Migrations](./database_migrations.md#supported-source-versions)).
- Reporting change, no data change: for objects created before 5.13.0, Get Attributes now reports `KeyFormatType` as the format a Get returns (`Raw` for symmetric keys, `PKCS1` for RSA keys) instead of the stored `TransparentSymmetricKey`/`TransparentRSA*` form, and reports `State` from the enforced object state (`Active`, `Destroyed`) where 5.9 to 5.12 reported a stale `PreActive` or `Deactivated`. Key material and the server's behaviour are unchanged; update any client that compares these two attributes.
- Redis-with-Findex 5.12.x only: a certificate re-certified on 5.12.x had lost its user tags in the stored record while the Findex index still listed them, so Locate by that tag still found it. The upgrade rebuilds the index entries from the stored record (while adding the `_serial=` tag), so such a certificate is no longer found by the tag it had already lost.

Run it yourself before cutting over: `mise run test:db:upgrade --backend <sqlite|postgresql|mysql|redis|all> --old-version <all|5.x.y,...>` (Docker required; `--variant non-fips` for Redis). In CI it runs nightly, on tags and on dispatch, not on pull requests. SQL upgrades from 5.0.0 to 5.8.x are accepted by the runner but not covered by this gate. The package upgrade tests remain same-version (see [Packages](#packages)).

## Client changes

Each row is a behaviour that changed to follow KMIP. The last column is what the client or operator must do.

| Change | 5.x behaviour | 5.30 behaviour | Client action |
|---|---|---|---|
| Revoke of a Pre-Active object | A non-compromise Revoke moved it to Deactivated. | A non-compromise Revoke is refused with `Wrong_Key_Lifecycle_State`; the object stays Pre-Active. A compromise reason is still accepted. | Destroy a never-activated object directly, or activate it before use and revoke it when retiring it. |
| Batch error continuation | An omitted `BatchErrorContinuationOption` continued after a failed item. | An omitted option is `Stop`. | Send `Continue` when later items must still run, and check every result. |
| KMIP 1.4 DeriveKey | A request without Object Type was accepted as a symmetric key. | The Object Type is required. | Send `ObjectType` (for example `SymmetricKey`). |
| IV Length | A byte value equal to the nonce size (for example `12` for AES-GCM) was accepted. | IV Length is in bits only; `12` is refused with `Bad_Cryptographic_Parameters`. A client-supplied IV is used as is (non-FIPS builds only: a FIPS build refuses a caller-supplied IV, see [FIPS builds](#fips-builds)). | Send `96` for AES-GCM and let the server generate the IV, or supply the IV on a non-FIPS build. For `ovh/kmip-go` users, override `IVLength` with `96`. |
| MAC and MAC Verify usage mask | The key's usage mask was not checked. | MAC needs the `MACGenerate` bit and MAC Verify the `MACVerify` bit; otherwise `Incompatible_Cryptographic_Usage_Mask`. | Create new keys with both bits and re-MAC the data. Do not rely on editing the usage mask of an existing key. |
| Revoke of a Pre-Active Opaque Object | Accepted. | Refused like any Pre-Active object (`Wrong_Key_Lifecycle_State`). | Destroy it directly. |
| Certify without an Activation Date | The certificate was Active. | The certificate starts Pre-Active, and ReCertify accepts only Active or Deactivated certificates. | Send an Activation Date in Certify, or Activate the certificate before workflows that need it Active. |
| Attribute edits with a `Get`-only grant | A `Get` grant allowed edits of usage mask, dates, links, usage limits and similar protected attributes. | Those edits need ownership or an explicit grant of the edit operation. | Grant the edit operation explicitly or let the owner perform it. |
| Protection Storage Mask | Could be added, set and deleted. | Server-managed and read-only: Add/Set return `Read_Only_Attribute`, Modify/Delete return `Attribute_Read_Only`. | Stop writing it; read it with Get Attributes. |
| Set Constraints | Accepted from any authenticated user on a server without roles. | Refused with `Unauthorized` unless a Crypto Officer is configured, like PKCS11; once roles are configured, only Crypto Officers may call it. Get Constraints stays open to every authenticated user. | Before upgrading, add `[roles] crypto_officer_users = [...]` to the server configuration and call Set Constraints as one of those users. |
| KMIP 2.0 Query | Listed Ping, Set Constraints and Get Constraints. | A KMIP 2.0 request no longer lists them (they are KMIP 2.1 operations); a 2.1 request still does. | Do not use these operations from a 2.0 client. |
| Get Attribute List and Get Attributes | Listed attributes that were not set, and reported an invented Random Number Generator attribute (ANSI X9.31, AES, 256) on every object. | Lists and reports only the attributes set on the object. | Treat absent attributes as absent. |
| Usage Limits Unit | `Block` and `Operation` values. | The KMIP 2.1 values `Byte` = 1 and `Object` = 2; stored `Block`/`Operation` values are read as `Object`. | Use the spec values. |

### Additional KMIP rules

| From 5.30 | What to do on an existing installation |
|---|---|
| `DeriveKey` requires the Create permission ([#1492](https://github.com/Cosmian/kms/issues/1492)). | Grant Create to the users that derive keys. |
| Result Reasons follow each operation's error table (for example `Object_Not_Found`, `Read_Only_Attribute`, `Invalid_Attribute_Value`, `Object_Already_Exists`), with version-specific codes for KMIP 1.x. Wrap and unwrap answer `Permission_Denied` for a missing or unusable key. An HSM `ReKey` answers `Item_Not_Found` or `Invalid_Object_Type` ([#1312](https://github.com/Cosmian/kms/issues/1312), [#1313](https://github.com/Cosmian/kms/issues/1313)). | Match on the codes of the KMIP error tables rather than on the former codes. |
| `Locate` returns the newest object first and empties the ID Placeholder when several objects match. Set Attribute `Name` replaces the name. | Read the full Locate result instead of the ID Placeholder, and add a second name with Add Attribute. |
| Create Key Pair rejects conflicting algorithm, length or curve between the private and public key attributes (`Invalid_Attribute`). | Send consistent attributes for both keys. |
| The KMIP 1.4 enumeration codes follow the specification: Recommended Curve (SECP256K1 = `0x19`, Brainpool from `0x37`) and Key Compression Type. | Regenerate or update a client that hard-codes the former values. |
| Bounds apply: CRL `validity_days` up to 365; `RotateInterval` and `RotateOffset` 0 to 4294967295 s; DeriveKey length 8 to 8192 bits and PBKDF2 work up to 10,000,000; FPE data and tweak up to 4096 bytes; `CreateSplitKey` up to 8 KiB; Bulk Encrypt rejects a reused client IV ([#1489](https://github.com/Cosmian/kms/issues/1489)). | Keep requests inside the bounds, and use a fresh IV per Bulk Encrypt item. |
| `CreateSplitKey` rejects `Sensitive` and non-extractable keys ([#1490](https://github.com/Cosmian/kms/issues/1490)). | Split a key created with `Sensitive` false and extractable. |
| Keyset decryption by bare name rejects the modes without wrong-key detection: CBC, ECB, CTR, XTS, ChaCha20, FPE and RSA PKCS#1 v1.5 (COSMIAN-2026-057). | Address the key as `name@N`. |
| User-supplied system tags (`_...`) are stripped on `Import` and rejected on `Create`. | Stop sending tags that start with `_`. |
| The server-only vendor attributes `x-cosmian-split-key-source` and `x-cosmian-share-wrapping-key` cannot be written by clients (`SetAttribute`, `AddAttribute`, `ModifyAttribute`, `Import`, `Register`, `Create`, `CreateKeyPair`) ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Stop writing them; the server sets them. |
| With `crypto_officer.require_ceremony`, only Crypto Officer candidates and the `default_username` provisioning identity trigger a ceremony split in `CreateSplitKey`; other callers holding Create get an ordinary split they own ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Run the ceremony split as a Crypto Officer candidate. |
| `Locate` rejects `OffsetItems` above 1,000,000. The algorithm policy also checks the Key Wrapping Specification of `Get`, as it does for `Export` ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Page a large Locate with a smaller offset, and wrap with an algorithm the policy allows. |
| `Validate` reads its `certificate` as Certificate structures. | Send Certificate structures, not raw bytes. |

The full list of changes is in the release notes.

## Packages

- **Debian and RPM packages**: the post-remove script of 5.29.0 and earlier stops and disables `cosmian_kms.service` during an upgrade. The 5.30 packages record whether the service was enabled and running before the upgrade, restore both afterwards (the service restarts on the new binary), and no longer disable it on upgrade; a fresh install still leaves the service stopped. `/etc/cosmian/kms.toml` is kept, with a timestamped copy next to it in `/etc/cosmian/`. The packaged `kms.toml` template of 5.30 sets `region_role` and a `[kv]` section; merge any new key you need by hand.
- **Debian, edited `kms.toml`**: when you changed `/etc/cosmian/kms.toml`, dpkg asks whether to keep it because the packaged template changed. A non-interactive `apt-get install ./cosmian-kms-server-*.deb` fails with `end of file on stdin at conffile prompt` and leaves the package unconfigured (service disabled). Run it with `-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold` to keep your file (the new template is then written to `kms.toml.dpkg-dist`), or answer `N` at the prompt. If the upgrade already aborted, finish it with `dpkg --configure -a --force-confold`, which also restores the service state; do not run the install a second time before that, it would record the already disabled state.
- **Windows installer**: `kms.toml`, `data` and `logs` are kept, whether the installer runs silently, interactively with "uninstall before installing", or without uninstalling. The new default configuration is written to `kms.toml.new` next to `kms.toml`; merge new keys by hand. The installers of 5.29.0 and earlier replaced `kms.toml` by the template and, with "uninstall before installing", deleted `data` and `logs`. The 5.30 installer saves and restores them around the old uninstaller; as a precaution (that interactive path has no automated test), keep a copy of `kms.toml` and the `data` directory before running it.

## FIPS builds

A 5.30 FIPS build enforces more of the FIPS 140-3 rules than 5.29.0:

- a caller-supplied AES-GCM IV is refused (the server generates it);
- HMAC generation with a key shorter than 112 bits is refused;
- PBKDF2 DeriveKey needs a salt of at least 16 bytes, at least 1000 iterations and an output of at least 14 bytes;
- ML-KEM, ML-DSA, SLH-DSA, `X25519MLKEM768`, Ed25519 and Ed448 are now available (OpenSSL FIPS provider 3.5.9); `X448MLKEM1024`, `ConfigurableKEM` and standalone X25519/X448 stay non-FIPS;
- the server refuses to start when the `default` provider is activated through `OPENSSL_CONF`;
- an AES-GCM key is limited to 2^32 invocations.

### HSM

| From 5.30 | What to do on an existing installation |
|---|---|
| HSM keys created without `Sensitive` are sensitive and non-extractable by default ([#1490](https://github.com/Cosmian/kms/issues/1490)). | Send `Sensitive=false` (`ckms ... --sensitive false`) for a key that must be exportable. |
| HSM keys addressed by UID obey the KMIP algorithm policy, and retired HSM generations reject Encrypt, Sign and MAC. `SetAttribute RotateAutomatic` on HSM keys and rotation attributes in HSM `Create` and `CreateKeyPair` are rejected (COSMIAN-2026-058, COSMIAN-2026-059). | Address the current generation of a key, and stop sending rotation attributes for HSM keys. |
| Waiting for a pooled HSM session ends after 30 s instead of waiting indefinitely ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Size the HSM session pool for your peak concurrency. |
| A FIPS AES-GCM Encrypt by HSM keyset name needs an HSM that can generate the IV; SoftHSM2 and Kryoptic cannot. | Use an HSM that generates the GCM IV, or keep the key in the KMS. |
| RSA PKCS#1 v1.5 and SHA-1 OAEP encryption are rejected on HSM keys. | Use RSA-OAEP with SHA-256 or higher. |
| The OpenSSL FIPS provider moves from 3.1.2 to 3.5.9 (CMVP #5586), and the SBOM targets are renamed `openssl_fips` and `openssl_main` ([#1502](https://github.com/Cosmian/kms/issues/1502)). | Update the compliance records and the tooling that reads the SBOM target names. |

## HTTP APIs and integrations

| From 5.30 | What to do on an existing installation |
|---|---|
| Google CSE: the privileged endpoints (`privilegedwrap`, `privilegedunwrap`, `privilegedprivatekeydecrypt`) accept only the users whose email is listed in the new `google_cse_privileged_users` option (`--google-cse-privileged-users`, `KMS_GOOGLE_CSE_PRIVILEGED_USERS`). It is empty by default, so everyone gets 401. `privilegedunwrap` also accepts a KACLS migration token whose `aud` is `kacls-migration`, whose `kacls_url` is this KACLS and whose `resource_name` is the requested resource ([#1485](https://github.com/Cosmian/kms/issues/1485), [#1534](https://github.com/Cosmian/kms/pull/1534)). | List the administrators in `google_cse_privileged_users`. |
| Google CSE: KACLS migration tokens of the servers listed in `google_cse_incoming_url_whitelist` no longer authenticate end users on the other CSE endpoints, nor on the KMIP API ([#1534](https://github.com/Cosmian/kms/pull/1534)). | No action unless you used a migration token as a user token. |
| Google CSE: tokens naming a reserved service identity (such as the AWS XKS service identity) are rejected on every token path, and `private_key_sign` rejects SHA-1 RSA signatures in FIPS builds ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Use a token of a real user identity, and SHA-256 or higher. |
| Microsoft DKE: `/ms_dke` no longer answers cross-origin browser requests (no permissive CORS). Native Office clients send no `Origin` and are unaffected ([#1534](https://github.com/Cosmian/kms/pull/1534)). | No action for Office clients. |
| AWS XKS: bodies above 2 MiB get 413, and SigV4 parsing is stricter: duplicate `Authorization` parameters, and duplicate or uppercase `SignedHeaders`, are rejected ([#1488](https://github.com/Cosmian/kms/issues/1488)). | Check the XKS proxy sends a single well-formed `Authorization` header. |
| `/health` reports `DEGRADED` (HTTP 200) when an HSM is down or the KMIP socket server is stopped; the `DOWN` messages are fixed text (COSMIAN-2026-064, [#1366](https://github.com/Cosmian/kms/issues/1366)). | Make the load balancer and the monitoring read the status text, not only the HTTP status. |
| OCSP answers an unsigned `tryLater` on database errors (it answered `unknown`), and `Locate` and CRL generation return the error (COSMIAN-2026-080). | Let OCSP clients retry on `tryLater`. |
| SSH and `/v1/secrets/password` require `X-Vault-Token` when the Vault verifier is the only method ([#864](https://github.com/Cosmian/kms/issues/864)). | Send the Vault token from those clients. |
| `/ui/logout` accepts `POST` only; `GET` returns 405 ([#1528](https://github.com/Cosmian/kms/pull/1528)). | The Web UI is updated. Switch custom scripts or links that call `GET /ui/logout` to `POST`. |
| The Web UI index page and static assets carry a Content-Security-Policy that restricts scripts, styles, images, connections, objects and the base URI to the server's own origin. Every response also carries `Strict-Transport-Security`, `Referrer-Policy: same-origin` and `X-Content-Type-Options: nosniff` ([#1528](https://github.com/Cosmian/kms/pull/1528)). | A reverse proxy or a customised UI that loads external resources must serve them from the KMS origin. |
| `GET /version` no longer reports the OpenSSL build string; the `(FIPS)` or `(non-FIPS)` flavour stays. `GET /server-info` keeps the detail for authenticated users ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Read the OpenSSL build from `GET /server-info`. |
| The `cosmian_kms` secret backend uses plain `http` only for `localhost`, `127.0.0.1` and `::1`; other hosts (for example `localhost.evil.com`) use `https` ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Serve any non-loopback KMS used as a secret backend over `https`. |

## Command-line client (ckms)

| From 5.30 | What to do on an existing installation |
|---|---|
| `ckms certificates validate` exits with an error unless the chain is `Valid`. | Check the exit code in scripts that used to ignore it. |
| `ckms login` and `ckms logout` no longer persist `--url`, `--accept-invalid-certs`, `--header` or the proxy flags to `ckms.toml`, and written files have mode 0600 ([#1497](https://github.com/Cosmian/kms/issues/1497)). | Set the URL and the proxy in `ckms.toml` or on each command. |
| A FIPS `ckms` no longer offers AES-XTS. | No action unless you use `ckms` with AES-XTS; use a non-FIPS build for XTS. |
| A FIPS server rejects a caller-supplied AES-GCM IV, so the nonce option of `ckms sym encrypt` (`--nonce`) does not apply to AES-GCM there. | Let the server generate the IV. |
| `auth_verifier_login` and the OAuth callback no longer follow redirects, ignore the `HTTP(S)_PROXY` environment and use the host CA bundle instead of the bundled webpki roots. | Add your CA to the host trust store. |
| The `ckms` Auth Verifier login requires an `https://` server URL, except for loopback hosts ([#1528](https://github.com/Cosmian/kms/pull/1528)). | Use an `https://` URL. |

## Deployment tooling and developers

- **MISE tasks:** the test tasks are regrouped (`test:psql` becomes `test:db:psql`, `test:hsm-softhsm2` becomes `test:hsm:softhsm2`, `test:ocsp` becomes `test:pki:ocsp`, and so on) and `test:ui:standard --standard-only` is removed ([#1418](https://github.com/Cosmian/kms/issues/1418)). Update your scripts and CI jobs.
- **Nix and Docker build:** the `.mise/scripts/nix.sh` dispatcher is removed, and `build:docker` no longer takes `--test` or `--force` ([#1420](https://github.com/Cosmian/kms/issues/1420)).
- **Monitoring stack:** there are no default credentials, the P12 password is passed through `KMS_TLS_P12_PASSWORD`, VictoriaMetrics is published on `127.0.0.1` only, the images are pinned by digest, and `resources/kms.toml` no longer enables a placeholder Redis master password ([#1500](https://github.com/Cosmian/kms/issues/1500), [#1528](https://github.com/Cosmian/kms/pull/1528)). Set the credentials, and expose VictoriaMetrics yourself if you need it.
- **Kubernetes operator:** `KMSSecret` `status.lastSecretHash` is removed (cleared on the next reconcile), and the mutating webhook rejects an annotated pod with invalid injection annotations instead of admitting it without the init container ([#1528](https://github.com/Cosmian/kms/pull/1528)).
- **`cosmian_kmip`:** in `kmip_1_4::kmip_operations`, omitted `unique_identifier` (and similar) fields are now `Option`. Secret-bearing KMIP fields use `cosmian_kmip::Sensitive<T>` (`SensitiveBytes`, `SensitiveString`) with an unchanged wire format ([#1426](https://github.com/Cosmian/kms/issues/1426)). `Validate.certificate` is `Option<Vec<Certificate>>`, and `RequestMessageHeader::default()` no longer sets a 1 MiB Maximum Response Size.
- **`cosmian_pkcs11_module`:** `PublicKey::rsa_public_key` returns `openssl::rsa::Rsa<Public>`, `ec_p256_public_key` returns `openssl::ec::EcKey<Public>`, `ModuleError::Pkcs1DerError` is renamed `ModuleError::Der`, and `DataObject::data_hash` is removed.
- **`cosmian_kms_client`:** it no longer depends on `actix-web`, `reqwest` or `oauth2`. The `allows_caller_iv_in_fips` option is removed.

## Downgrading

Restoring the pre-upgrade database backup is required (see above). Also restore the pre-upgrade `kms.toml`, or remove `region_role` and the `[kv]` section from it: a 5.29.0 server rejects unknown keys at startup, and the deb and rpm packages keep the current `kms.toml` on a package downgrade.

## Verify the upgrade

Test your real client applications against a non-production copy of your database upgraded to 5.30 before cutting over production traffic:

- create or register a key;
- locate and get it;
- use it (encrypt/decrypt, sign/verify, MAC), including the IV and usage-mask rows above;
- rotate it (re-key);
- revoke and destroy it, including a key that was never activated;
- start the server with your authentication method and without `insecure_allow_unauthenticated`;
- log in through each identity provider and check the identity the server records: `email#<issuer>` for the second and later providers;
- run `curl --cacert <CA> https://<host>/health` and expect 200 with `UP` (`DEGRADED` when an HSM or the KMIP socket server is down).

## Tested clients

Results of running client libraries against 5.29.0 and 5.30 servers. "Adapted" means a synthetic client workload rather than a vendor product test suite.

| Client | Workload | 5.29.0 server | 5.30 server |
|---|---|---|---|
| PyKMIP 0.10.0 (Python 3.11.15), adapted | 17 KMIP operations | Non-FIPS build: 17/17. FIPS build: 14/17. | Non-FIPS build: 17/17. FIPS build: 14/17. |
| `ovh/kmip-go` v0.9.2, adapted | Updated workload (`IVLength` = 96) | Passes (FIPS and non-FIPS builds). | Passes (FIPS and non-FIPS builds). |
| `ovh/kmip-go` v0.9.2, adapted | Pre-5.30 workload (`IVLength` = 12) | Passes. | Fails, see below. |

- **PyKMIP, FIPS builds** (5.29.0 and 5.30 alike): `create_keypair`, `sign` and `signature_verify` fail because the driver's RSA key pair carries no usage mask and a FIPS build refuses it (`RSA: forbidden CryptographicUsageMask value, got None but expected among 0x00000A29 in FIPS mode`). This is unrelated to the upgrade.
- **kmip-go, 5.29.0 workload against 5.30**: `TestEncryptDecryptAES_GCM_V14` and `TestEncryptDecryptAES_GCM_MultiVersion` (V1.2, V1.4) fail with `Encrypt: IV Length of 12 bits is not valid for Aes256Gcm` (the IV Length row above: send `96`). `TestVersionGating_KMIP12` (1.2, 1.3, 1.4) fails because Get Attribute List no longer lists `Alternative Name`, which the workload expected on a new key (the Get Attribute List row above).

Not tested: the Synology DSM client script, other KMIP client libraries and products, KMIP 1.x clients other than the `ovh/kmip-go` KMIP 1.2 to 1.4 cases above.

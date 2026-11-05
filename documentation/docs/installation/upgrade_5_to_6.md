# Upgrading from 5.x to 6.0

This guide is for operators moving a running KMS from a 5.x release to 6.0. 6.0 follows KMIP strictly: there is no legacy mode and no compatibility exception that contradicts the specification. A request that a 5.x server accepted can therefore fail on 6.0, and a batch can stop earlier than before. The database schema is upgraded automatically at startup (see [Database migration](../configuration/database/configuration.md#database-migration)); the work for you is in the clients.

## Before you upgrade

1. **Inventory the KMIP clients and integrations** that talk to the server, and for each one note which operations it sends (create/register, locate/get, encrypt/decrypt/MAC, rotate, revoke/destroy). The [client changes](#client-changes) table below tells you which of them can break.
2. **Take a cold backup of the database** with the server stopped. For SQLite, copy the whole `sqlite_path` directory (`cp -a`). For the other backends, use the backend's own dump tool.
3. **Plan recovery as "restore the backup with the old binary".** Opening a database written by 6.0 with a 5.x server is not supported: once 6.0 has written to the database, go back by restoring the pre-upgrade backup, not by starting the old binary on the new data.
4. **Know what is verified.** Only the SQLite path from 5.29.0 is covered by an automated upgrade proof (see [Verify the upgrade](#verify-the-upgrade)). PostgreSQL, MySQL and Redis upgrades are not covered by it. If you run Redis-findex from a release older than 5.12, read the limits in [Redis migration](../configuration/database/redis.md#migration) first.
5. **If you use Set Constraints, configure a Crypto Officer first** (see the table below): `[roles] crypto_officer_users`.

## Client changes

Each row is a behaviour that changed to follow KMIP. The last column is what the client or operator must do.

| Change | 5.x behaviour | 6.0 behaviour | Client action |
|---|---|---|---|
| Revoke of a Pre-Active object | A non-compromise Revoke moved it to Deactivated. | A non-compromise Revoke is refused with `Wrong_Key_Lifecycle_State`; the object stays Pre-Active. A compromise reason is still accepted. | Destroy a never-activated object directly, or activate it before use and revoke it when retiring it. |
| Batch error continuation | An omitted `BatchErrorContinuationOption` continued after a failed item. | An omitted option is `Stop`. | Send `Continue` when later items must still run, and check every result. |
| KMIP 1.4 DeriveKey | A request without Object Type was accepted as a symmetric key. | The Object Type is required. | Send `ObjectType` (for example `SymmetricKey`). |
| IV Length | A byte value equal to the nonce size (for example `12` for AES-GCM) was accepted. | IV Length is in bits only; `12` is refused with `Bad_Cryptographic_Parameters`. A client-supplied IV is used as is. | Send `96` for AES-GCM, or supply the IV. For `ovh/kmip-go` users, override `IVLength` with `96`. |
| MAC and MAC Verify usage mask | The key's usage mask was not checked. | MAC needs the `MACGenerate` bit and MAC Verify the `MACVerify` bit; otherwise `Incompatible_Cryptographic_Usage_Mask`. | Create new keys with both bits and re-MAC the data. Do not rely on editing the usage mask of an existing key. |
| Revoke of a Pre-Active Opaque Object | Accepted. | Refused like any Pre-Active object (`Wrong_Key_Lifecycle_State`). | Destroy it directly. |
| Certify without an Activation Date | The certificate was Active. | The certificate starts Pre-Active, and ReCertify accepts only Active or Deactivated certificates. | Send an Activation Date in Certify, or Activate the certificate before workflows that need it Active. |
| Attribute edits with a `Get`-only grant | A `Get` grant allowed edits of usage mask, dates, links, usage limits and similar protected attributes. | Those edits need ownership or an explicit grant of the edit operation. | Grant the edit operation explicitly or let the owner perform it. |
| Protection Storage Mask | Could be added, set and deleted. | Server-managed and read-only: Add/Set return `Read_Only_Attribute`, Modify/Delete return `Attribute_Read_Only`. | Stop writing it; read it with Get Attributes. |
| Set Constraints | Accepted from any authenticated user on a server without roles. | Refused with `Unauthorized` unless a Crypto Officer is configured, like PKCS11; once roles are configured, only Crypto Officers may call it. Get Constraints stays open to every authenticated user. | Before upgrading, add `[roles] crypto_officer_users = [...]` to the server configuration and call Set Constraints as one of those users. |
| KMIP 2.0 Query | Listed Ping, Set Constraints and Get Constraints. | A KMIP 2.0 request no longer lists them (they are KMIP 2.1 operations); a 2.1 request still does. | Do not use these operations from a 2.0 client. |
| Get Attribute List and Get Attributes | Listed attributes that were not set, and reported an invented Random Number Generator attribute (ANSI X9.31, AES, 256) on every object. | Lists and reports only the attributes set on the object. | Treat absent attributes as absent. |
| Usage Limits Unit | `Block` and `Operation` values. | The KMIP 2.1 values `Byte` = 1 and `Object` = 2; stored `Block`/`Operation` values are read as `Object`. | Use the spec values. |

The full list of fixes is in the branch changelog (`CHANGELOG/`).

## Verify the upgrade

### Automated SQLite upgrade and restore proof

`mise run test:db:upgrade-sqlite` takes four binaries that you build yourself: the old `cosmian_kms` and `ckms` (for example from the `5.29.0` tag) and the new ones. The binaries decide FIPS or non-FIPS; the task builds and downloads nothing and starts only its own servers on free ports.

```bash
mise run test:db:upgrade-sqlite \
  --old-kms /path/to/5.29.0/target/debug/cosmian_kms \
  --old-ckms /path/to/5.29.0/target/debug/ckms \
  --new-kms target/debug/cosmian_kms \
  --ckms target/debug/ckms
```

It runs four phases on temporary copies of a database:

1. **Seed**: the old server creates keys (one wrapped by another), a name, a certificate with a link, a grant, and a revoked-then-destroyed key; it encrypts with two of them.
2. **Cold backup**: the stopped database is copied twice.
3. **Candidate**: the new server opens one copy. Old ciphertexts must decrypt byte-identically, grants and denials must be unchanged, attributes must match (every old digest must still be present). It then writes (new name, new key), restarts, and checks again.
4. **Restore**: the old server opens the untouched backup: the original name is present and the key created by the new server does not exist.

The attributes are read with the same KMIP 2.1 Get Attributes request on both servers, because `ckms attributes get` does not display State, Link or Digest. The comparison ignores nothing except that 6.0 no longer reports the invented Random Number Generator attribute. This proves only SQLite, only between the two binaries you pass, on this seed data. It does not test your data, your clients or other backends. It has passed from the 5.29.0 tag to this branch, with FIPS binaries and with non-FIPS binaries (debug builds, macOS arm64).

### Business-workflow checklist

Passing repository tests does not prove that an unchanged third-party product works. Rerun your real client against a copy of your database upgraded by 6.0:

- create or register a key;
- locate and get it;
- use it (encrypt/decrypt, sign/verify, MAC), including the IV and usage-mask rows above;
- rotate it (re-key);
- revoke and destroy it, including a key that was never activated.

## Tested clients

Results of running real client libraries against task-owned debug builds of the 5.29.0 tag and of this branch, on macOS arm64. "Adapted" means the workload is a repository script that drives the library, not the vendor's own test suite. This is not a statement about any vendor's deployed product.

| Client | Workload | 5.29.0 server | 6.0 server (this branch) |
|---|---|---|---|
| PyKMIP 0.10.0 (Python 3.11.15), adapted | `.mise/scripts/pykmip/pykmip_client.py`, 17 operations | Non-FIPS build: 17/17. FIPS build: 14/17. | Non-FIPS build: 17/17. FIPS build: 14/17. |
| `ovh/kmip-go` v0.9.2, adapted | Branch workload (`.mise/scripts/kmip-go`, `IVLength` = 96) | Passes (FIPS and non-FIPS builds). | Passes (FIPS and non-FIPS builds). |
| `ovh/kmip-go` v0.9.2, adapted | 5.29.0 workload, unchanged (`IVLength` = 12) | Passes. | Fails, see below. |

- **PyKMIP, FIPS builds** (5.29.0 and this branch alike): `create_keypair`, `sign` and `signature_verify` fail because the driver's RSA key pair carries no usage mask and a FIPS build refuses it (`RSA: forbidden CryptographicUsageMask value, got None but expected among 0x00000A29 in FIPS mode`). This is unrelated to the upgrade.
- **kmip-go, 5.29.0 workload against 6.0**: `TestEncryptDecryptAES_GCM_V14` and `TestEncryptDecryptAES_GCM_MultiVersion` (V1.2, V1.4) fail with `Encrypt: IV Length of 12 bits is not valid for Aes256Gcm` (the IV Length row above: send `96`). `TestVersionGating_KMIP12` (1.2, 1.3, 1.4) fails because Get Attribute List no longer lists `Alternative Name`, which the workload expected on a new key (the Get Attribute List row above).

Not tested: the Synology DSM client script, other KMIP client libraries and products, KMIP 1.x clients other than the `ovh/kmip-go` KMIP 1.2 to 1.4 cases above.

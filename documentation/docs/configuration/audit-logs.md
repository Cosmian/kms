# Audit logging

The Eviden KMS server can write a cryptographically-chained, tamper-evident audit trail of every
KMIP operation to a local JSONL file. Each line is a JSON object; the file is human-readable and
can be parsed by any standard tooling.

Audit logging is **disabled by default**. No file is created and no background writer thread is
spawned until the feature is explicitly enabled.

---

## Enable audit logging

=== "TOML configuration file"

    ```toml
    [audit]
    enabled = true

    [audit.file]
    path = "/var/log/cosmian-kms/audit.jsonl"
    ```

=== "Command line"

    ```bash
    cosmian_kms --audit-enable --audit-file-path /var/log/cosmian-kms/audit.jsonl
    ```

=== "Environment variables"

    ```bash
    export KMS_AUDIT_ENABLE=true
    export KMS_AUDIT_FILE_PATH=/var/log/cosmian-kms/audit.jsonl
    cosmian_kms
    ```

When `audit.file.path` is omitted the file defaults to `<root-data-path>/audit.jsonl`.

---

## Configuration reference

| CLI flag                   | Environment variable         | Default                        | Description                                                                                                                              |
| -------------------------- | ---------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `--audit-enable`           | `KMS_AUDIT_ENABLE`           | `false`                        | Enable the audit pipeline. When `false` no file is created and no writer thread is spawned.                                              |
| `--audit-file-path`        | `KMS_AUDIT_FILE_PATH`        | `<root-data-path>/audit.jsonl` | Absolute path to the JSONL audit log file. Parent directories are created automatically on first write.                                  |
| `--audit-channel-capacity` | `KMS_AUDIT_CHANNEL_CAPACITY` | `4096`                         | Capacity of the bounded in-memory channel between request threads and the writer task. Each event is ≈ 500 B (≈ 2 MiB total at default). |

> **Tip**: if you see `AuditFileStore: channel full` in the server log under sustained high load, raise
> `--audit-channel-capacity`. When the channel is full the event is dropped (non-blocking) and an
> `error!` line is emitted — the request itself is never blocked.

---

## Event schema

Each line in the JSONL file is a complete JSON object with the following fields:

| Field         | Type                                     | Nullable | Description                                                                                                                          |
| ------------- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `id`          | `integer`                                | No       | Monotonically increasing row counter, starting at 0.                                                                                 |
| `timestamp`   | `string` (RFC 3339 / UTC)                | No       | Wall-clock time of the KMIP operation.                                                                                               |
| `operation`   | `string`                                 | No       | KMIP operation name, e.g. `"Create"`, `"Encrypt"`, `"Destroy"`. Batch requests produce a `+`-joined name such as `"Create+Encrypt"`. |
| `user`        | `string`                                 | No       | Authenticated username. `"unauthenticated"` when no identity was presented (e.g. 401 paths).                                         |
| `object_uid`  | `string` or `null`                       | Yes      | KMIP `UniqueIdentifier` of the object involved. `null` when unavailable (e.g. failed auth, batch).                                   |
| `algorithm`   | `string` or `null`                       | Yes      | Cryptographic algorithm, e.g. `"AES"`, `"RSA"`. `null` when the operation carries no algorithm.                                      |
| `client_ip`   | `string` or `null`                       | Yes      | Source IP from `X-Forwarded-For` (if present) or the TCP peer address.                                                               |
| `result`      | `"Success"` or `{"Failure": "<reason>"}` | No       | Outcome of the operation.                                                                                                            |
| `duration_ms` | `integer`                                | No       | Wall-clock duration of the operation in milliseconds.                                                                                |
| `prev_hash`   | `string` (64 hex chars)                  | No       | SHA-256 of the previous row's canonical bytes. All-zeros for the first row (`id = 0`).                                               |
| `row_hash`    | `string` (64 hex chars)                  | No       | SHA-256 of this row's canonical bytes (including `prev_hash`).                                                                       |

**Example event**:

```json
{
  "id": 4,
  "timestamp": "2026-05-06T20:31:42.321328507Z",
  "operation": "Encrypt",
  "user": "admin",
  "object_uid": "417fe2de-827d-48d0-8d51-851bec315b76",
  "algorithm": "AES",
  "client_ip": "127.0.0.1",
  "result": "Success",
  "duration_ms": 1,
  "prev_hash": "e492c0f02860bc6c428259d44414651eda3aaaee2f48eb857144c940ac0fe909",
  "row_hash": "699a2837830af4a26fe79aeb48509fc707507e514da5850d953366a14e730c38"
}
```

---

## Hash chain

Every persisted event includes a SHA-256 hash chain that makes tampering detectable offline.

The hash is computed over a canonical byte sequence of the event's fields:
`id || timestamp || operation || user || object_uid || algorithm || client_ip || result || duration_ms || prev_hash`

`prev_hash` of the first event (`id = 0`) is the 32-byte all-zeros sentinel.

Any modification to a field in any row — including reordering rows, deleting rows, or appending
forged rows — breaks at least one `prev_hash → row_hash` link and is detected by `ckms audit verify`.

#### Durability

Each write is followed by [`fsync()`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fsync.html) to ensure data is physically written to disk. Events survive
an OS crash or power failure as long as the storage medium has confirmed the write.

On restart the server reads only the last 64 KiB of an existing log file to resume the chain. **If the last event's `row_hash` does not verify, the server refuses to start and reports the corrupted line.**

---

## Verify the chain offline

You can run the following command:

```bash
ckms audit verify --path /var/log/cosmian-kms/audit.jsonl
```

**Sample output: intact chain**:

```
Verified 42 events. Chain is intact.
```

**Sample output: tampered file**:

```
TAMPERED: event id=17 row_hash mismatch
```

**Exit codes**: `0` = intact, `1` = broken or tampered.

With `--verbose`, a summary line is printed for every event:

```
id=0  2026-05-06T20:31:15Z  Create   chain=ok
id=1  2026-05-06T20:31:15Z  Encrypt  chain=ok
...
```

---

## Best practices

- Use an **append-only** filesystem or object store (e.g. S3 with Object Lock) for the audit
  file.
- Restrict read access to the audit file to the KMS process user and auditors only; the file
  contains usernames and operation details.
- Retain audit files for the compliance window required by your framework
  (PCI-DSS Req. 10.7: 12 months; HIPAA §164.312(b): 6 years).
- If the server refuses to start because the last event's `row_hash` does not verify
  (corrupted write), move the file aside and restart — the server will create a fresh log.
  Keep the corrupted file for forensic review.
- For SIEM ingestion and CEF export, see [SIEMs](./siems.md).

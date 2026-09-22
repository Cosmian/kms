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

!!! warning "Not safe for multiple KMS instances sharing one file"
    The audit file backend is designed for **one writer per file**. If you run multiple KMS
    instances (horizontal scaling, Kubernetes replicas), each one needs its **own** audit file —
    never point several instances at the same path on a shared volume. Only one instance will ever hold the
    lock and write, so the others' events are effectively never recorded. For a centralized,
    multi-writer-safe audit trail across instances, use the [PostgreSQL backend](#postgresql-backend)
    instead.

---

## Configuration reference

| CLI flag                      | Environment variable            | Default                        | Description                                                                                                                                                                                                            |
| ----------------------------- | ------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--audit-enable`              | `KMS_AUDIT_ENABLE`              | `false`                        | Enable the audit pipeline. When `false` no file is created and no writer thread is spawned.                                                                                                                            |
| `--audit-file-path`           | `KMS_AUDIT_FILE_PATH`           | `<root-data-path>/audit.jsonl` | Absolute path to the JSONL audit log file. Parent directories are created automatically on first write.                                                                                                                |
| `--audit-file-max-size-bytes` | `KMS_AUDIT_FILE_MAX_SIZE_BYTES` | _(unlimited)_                  | Stops all further writes once the file reaches this many bytes. Omitted means unlimited. Must be > 0 when set. See [Audit file size cap](#audit-file-size-cap).                                                        |
| `--audit-channel-capacity`    | `KMS_AUDIT_CHANNEL_CAPACITY`    | `4096`                         | Capacity of the bounded in-memory channel between request threads and the writer task. Each event is ≈ 500 B (≈ 2 MiB total at default).                                                                               |
| `--audit-trusted-proxy-cidrs` | `KMS_AUDIT_TRUSTED_PROXY_CIDRS` | _(empty)_                      | Comma-separated CIDR blocks (e.g. `10.0.0.0/8,172.16.0.0/12`) of reverse proxies/load balancers allowed to set `client_ip` via `X-Forwarded-For`. See [Client IP and reverse proxies](#client-ip-and-reverse-proxies). |
| `--audit-failure-mode`        | `KMS_AUDIT_FAILURE_MODE`        | `continue`                     | What to do when an event cannot be queued. `continue` — log the error, keep serving. `reject` — return HTTP 503. See [Audit failure mode](#audit-failure-mode).                                                        |

> **Tip**: if you see `AuditFileStore: channel full` in the server log under sustained high load, raise
> `--audit-channel-capacity`. When the channel is full the event is dropped (non-blocking) and an
> `error!` line is emitted — the request itself is never blocked.

### Client IP and reverse proxies

By default (`--audit-trusted-proxy-cidrs` empty), `client_ip` in every audit event is always the
direct TCP peer address — the `X-Forwarded-For` header is ignored entirely.

If the KMS runs **directly reachable** by clients (no reverse proxy/load balancer in front), leave
this unset: the TCP peer address is always the real client.

If the KMS runs **behind a reverse proxy or load balancer**, the direct TCP peer is always the
proxy, not the real client. Set `--audit-trusted-proxy-cidrs` to the proxy's IP/CIDR so the audit
middleware knows it can trust `X-Forwarded-For` coming from that address — otherwise every audit
event will record the proxy's IP instead of the real client's.

**Never** trust `X-Forwarded-For` unconditionally: any direct caller can set that header to an
arbitrary value, corrupting the forensic trail (e.g. framing another IP, or hiding its own).
Restricting trust to known proxy CIDRs prevents this while still letting a legitimate reverse
proxy forward the real client IP.

---

### Audit failure mode

By default (`continue`) the KMS keeps serving even when an audit event cannot be queued — the
event is dropped, an `error!` is logged, and the request succeeds normally.

Set `--audit-failure-mode reject` to enforce strict auditability: if an event cannot be placed in
the writer channel (channel full or writer task dead), the KMS returns **HTTP 503** to the client
instead of the normal KMIP response. The KMIP operation has already executed at this point; the
503 signals that its outcome was not recorded.

!!! warning "`reject` mode can cause service disruption"
    When `failure_mode = reject`, a saturated audit channel or a dead writer task will
    make every subsequent KMIP request fail with 503 until the condition is resolved.
    Only use this mode when unlogged operations are strictly unacceptable (e.g.
    regulated environments requiring a complete audit trail).

---

### Audit file size cap

`--audit-file-max-size-bytes` (or `[audit.file] max_size_bytes` in TOML) stops the writer from
appending to the audit file once it reaches the configured size. This is a **write-stop cap, not
rotation or retention** — the writer never deletes, truncates, or rolls the file on its own.

```toml
[audit.file]
max_size_bytes = 1073741824 # 1 GiB
```

Behavior:

- Omitted (the default): unlimited, today's behavior.
- The event that pushes the file to or past the cap is still persisted — only events **after**
  that one are dropped (subject to `--audit-failure-mode`, exactly like a full channel or a dead
  writer).
- Once capped, the condition does **not** clear itself: an external process truncating or
  rotating the file does not resume writing. The KMS must be restarted after the log is safely
  remediated. KMS-aware rotation/reopen is a possible future improvement.
- A `0` value is rejected at startup as a configuration error.

---

## Event schema

Each line in the JSONL file is a complete JSON object with the following fields:

| Field         | Type                                     | Nullable | Description                                                                                                                                      |
| ------------- | ---------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`          | `integer`                                | No       | Monotonically increasing row counter, starting at 0.                                                                                             |
| `timestamp`   | `string` (RFC 3339 / UTC)                | No       | Wall-clock time of the KMIP operation.                                                                                                           |
| `operation`   | `string`                                 | No       | KMIP operation name, e.g. `"Create"`, `"Encrypt"`, `"Destroy"`. Batch requests produce a `+`-joined name such as `"Create+Encrypt"`.             |
| `user`        | `string`                                 | No       | Authenticated username. `"unauthenticated"` when no identity was presented (e.g. 401 paths).                                                     |
| `object_uid`  | `string` or `null`                       | Yes      | KMIP `UniqueIdentifier` of the object involved. `null` when unavailable (e.g. failed auth, batch).                                               |
| `algorithm`   | `string` or `null`                       | Yes      | Cryptographic algorithm, e.g. `"AES"`, `"RSA"`. `null` when the operation carries no algorithm.                                                  |
| `client_ip`   | `string` or `null`                       | Yes      | Source IP from `X-Forwarded-For` (if present) or the TCP peer address.                                                                           |
| `result`      | `"Success"` or `{"Failure": "<reason>"}` | No       | Outcome of the operation.                                                                                                                        |
| `duration_ms` | `integer`                                | No       | Wall-clock duration of the operation in milliseconds.                                                                                            |
| `request_id`  | `string` (UUID) or `null`                | Yes      | Correlation ID across operations from the same request. `null` for synthetic events.                                                             |
| `details`     | `string` or `null`                       | Yes      | Structured JSON payload attached to synthetic recovery events (`audit:torn-write-recovered`, `audit:reanchor`). `null` for ordinary KMIP events. |
| `prev_hash`   | `string` (64 hex chars)                  | No       | SHA-256 of the previous row's canonical bytes. All-zeros for the first row (`id = 0`).                                                           |
| `row_hash`    | `string` (64 hex chars)                  | No       | SHA-256 of this row's canonical bytes (including `prev_hash`).                                                                                   |

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
  "request_id": "c1f728c0-85f2-498c-8f47-9759d57a2745",
  "prev_hash": "e492c0f02860bc6c428259d44414651eda3aaaee2f48eb857144c940ac0fe909",
  "row_hash": "699a2837830af4a26fe79aeb48509fc707507e514da5850d953366a14e730c38"
}
```

---

## Hash chain

Every persisted event includes a SHA-256 hash chain that makes tampering detectable offline.

The hash is computed over a canonical byte sequence of the event's fields:
`id || timestamp || operation || user || object_uid || algorithm || client_ip || result || duration_ms || request_id || prev_hash`

`prev_hash` of the first event (`id = 0`) is the 32-byte all-zeros sentinel.

Any modification to a field in any row — including reordering rows, deleting rows, or appending
forged rows — breaks at least one `prev_hash → row_hash` link and is detected by `ckms audit verify`.

### Durability

Each write is followed by [`fsync()`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/fsync.html) to ensure data is physically written to disk. Events survive
an OS crash or power failure as long as the storage medium has confirmed the write.

On restart, the audit writer task always verifies the entire chain — every row's hash and its
link to the previous row — before it appends any queued event, then reads the last 64 KiB of the
file to decide how to resume. This runs in the background: **the KMS starts and serves traffic
immediately**, without waiting for verification to finish, and any events submitted in the
meantime are queued and written once recovery completes — see
[Startup recovery](#startup-recovery) below.

---

## Startup recovery

No condition found in the audit log — whether at the tail or anywhere in the middle of the
file — ever prevents the KMS from starting. Recovery is routed by cause:

| Condition                                                                                                   | What happens                                                                                                                                                                                                                                                                                                                               |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No file, or empty file                                                                                      | Fresh chain starts at `id = 0`.                                                                                                                                                                                                                                                                                                            |
| **Mid-chain tamper** — any row other than the last fails its own hash check or its link to the previous row | **Seal-and-roll** (below) — caught by the unconditional whole-chain scan that runs on every boot, not just a tail check.                                                                                                                                                                                                                   |
| Last row is valid but missing its trailing newline                                                          | Resumes in place; the missing newline is repaired before the next event is appended.                                                                                                                                                                                                                                                       |
| **Torn write** — an incomplete trailing row, but the row before it (or genesis) is valid                    | The incomplete fragment is truncated away; an `audit:torn-write-recovered` event is appended recording the bytes discarded. The chain continues in place — no data loss beyond the incomplete row, which was never durably committed.                                                                                                      |
| **Tampered last row**, or structural garbage with no trustworthy fallback row                               | **Seal-and-roll**: the corrupted file is renamed aside as `<name>.<UTC-timestamp>.<8-hex>.corrupt.<ext>` — kept as forensic evidence, never modified or deleted by the KMS. A fresh chain starts at the original path with an `audit:reanchor` event as row 0, recording the sealed file's name, size, and SHA-256 in its `details` field. |

A torn write is the common case after an ungraceful restart (OOM kill, pod eviction, power
loss) and is expected to happen periodically at fleet scale — it does not indicate tampering.

### Concurrent instances (rolling updates)

The KMS takes a best-effort, non-blocking exclusive lock (`<audit-file-path>.lock`) before
recovering or writing to the audit file, preventing two live instances — e.g. old and new pods
overlapping during a rolling update on a shared volume — from corrupting the same log. If the
lock is held by another instance, the KMS still starts and serves immediately; audit events are
buffered (up to `--audit-channel-capacity`) and flushed in order once the lock becomes available.

### Unwritable path (permissions, read-only mount, disk fault)

A path that cannot be opened for a reason unrelated to log content is treated as a deployment
fault, not corruption. The KMS starts and serves traffic; audit events are buffered in the
writer's channel (up to `--audit-channel-capacity`) while it retries opening the path — only once
that buffer fills does an event get dropped with an `error!` log line. Audit logging resumes
automatically once the fault is fixed, with no restart required.

---

## Verify the chain offline

You can run the following command:

```bash
ckms audit verify --path /var/log/cosmian-kms/audit.jsonl
```

`--path` also accepts a **directory**, verifying every non-sealed `*.jsonl` file in it as its
own independent chain. Sealed `*.corrupt.jsonl` evidence files from past recoveries are not
independent chains; they are checked through the SHA-256 recorded in their live log's reanchor:

```bash
ckms audit verify --path /var/log/cosmian-kms/
```

**Sample output: intact chain**:

```text
/var/log/cosmian-kms/audit.jsonl: chain OK: 42 events verified
```

**Sample output: tampered file**:

```text
TAMPERED: /var/log/cosmian-kms/audit.jsonl event id=17 (line 18) has an invalid row_hash
```

For every `audit:reanchor` event encountered, `verify` also confirms the sealed evidence file it
references still exists next to the log and its SHA-256 still matches the digest recorded in the
event — this is what makes deleting or altering sealed evidence after the fact detectable:

```text
MISSING EVIDENCE: /var/log/cosmian-kms/audit.jsonl: reanchor event id=0 references sealed file
audit.20260814T140233Z.9f3ac1b2.corrupt.jsonl which no longer exists
```

**Exit codes**: `0` = intact (and all sealed evidence present and unaltered), `1` = broken,
tampered, or missing/altered sealed evidence.

With `--verbose`, a summary line is printed for every event:

```text
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
  (PCI-DSS Req. 10.7: 12 months; HIPAA §164.312(b): 6 years). This includes sealed
  `*.corrupt.jsonl` files left behind by a seal-and-roll recovery — they are forensic evidence
  and are never deleted automatically; clean them up as part of your retention/rotation process.
- Monitor the recovery audit events and server logs when a torn-write or seal-and-roll recovery
  happens — the KMS no longer refuses to start on audit-log corruption, so these are the primary
  operator signals for noticing and triaging it.
- For SIEM ingestion and CEF export, see [SIEMs](./siems.md).

## PostgreSQL backend

Instead of a local JSONL file, the KMS can write the audit hash chain to a `PostgreSQL`
database — a centralized, multi-writer-safe alternative for horizontally-scaled deployments.
Backend selection is config-time only: setting `--audit-postgres-url` switches the writer to
`PostgreSQL` instead of the file; there is no runtime fallback between the two — a connectivity
failure at startup still aborts the server.

=== "Command line"

    ```bash
    cosmian_kms --audit-enable \
      --audit-postgres-url postgresql://kms_audit:password@db-host:5432/kms_audit \
      --audit-instance-id kms-prod-0
    ```

=== "Environment variables"

    ```bash
    export KMS_AUDIT_ENABLE=true
    export KMS_AUDIT_POSTGRES_URL=postgresql://kms_audit:password@db-host:5432/kms_audit
    export KMS_AUDIT_INSTANCE_ID=kms-prod-0
    cosmian_kms
    ```

| CLI flag               | Environment variable    | Description                                                                                                                                                                                                       |
| ----------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--audit-postgres-url` | `KMS_AUDIT_POSTGRES_URL` | Connection URL for the audit database. Must be a **different** database than `--database-url` when the object store is also `PostgreSQL` — the server refuses to start otherwise.                              |
| `--audit-instance-id`  | `KMS_AUDIT_INSTANCE_ID`  | Identifies this instance's chain. Required when `--audit-postgres-url` is set — no default. Must be stable across restarts and unique per instance sharing the database; a reused id is rejected at startup by an advisory-lock check. |

`--audit-postgres-url` supports the same `sslmode`/`sslrootcert`/`sslcert`/`sslkey` query
parameters as `--database-url` — see [PostgreSQL TLS / mTLS](./database/configuration.md#postgresql-tls-mtls).

If `--audit-file-path` is also set, it's never used as a fallback — `PostgreSQL` always takes
precedence, and a connectivity failure still aborts startup. The KMS only logs a warning in
this case, either confirming the file path is ignored (connection succeeded) or noting that it's
not used as a fallback (connection failed, startup aborts).

!!! warning "Schema is not release-stable yet"
    The `PostgreSQL` audit schema has no migration path between versions yet. If you are
    developing against it and upgrade the KMS across a schema change, drop and let the KMS
    recreate `kms_audit_events` rather than expecting an in-place upgrade:
    `psql "$KMS_AUDIT_POSTGRES_URL" -c 'DROP TABLE IF EXISTS kms_audit_events CASCADE'`.

### Chain generations and startup recovery

A stable `--audit-instance-id` owns a sequence of immutable **generations**
(`chain_generation`, starting at 0) in the shared `kms_audit_events` table, keyed by
`(instance_id, chain_generation, id)`. Exactly one generation accepts writes at a time; every
older generation is sealed and never modified again — the `PostgreSQL` analogue of the file
backend's renamed `*.corrupt.jsonl` evidence file, applying the same
[always-start recovery policy](../adr/2026-08-14-006-audit-log-always-start-recovery.md).

On startup only the **latest** generation is verified. A clean generation resumes normally. A
corrupted row is classified by cause, recorded in the reanchor `details` below:

| Reason          | Meaning                                                                   |
| ---------------- | ---------------------------------------------------------------------------- |
| `hash_mismatch` | A complete row whose own hash doesn't match its stored bytes.             |
| `broken_link`   | A row that verifies on its own but doesn't chain to its predecessor.      |
| `unparsable`   | A column doesn't decode as an audit event at all.                        |
| `id_overflow`   | A valid tail row at `id = i64::MAX` — continuing in place would overflow. |

The corrupted generation is preserved unchanged. A fresh generation starts with a row-0
`audit:reanchor` event whose `details` record:

```json
{
  "sealed_generation": 0,
  "new_generation": 1,
  "first_failure_id": 2,
  "reason": "hash_mismatch",
  "evidence": "v1:sha256:<64 hex chars>"
}
```

Only connectivity, TLS, schema, advisory-lock, or recovery-write failures still abort startup —
the same operational/content distinction the file backend draws between a torn write and a
tampered row. A seal-and-roll recovery is logged at `error!` level; monitor server logs for it
the same way you would for a file-backend seal-and-roll.

### Reproducing the evidence digest independently

The `evidence` digest is SHA-256 over a deterministic SQL projection of every row in the sealed
generation (one canonical line per row, in `id` order), plus a footer recording the generation
number and row count. It is reproducible without trusting the KMS's own hashing — run the same
projection through `psql` and pipe it to `sha256sum`:

```bash
QUERY="SELECT 'v1' || '|' || encode(convert_to(instance_id, 'UTF8'), 'hex') || '|' ||
  chain_generation || '|' || id || '|' ||
  to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') || '|' ||
  encode(convert_to(operation, 'UTF8'), 'hex') || '|' ||
  encode(convert_to(username, 'UTF8'), 'hex') || '|' ||
  COALESCE(encode(convert_to(object_uid, 'UTF8'), 'hex'), '-') || '|' ||
  COALESCE(encode(convert_to(algorithm, 'UTF8'), 'hex'), '-') || '|' ||
  COALESCE(encode(convert_to(client_ip, 'UTF8'), 'hex'), '-') || '|' ||
  encode(convert_to(result, 'UTF8'), 'hex') || '|' || duration_ms || '|' ||
  COALESCE(request_id::text, '-') || '|' ||
  COALESCE(encode(convert_to(details, 'UTF8'), 'hex'), '-') || '|' ||
  encode(prev_hash, 'hex') || '|' || encode(row_hash, 'hex')
  FROM kms_audit_events
  WHERE instance_id = '<instance_id>' AND chain_generation = <sealed_generation>
  ORDER BY id ASC"

{
  psql "$KMS_AUDIT_POSTGRES_URL" -qtA -c "$QUERY"
  printf 'v1|end|%s|%s\n' "<sealed_generation>" "<row_count>"
} | sha256sum
```

The resulting hex digest, prefixed with `v1:sha256:`, must match the `evidence` field recorded
in the corresponding `audit:reanchor` event.

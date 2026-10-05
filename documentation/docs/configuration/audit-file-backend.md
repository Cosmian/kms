# File backend

The file backend writes a tamper-evident JSONL audit trail to a local file. It is the default
backend and needs no external service.

Each KMS instance needs its own file. Never point two instances at the same path on a shared
volume: only one of them ever holds the write lock, so the other's events are never recorded.
For a single audit trail shared across a fleet of instances, use the
[PostgreSQL backend](./audit-postgresql-backend.md) instead.

Each write is flushed to disk before the KMS moves on to the next request, so events survive an
OS crash or a power failure.

---

## Configuration

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

| CLI flag                      | Environment variable            | Default                        | Description                                                                                              |
| ------------------------------- | --------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `--audit-file-path`           | `KMS_AUDIT_FILE_PATH`           | `<root-data-path>/audit.jsonl` | Absolute path to the JSONL audit log file. Parent directories are created automatically on first write. |
| `--audit-file-max-size-bytes` | `KMS_AUDIT_FILE_MAX_SIZE_BYTES` | _(unlimited)_                   | Stops all further writes once the file reaches this many bytes. Must be greater than 0 when set.        |

`--audit-file-max-size-bytes` is a write-stop cap, not rotation or retention: the KMS never
deletes, truncates, or rolls the file on its own. Once the file reaches the cap, the event that
would cross it is replaced by a final `audit:size-cap-reached` event, later events are dropped
subject to `--audit-failure-mode`, and the condition does not clear itself: remediate the log and
restart the KMS. A value of `0` is rejected at startup.

To rotate the file, stop the KMS, move the file aside, and start it again: a new chain begins at
`id = 0`. The KMS never rotates the file on its own while running.

---

## Startup and recovery

The KMS always starts and serves traffic immediately, whatever condition is found in the audit
file. Verifying the whole file, and repairing it if needed, happens in the background; any event
submitted in the meantime is queued and written once recovery completes. Recovery is routed by
cause:

| Condition                                            | What happens                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No file, or empty file                                | Fresh chain starts at `id = 0`.                                                                                                                                                                                                                                                                                                                                     |
| **Mid-chain tamper**                                  | Any row other than the last fails its own hash check or its link to the previous row. **Seal-and-roll** (below) — caught by the unconditional whole-chain scan that runs on every boot, not just a tail check.                                                                                                                                                     |
| Last row is valid but missing its trailing newline    | Resumes in place; the missing newline is repaired before the next event is appended.                                                                                                                                                                                                                                                                               |
| **Torn write**                                        | An incomplete trailing row, but the row before it (or genesis) is valid. The incomplete fragment is truncated away; an `audit:torn-write-recovered` event is appended recording the bytes discarded. The chain continues in place: no data loss beyond the incomplete row, which was never durably committed.                                                     |
| **Tampered last row**                                 | Or structural garbage with no trustworthy fallback row. **Seal-and-roll**: the corrupted file is renamed aside as `<name>.<UTC-timestamp>.<8-hex>.corrupt.<ext>`, kept as forensic evidence and never modified or deleted by the KMS. A fresh chain starts at the original path with an `audit:reanchor` event as row 0, recording the sealed file's name, size, and SHA-256 in its `details` field. |

A torn write is the common case after an ungraceful restart (OOM kill, pod eviction, power loss)
and is expected to happen periodically at fleet scale; it does not indicate tampering. See
[Audit events](./audit-events.md#system-events) for the exact fields each recovery event carries.

If another instance already holds the file's lock, the KMS still starts and serves traffic
immediately; events are buffered (up to `--audit-channel-capacity`) and flushed in order once the
lock becomes available.

If the path cannot be opened for a reason unrelated to file content (permissions, a read-only
mount, a disk fault), the KMS treats it as a deployment fault, not corruption: it buffers events
in the writer's channel while retrying, and resumes automatically once the fault is fixed, with
no restart required.

---

## Verifying a file or a directory

```bash
ckms audit verify --path /var/log/cosmian-kms/audit.jsonl
```

`--path` also accepts a directory, verifying every non-sealed `*.jsonl` file in it as its own
independent chain. Sealed `*.corrupt.jsonl` evidence files from past recoveries are not
independent chains; they are checked through the SHA-256 recorded in their live log's reanchor:

```bash
ckms audit verify --path /var/log/cosmian-kms/
```

Chain intact:

```text
/var/log/cosmian-kms/audit.jsonl: chain OK: 42 events verified
```

Tampered file:

```text
TAMPERED: /var/log/cosmian-kms/audit.jsonl event id=17 (line 18) has an invalid row_hash
```

For every `audit:reanchor` event, `verify` also confirms the sealed evidence file it references
still exists and its SHA-256 still matches the digest recorded in the event. This is what makes
deleting or altering sealed evidence after the fact detectable:

```text
MISSING EVIDENCE: /var/log/cosmian-kms/audit.jsonl: reanchor event id=0 references sealed file
audit.20260814T140233Z.9f3ac1b2.corrupt.jsonl which no longer exists
```

Exit codes: `0` when the chain (and all sealed evidence) is intact, `1` when a broken link,
tampered event, or altered/missing sealed evidence is detected.

With `--verbose`, a summary line is printed for every event:

```text
id=0  2026-05-06T20:31:15Z  Create   chain=ok
id=1  2026-05-06T20:31:15Z  Encrypt  chain=ok
...
```

See [ckms audit](../kms_clients/audit.md) for the full CLI reference.

---

## Protecting the file

- Use an append-only filesystem or object store (e.g. S3 with Object Lock) for the audit file.
- Restrict read access to the KMS process user, authorized auditors, and the collection agent's
  dedicated service account; the file contains usernames and operation details.
- Give the collection account read-only file access and traversal permission on parent directories.
  Preserve these grants when active files are recreated or rotated.
  Keep write access with the KMS process user; do not run the collector under that account.
- Retain audit files for the compliance window required by your frameworkThis includes sealed 
`*.corrupt.jsonl` files left behind by a seal-and-roll recovery: they are forensic evidence, 
never deleted automatically, and need
  cleaning up as part of your retention process.
- Monitor for the recovery events in [Audit events](./audit-events.md#system-events) and the
  matching server log lines in the [log reference](./log-reference.md): they are the primary
  signal that a torn-write or seal-and-roll recovery happened.

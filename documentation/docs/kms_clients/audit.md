# ckms audit

Manage the KMS audit log offline, reading either a local JSONL file or a `PostgreSQL` audit
database directly — no running KMS server is required.
The subcommands are suitable for scripts, cron jobs, and SIEM export pipelines.

## Usage

`ckms audit <subcommand>`

## Subcommands

**`export`** Export events from the audit log in JSON or CEF format.

**`verify`** Verify the SHA-256 hash chain of the audit log.

---

## ckms audit export

Export events from the audit log to stdout. Supports JSON (default) and CEF output.

### Usage

`ckms audit export --path <FILE> [options]`

### Arguments

`--path [-p] <FILE>` Path to the JSONL audit log file.
Can also be set via `KMS_AUDIT_FILE_PATH`. Mutually exclusive with `--postgres-url`; exactly
one of the two is required.

`--postgres-url <URL>` `PostgreSQL` URL of the audit database, as an alternative to `--path`.
Can also be set via `KMS_AUDIT_POSTGRES_URL`. Use a read-only role — these commands only ever
`SELECT`.

`--instance-id <ID>` Restrict to one instance's chain. Only meaningful with `--postgres-url`;
when omitted, every chain (`instance_id`) in the database is processed in turn and reported
separately, since each is an independently verifiable chain.

`--since <RFC3339>` Export only events whose `timestamp` is greater than or equal to this value.
The value must be an RFC 3339 timestamp, e.g. `2026-05-01T00:00:00Z`.

`--format <FORMAT>` Output format. One of `json` (default) or `cef`.

`--kms-version <STRING>` KMS version string to embed in the CEF device version header.
If omitted the field is left blank. Useful when merging exports from multiple nodes.

### Output formats

**`json`** — Emits one JSON object per line on stdout (JSONL). Same schema as the log file.

**`cef`** — Emits one CEF line per event on stdout (`CEF:0` header, Common Event Format spec 0.1):

```text
CEF:0|Cosmian|KMS|<version>|<operation>|<operation>|<severity>|rt=<epoch_ms> suser=<user> ...
```

### CEF field mapping

The CEF header fields (`Device Vendor`, `Device Product`, `Device Version`, `Signature ID`, `Name`, `Severity`)
are set automatically. Extension fields carry the structured event data:

| CEF extension key | Label        | Value                                                              |
| ----------------- | ------------ | ------------------------------------------------------------------ |
| `rt`              | —            | Event time as Unix epoch milliseconds.                             |
| `suser`           | —            | Authenticated username.                                            |
| `src`             | —            | Client IP. **Omitted** when the IP is not available.               |
| `outcome`         | —            | `"Success"` or `"Failure"`.                                        |
| `reason`          | —            | Failure reason string. **Omitted** on success.                     |
| `act`             | —            | KMIP operation name (e.g. `"Encrypt"`, `"Create+Destroy"`).        |
| `cn1`             | `durationMs` | Wall-clock operation duration in milliseconds.                     |
| `cs1`             | `objectUID`  | KMIP `UniqueIdentifier`. **Omitted** when `null`.                  |
| `cs2`             | `algorithm`  | Cryptographic algorithm. **Omitted** when `null`.                  |
| `externalId`      | —            | Monotonically increasing event ID (integer, from `event.id`).      |
| `devicePayloadId` | —            | Request correlation UUID. **Omitted** when no request ID is set.   |

> **CEF severity** is derived from the result: `5` (Medium) for `Success`; `7` (High) for
> authorization failures (401 / 403); `6` (Medium-High) for all other failures.

### Examples

Export all events as JSONL:

```bash
ckms audit export --path /var/log/cosmian-kms/audit.jsonl > events.jsonl
```

Export events since a given date as CEF, piped to a SIEM:

```bash
ckms audit export \
  --path /var/log/cosmian-kms/audit.jsonl \
  --format cef \
  --since "2026-05-01T00:00:00Z" \
  | nc -u splunk-host 514
```

---

## ckms audit verify

Verify the SHA-256 hash chain of a JSONL audit log file.

Checks that:

1. Each event's `row_hash` matches a freshly computed hash of its fields.
2. Each event's `prev_hash` matches the `row_hash` of the previous event (or is all-zeros for the first event).

Exits with code **0** when the chain is intact, or **1** when a broken link is detected.

### Usage

`ckms audit verify --path <FILE> [options]`

#### Arguments

`--path [-p] <FILE>` Path to the JSONL audit log file.
Can also be set via `KMS_AUDIT_FILE_PATH`. Mutually exclusive with `--postgres-url`; exactly
one of the two is required.

`--postgres-url <URL>` `PostgreSQL` URL of the audit database, as an alternative to `--path`.
Can also be set via `KMS_AUDIT_POSTGRES_URL`.

`--instance-id <ID>` Restrict to one instance's chain. Only meaningful with `--postgres-url`;
when omitted, every chain in the database is verified in turn and reported separately.

`--verbose` Print a summary line for every event even when the chain is valid.
_Default: false._

#### Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| `0`  | All events verified — chain is intact.  |
| `1`  | A tampered or broken link was detected. |

#### Output examples

Chain intact:

```text
Verified 42 events. Chain is intact.
```

Tampered file:

```text
TAMPERED: event id=17 row_hash mismatch
```

Verbose mode:

```text
id=0  2026-05-06T20:31:15Z  Create   chain=ok
id=1  2026-05-06T20:31:15Z  Encrypt  chain=ok
...
```

### Examples

Verify a log file and fail CI if the chain is broken:

```bash
ckms audit verify --path /var/log/cosmian-kms/audit.jsonl
```

Verbose verification for debugging:

```bash
ckms audit verify --path audit.jsonl --verbose
```

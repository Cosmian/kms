# ckms audit

Manage the KMS audit log file offline.

All `ckms audit` commands work **directly on a JSONL file** — no running KMS server is required.
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
_Required._ Can also be set via `KMS_AUDIT_FILE_PATH`.

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

Verify the SHA-256 hash chain of a JSONL audit log file, or every JSONL file in a directory.

Checks that:

1. Each event's `row_hash` matches a freshly computed hash of its fields.
2. Each event's `prev_hash` matches the `row_hash` of the previous event (or is all-zeros for the first event).
3. Every `audit:reanchor` event's sealed evidence file still exists next to the log and its
   SHA-256 still matches the digest recorded in the event — this is what makes deleting or
   altering sealed evidence after the fact detectable.

Exits with code **0** when every chain is intact, or **1** when a broken link, tampered event, or
altered/missing sealed-evidence file is detected.

### Usage

`ckms audit verify --path <FILE|DIRECTORY> [options]`

#### Arguments

`--path [-p] <FILE|DIRECTORY>` Path to a JSONL audit log file, or a directory containing one or
more. A directory is scanned for every non-sealed `*.jsonl` file, each verified as its own
**independent** chain. Sealed `*.corrupt.jsonl` evidence files are intentionally not verified
as chains — their corruption is why they were sealed — but are SHA-256 checked through the live
log's `audit:reanchor` record. _Required._ Can also be set via `KMS_AUDIT_FILE_PATH`.

`--verbose` Print a summary line for every event even when the chain is valid.
_Default: false._

#### Exit codes

| Code | Meaning                                                                        |
| ---- | ------------------------------------------------------------------------------- |
| `0`  | All events (and, for reanchor events, all sealed evidence) verified — intact.   |
| `1`  | A tampered/broken link, or missing/altered sealed evidence, was detected.       |

#### Output examples

Chain intact:

```text
/var/log/cosmian-kms/audit.jsonl: chain OK: 42 events verified
```

Tampered file:

```text
TAMPERED: /var/log/cosmian-kms/audit.jsonl event id=17 (line 18) has an invalid row_hash
```

Missing sealed evidence (a `seal-and-roll` recovery's corrupted file was deleted or moved):

```text
MISSING EVIDENCE: /var/log/cosmian-kms/audit.jsonl: reanchor event id=0 references sealed file
audit.20260814T140233Z.9f3ac1b2.corrupt.jsonl which no longer exists
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

Verify every live JSONL chain in a directory; sealed evidence is checked through its reanchor:

```bash
ckms audit verify --path /var/log/cosmian-kms/
```

Verbose verification for debugging:

```bash
ckms audit verify --path audit.jsonl --verbose
```

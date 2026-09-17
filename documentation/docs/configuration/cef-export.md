# CEF export format

The KMS can export audit events in the **Common Event Format (CEF)** — a text-based,
vendor-neutral log format widely ingested by SIEM products (ArcSight, Splunk, IBM QRadar,
Microsoft Sentinel, and others) without a custom parser.

CEF export is a **serialisation view** of the tamper-evident JSONL audit log (see
[Audit logs](./audit-logs.md)). It does not replace the JSONL file, which remains the
authoritative, hash-chain-verifiable record.

---

## Specification

The KMS produces **CEF version 0** (`CEF:0`) as defined by the
[ArcSight CEF Implementation Standard, version 27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf)
(OpenText/ArcSight, April 2024).

> **Reference links**
>
> - [CEF Implementation Standard v27 (PDF)](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf)
> - [jc CEF parser (kellyjonbrazil/jc)](https://github.com/kellyjonbrazil/jc) — independent,
>   third-party CEF parser used for interoperability validation

---

## Format overview

Each audit event is serialised as a single line:

```text
CEF:0|Cosmian|KMS|<version>|<operation>|<operation>|<severity>|<extensions>
```

### Header fields

| Position | CEF field name       | Value                                   | Max length |
| -------- | -------------------- | --------------------------------------- | ---------- |
| 1        | CEF Version          | Always `0`                              | —          |
| 2        | `deviceVendor`       | `Cosmian`                               | 63         |
| 3        | `deviceProduct`      | `KMS`                                   | 63         |
| 4        | `deviceVersion`      | KMS version string (e.g. `5.25.0`)      | 31         |
| 5        | `deviceEventClassId` | KMIP operation name (e.g. `Encrypt`)    | 1023       |
| 6        | `name`               | Same as `deviceEventClassId`            | 512        |
| 7        | `agentSeverity`      | Integer 0–10 (see severity table below) | —          |

### Extension fields

All extension keys below are **standard CEF v27 dictionary keys** — no custom labels are used.

| CEF key           | CEF v27 full name       | Type       | Description                                        |
| ----------------- | ----------------------- | ---------- | -------------------------------------------------- |
| `rt`              | `deviceReceiptTime`     | DateTime   | Event time as Unix epoch milliseconds.             |
| `suser`           | `sourceUserName`        | String     | Authenticated username.                            |
| `src`             | `sourceAddress`         | IP address | Client IP. **Omitted** when not available.         |
| `outcome`         | `eventOutcome`          | String     | `"Success"` or `"Failure"`.                        |
| `reason`          | `reason`                | String     | Failure reason. **Omitted** on success.            |
| `act`             | `deviceAction`          | String     | KMIP operation name.                               |
| `cn1`             | `deviceCustomNumber1`   | Long       | Wall-clock operation duration in milliseconds.     |
| `cn1Label`        | `deviceCustomNumber1Label` | String  | Always `"durationMs"`.                             |
| `cs1`             | `deviceCustomString1`   | String     | KMIP `UniqueIdentifier`. **Omitted** when `null`.  |
| `cs1Label`        | `deviceCustomString1Label` | String  | Always `"objectUID"`.                              |
| `cs2`             | `deviceCustomString2`   | String     | Cryptographic algorithm. **Omitted** when `null`.  |
| `cs2Label`        | `deviceCustomString2Label` | String  | Always `"algorithm"`.                              |
| `externalId`      | `externalId`            | String     | Audit record ID (monotonically increasing integer).|
| `devicePayloadId` | `devicePayloadId`       | String     | Request correlation UUID. **Omitted** when absent. |

---

## Severity mapping

| Outcome                              | CEF severity | Meaning      |
| ------------------------------------ | ------------ | ------------ |
| Success                              | `5`          | Medium       |
| Authentication failure (401 / 403)   | `7`          | High         |
| Other failure                        | `6`          | Medium-High  |

CEF severity follows the ArcSight scale: 0–3 = Low, 4–6 = Medium, 7–8 = High, 9–10 = Very-High.

---

## Escaping rules

CEF uses special characters as delimiters. The serialiser escapes them to prevent injection:

**Header fields** (pipe-delimited):

| Character | Escaped as |
| --------- | ---------- |
| `\`       | `\\`       |
| `\|`      | `\|`       |
| newline   | `\n`       |
| carriage return | `\r` |

**Extension values** (key=value pairs):

| Character | Escaped as |
| --------- | ---------- |
| `\`       | `\\`       |
| `=`       | `\=`       |
| newline   | `\n`       |
| carriage return | `\r`       |

> Pipe characters (`|`) in extension values do **not** need escaping — they only delimit
> the header.

---

## Example

Annotated CEF line for a successful `Encrypt` operation:

```text
CEF:0|Cosmian|KMS|5.25.0|Encrypt|Encrypt|5|rt=1784574156704 suser=admin src=127.0.0.1 outcome=Success act=Encrypt cn1=12 cn1Label=durationMs cs1=359019d8-1543-4e2e-9d96-674dd64fcffc cs1Label=objectUID cs2=AES cs2Label=algorithm externalId=1 devicePayloadId=3618ade8-5db7-4635-9d05-5af6a7614d52
```

| Field             | Value                                          |
| ----------------- | ---------------------------------------------- |
| `deviceVendor`    | `Cosmian`                                      |
| `deviceProduct`   | `KMS`                                          |
| `deviceVersion`   | `5.25.0`                                       |
| `deviceEventClassId` | `Encrypt`                                   |
| `name`            | `Encrypt`                                      |
| `agentSeverity`   | `5` (Medium — success)                         |
| `rt`              | `1784574156704` (epoch ms)                     |
| `suser`           | `admin`                                        |
| `src`             | `127.0.0.1`                                    |
| `outcome`         | `Success`                                      |
| `act`             | `Encrypt`                                      |
| `cn1`             | `12` (ms)                                      |
| `cs1`             | `359019d8-1543-4e2e-9d96-674dd64fcffc`         |
| `cs2`             | `AES`                                          |
| `externalId`      | `1`                                            |
| `devicePayloadId` | `3618ade8-5db7-4635-9d05-5af6a7614d52`         |

---

## CLI usage

Export audit events as CEF using the `ckms` CLI (works offline, no running server needed):

```bash
# Export all events as CEF
ckms audit export --path /var/log/cosmian-kms/audit.jsonl --format cef

# Export with a specific KMS version in the header
ckms audit export --path /var/log/cosmian-kms/audit.jsonl \
  --format cef --kms-version 5.25.0

# Export events since a given date
ckms audit export --path /var/log/cosmian-kms/audit.jsonl \
  --format cef --since 2026-01-01T00:00:00Z
```

For the full CLI reference, see [Audit log management](../kms_clients/audit.md).

---

## Interoperability validation

The KMS CEF output is validated against [jc](https://github.com/kellyjonbrazil/jc)
(kellyjonbrazil/jc, 8.7k+ GitHub stars, MIT licence) — an independent, widely used,
actively maintained CEF parser.

The interop test (`mise test:cef`) verifies:

1. **Structural parse** — jc can parse every CEF line and extracts exactly one record
2. **Field round-trip** — every field value matches the original JSONL source event
3. **CEF v27 compliance** — header field lengths within spec limits, severity in 0–10
   range, all extension keys exist in the CEF v27 dictionary
4. **Type validation** — `rt` is a valid epoch-ms integer, `cn1` is numeric, `src` is
   a valid IP address
5. **Escaping round-trip** — jc correctly unescapes values with special characters
   (`=`, `|`, `\`, newlines) back to the originals
6. **Injection hardening** — no raw newlines in CEF output; malicious input cannot
   inject forged CEF records

# CEF export

The KMS can export audit events in the **Common Event Format (CEF)** — a text-based,
vendor-neutral log format widely ingested by SIEM products (ArcSight, Splunk, IBM QRadar,
Microsoft Sentinel, and others) without a custom parser.

CEF export is a **serialisation view** of the tamper-evident audit trail (see [Audit logs](./audit-logs.md)).
The configured backend, either a JSONL file or a PostgreSQL audit database, remains the authoritative,
hash-chain-verifiable record.
CEF omits the hash-chain fields and cannot replace that record.

The KMS produces **CEF version 0** (`CEF:0`) as defined by the
[ArcSight CEF Implementation Standard, version 27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf)
(OpenText/ArcSight, April 2024).

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

All extension keys below are **standard CEF v27 dictionary keys**.

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
| `cn2`             | `deviceCustomNumber2`   | Long       | PostgreSQL chain generation. Omitted for file exports. |
| `cn2Label`        | `deviceCustomNumber2Label` | String  | `"chainGeneration"` for PostgreSQL exports only. |
| `cs1`             | `deviceCustomString1`   | String     | KMIP `UniqueIdentifier`. **Omitted** when `null`.  |
| `cs1Label`        | `deviceCustomString1Label` | String  | Always `"objectUID"`.                              |
| `cs2`             | `deviceCustomString2`   | String     | Cryptographic algorithm. **Omitted** when `null`.  |
| `cs2Label`        | `deviceCustomString2Label` | String  | Always `"algorithm"`.                              |
| `externalId`      | `externalId`            | String     | File: event ID. PostgreSQL: `<generation>:<id>`. |
| `deviceExternalId` | `deviceExternalId`      | String     | PostgreSQL instance ID. Omitted for file exports. |
| `devicePayloadId` | `devicePayloadId`       | String     | Request correlation UUID. **Omitted** when absent. |

For PostgreSQL exports, use the pair `deviceExternalId` and `externalId` as the event identity.
Event IDs restart in each chain generation and are not unique across instances.
For file exports, supply the KMS instance identity through the collection agent's source tag.

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

### File backend

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

### PostgreSQL backend

Set `AUDIT_READ_URL` to your audit database's connection URL using a
[read-only collection role](./siems.md#access-restriction).

Export one KMS instance's events as CEF:

```bash
ckms audit export \
  --audit-postgres-url "${AUDIT_READ_URL}" \
  --audit-instance-id kms-eu-west-1a \
  --format cef > kms-eu-west-1a.cef
```

Export every instance's events, retaining the source fields described above:

```bash
ckms audit export --audit-postgres-url "${AUDIT_READ_URL}" --format cef > fleet.cef
```

For the full CLI reference, see [Audit log management](../kms_clients/audit.md).

---

## Interoperability validation

The KMS CEF output is validated against [jc](https://github.com/kellyjonbrazil/jc)
(kellyjonbrazil/jc, MIT licence), an independent CEF parser.

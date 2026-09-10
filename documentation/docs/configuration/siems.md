# SIEM integration

The Eviden KMS produces audit events that can be ingested by any SIEM (Security Information
and Event Management) system. This page describes the available integration models and
provides configuration examples for common SIEM products.

For details on the CEF format itself — field mapping, severity rules, escaping, and
specification reference — see [CEF export format](./cef-export.md).

---

## Integration models

The KMS supports two integration models today, with a third planned:

| Model | How it works | Format | Continuous? |
| ----- | ------------ | ------ | ----------- |
| **File tailing** | SIEM agent tails the JSONL audit file directly | JSON | Yes |
| **CEF export** | `ckms audit export` converts JSONL → CEF on stdout | CEF v27 | Manual / scripted |
| **Native push** *(planned)* | Server-side pipeline pushes events to SIEM endpoints | CEF / OTEL / HEC | Yes |

> The JSONL file is the **authoritative audit store** (see [Audit logs](./audit-logs.md)).
> CEF is a serialisation *view* — it does not replace the JSONL file and does not include
> hash-chain fields (`prev_hash`, `row_hash`).

---

## File tailing (recommended for continuous ingestion)

The simplest and most reliable integration: a SIEM agent monitors the JSONL audit file
and forwards events as they are written. No format conversion is needed, and delivery
state is tracked by the agent.

### Splunk

Add to `inputs.conf` on the indexer or a Universal Forwarder:

```ini
[monitor:///var/log/cosmian-kms/audit.jsonl]
disabled = false
sourcetype = _json
index = kms_audit
```

Splunk's built-in `_json` sourcetype parses one JSON object per line as a searchable event.
Before enabling the monitor, validate field extraction against representative audit events
and ensure the `kms_audit` index exists with appropriate retention and access controls.

### Datadog

Datadog's Agent can tail the JSONL file and parse each line as a JSON log event. Add to
`datadog.yaml` or a dedicated integration config:

```yaml
logs:
  - type: file
    path: /var/log/cosmian-kms/audit.jsonl
    service: cosmian-kms
    source: json
```

Datadog automatically extracts top-level JSON fields as log attributes. You can then create
facets on `operation`, `user`, `result`, and build dashboards or monitors around KMS audit
activity.

### Elasticsearch / OpenSearch

Ship the JSONL file via Filebeat's `filestream` input with the `ndjson` parser:

```yaml
filebeat.inputs:
  - type: filestream
    id: cosmian-kms-audit
    paths:
      - /var/log/cosmian-kms/audit.jsonl
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true
```

### JSONL field reference for SIEM mapping

All SIEM integrations above ingest the same JSONL schema. Use this table to configure
field extraction, facets, or dashboards:

| Field | Type | Nullable | SIEM mapping suggestion |
|-------|------|----------|------------------------|
| `id` | integer | No | Event sequence number |
| `timestamp` | string (RFC 3339) | No | Event time |
| `operation` | string | No | Action / event type (e.g. `Encrypt`, `Create`, `Destroy`) |
| `user` | string | No | Source user identity |
| `object_uid` | string | Yes | Target object identifier (KMIP `UniqueIdentifier`) |
| `algorithm` | string | Yes | Cryptographic algorithm (e.g. `AES`, `RSA`) |
| `client_ip` | string | Yes | Source IP address |
| `result` | `"Success"` or `{"Failure": "..."}` | No | Outcome — split into `outcome` + `reason` fields |
| `duration_ms` | integer | No | Operation latency |
| `request_id` | string (UUID) | Yes | Correlation ID across batch operations |
| `prev_hash` | string (64 hex) | No | Hash-chain link (integrity only — ignore in SIEM) |
| `row_hash` | string (64 hex) | No | Row integrity hash (integrity only — ignore in SIEM) |

> **Note**: `prev_hash` and `row_hash` are tamper-evidence fields for offline chain
> verification (see [Audit logs](./audit-logs.md)). They carry no semantic meaning for
> SIEM correlation and can be excluded from indexing to save storage.

### Generic file tailing (rsyslog, Filebeat, Fluent Bit)

Any log shipping agent that supports file tailing can forward the JSONL file. Configure
the agent to:

1. Monitor the audit file path (default: `/var/log/cosmian-kms/audit.jsonl`)
2. Track file position (cursor) to avoid duplicate delivery
3. Use a sourcetype or tag that your SIEM recognises as JSON

---

## CEF export (for SIEMs requiring CEF format)

The `ckms audit export --format cef` command converts the JSONL audit store into
[CEF v27](./cef-export.md) and prints it to stdout. This is useful for:

- **Verification** — sending a sample of events to a CEF listener to confirm parsing
- **Scripted pipelines** — wrapping the export in a cron job or log rotation hook
- **SIEMs that require CEF** — ArcSight, QRadar, and others that expect CEF input

### Ad hoc export to a CEF listener

```bash
# Send today's events as CEF to a test listener on port 5514
ckms audit export --format cef \
  --path /var/log/cosmian-kms/audit.jsonl \
  --since "$(date -u +%Y-%m-%dT00:00:00Z)" \
  | nc -u -w 1 <host> 5514
```

!!! warning "Testing only — expect loss"

    - **UDP has no delivery guarantee**: events can be silently dropped or reordered.
    - **Use a port ≥ 1024** (e.g. `5514`): port 514 is privileged on Linux and usually
      occupied by the system syslog daemon.
    - **No cursor state**: each run re-exports from the beginning of the file (or from
      `--since`). This is fine for verification and unsuitable for continuous delivery.

### ArcSight / CEF-native SIEMs

ArcSight SmartConnectors natively ingest CEF over syslog. Configure the connector to
accept CEF on a TCP or UDP port, then forward the KMS CEF export output to that port.

Refer to the [ArcSight CEF Implementation Standard v27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf)
for connector-specific configuration details.

---

## Interoperability testing

The KMS CEF output is continuously validated against [jc](https://github.com/kellyjonbrazil/jc)
(kellyjonbrazil/jc) — an independent CEF parser with 8.7k+ GitHub stars — to ensure
third-party SIEMs can correctly ingest our events.

Run the interop test locally:

```bash
mise run test:cef
```

This validates:

- Every CEF line parses as exactly one record (no injection)
- All field values round-trip back to the source JSONL event
- Header field lengths comply with CEF v27 limits
- All extension keys exist in the CEF v27 standard dictionary
- Severity values are within the valid 0–10 range
- Escaping is correctly handled (special characters in values)

---

## Access restriction

!!! warning "Restrict access to the audit file"

    The audit file contains actor identities, client IP addresses, object identifiers, and
    operation metadata. Restrict file ownership to the KMS process user and grant read access
    only to the collection agent. Do not expose the file over untrusted networks without
    encryption.

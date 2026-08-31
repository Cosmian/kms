---
title: "ADR-2026-07-09-cef-siem-export-format: CEF v27 as SIEM Export Format for Audit Events"
status: "Accepted"
date: "2026-07-09"
authors: "contributors, security operations engineers, compliance engineers"
tags: ["architecture", "decision", "audit", "siem", "cef", "interoperability"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-07-09-cef-siem-export-format: CEF v27 as SIEM Export Format for Audit Events

## Status

Accepted

## Context

The tamper-evident JSONL audit log (ADR-2026-07-09-audit-log-single-writer-design) stores events in a KMS-specific JSON schema
optimised for hash-chain verification. Compliance environments additionally require feeding
audit events into centralised SIEM systems such as ArcSight, Splunk, IBM QRadar, or
Microsoft Sentinel for:

- Real-time alerting on suspicious patterns (e.g. mass `Destroy` operations)
- Cross-system correlation (KMS events alongside firewall, IdP, and application logs)
- Long-term retention and search under SIEM licencing

SIEM connectors are diverse and often expect a vendor-neutral wire format rather than
a proprietary JSON schema. The KMS must choose a serialisation format that:

1. Is widely supported by existing SIEM connectors with no custom parser.
2. Carries the fields needed for compliance (user, timestamp, operation, outcome, IP).
3. Is space-efficient enough for high-volume forwarding.
4. Remains a *view* of the audit record — it must not replace the authoritative JSONL log.

## Decision

Implement `to_cef_line()` on `AuditEvent` producing a **CEF v27** (ArcSight Common Event
Format, revision 27) line string.

```text
CEF:0|Cosmian|KMS|<version>|<operation>|<operation>|<severity>|<extensions>
```

Severity mapping:

| Outcome | CEF severity | Rationale |
|---|---|---|
| `Success` | 5 (Medium) | Normal operation |
| Auth failure (401/403) | 7 (High) | Potential intrusion |
| Other failure | 6 (Medium-High) | Operational issue |

Extension fields (all keys from the CEF v27 standard dictionary):
`rt` (epoch ms), `suser` (user), `src` (client IP), `outcome`, `reason` (failure message),
`act` (operation), `cn1` (duration ms), `cs1` (object UID), `cs2` (algorithm),
`externalId` (audit record ID), `devicePayloadId` (request correlation UUID).

CEF is implemented as a **pure serialisation method** (`fn to_cef_line(&self) -> String`)
on `AuditEvent`. It is not a transport; callers are responsible for forwarding the string
to a syslog socket, a file, or a network destination. This keeps the KMS codebase free of
SIEM-specific network transport dependencies.

## Consequences

### Positive

- **POS-001**: CEF is natively ingested by ArcSight, Splunk (via CIM auto-detection),
  IBM QRadar (DSM), Microsoft Sentinel, and most major SIEMs without a custom parser.
- **POS-002**: The format is self-describing (vendor, product, version embedded) — no
  schema negotiation needed.
- **POS-003**: Single-line format is trivially forwarded via `syslog`, `filebeat`,
  `fluentd`, or direct UDP/TCP without framing issues.
- **POS-004**: Pure serialisation: zero network dependencies added to the codebase;
  no async runtime required; no TLS certificate management for the SIEM transport.
- **POS-005**: `object_uid`, `algorithm`, and `client_ip` map to CEF standard
  extension keys (`cs1`, `cs2`, `src`). Audit ID and request ID use standard keys
  `externalId` and `devicePayloadId` — no custom labels.

### Negative

- **NEG-001**: CEF is a flat key=value line; the hash-chain fields (`prev_hash`,
  `row_hash`) are not included. CEF output alone is not verifiable — the JSONL file
  remains the authoritative audit record.
- **NEG-002**: CEF escaping rules (backslash, pipe) require careful handling; a bug in
  the serialiser could produce malformed lines silently accepted by some SIEMs but
  rejected by others.
- **NEG-003**: The transport layer is delegated to the operator (syslog daemon, file
  tail agent). There is no built-in forwarding; operators must configure their own
  pipeline.
- **NEG-004**: CEF `cs` (custom string) fields have no semantic standard — `cs1` for
  object UID and `cs2` for algorithm are KMS-specific conventions that must be documented
  for SIEM operators. The `csNLabel` fields describe the purpose of each custom field.

## Alternatives Considered

### Syslog (RFC 5424) structured data

- **ALT-001 Description**: Emit RFC 5424 messages with a structured-data element (SD-ID
  `cosmian_kms@<PEN>`) carrying audit fields. Natively supported by syslogd, rsyslog,
  syslog-ng.
- **ALT-002 Rejection Reason**: RFC 5424 structured data requires a registered Private
  Enterprise Number (PEN) for the SD-ID to be unambiguous in external environments.
  SIEM ingestion of RFC 5424 structured data is less uniform than CEF — many SIEMs treat
  the SD-ID as opaque. CEF has broader out-of-the-box support.

### LEEF (IBM Log Event Extended Format)

- **ALT-003 Description**: IBM's LEEF is the native format for IBM QRadar, similar in
  structure to CEF.
- **ALT-004 Rejection Reason**: LEEF is QRadar-specific. CEF has wider multi-vendor
  support (ArcSight, Splunk, Sentinel, QRadar, and others all ingest CEF). Implementing
  both would be duplication; CEF is the more universal choice.

### OCSF (Open Cybersecurity Schema Framework)

- **ALT-005 Description**: OCSF (AWS + 18 partners, 2022) is a JSON schema for security
  events with a formal taxonomy. Growing adoption in cloud-native SIEMs.
- **ALT-006 Rejection Reason**: OCSF tooling and SIEM connector maturity is lower than
  CEF as of 2026 for on-premise KMS deployments. The OCSF schema is richer but heavier;
  the per-event JSON overhead is larger than a CEF line. CEF remains the dominant choice
  for on-premise compliance tooling. OCSF support can be added later as a second
  serialiser without removing CEF.

### Raw KMS JSON (reuse JSONL schema)

- **ALT-007 Description**: Forward the JSONL audit line directly to the SIEM.
- **ALT-008 Rejection Reason**: Custom JSON schema requires a SIEM-side parser for each
  SIEM product. Includes `prev_hash` / `row_hash` fields that are meaningless to a SIEM.
  Does not map to any standard event taxonomy, so cross-system correlation is harder.

## Implementation Notes

- **IMP-001**: Serialiser: `crate/access/src/audit/cef.rs` — `to_cef_line()`
- **IMP-002**: CEF v27 spec reference: [ArcSight CEF Implementation Standard, version 27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf)
  (OpenText, April 2024)
- **IMP-003**: Severity thresholds (5/6/7) are constants in `cef.rs`; operators needing
  different mappings should adjust there.
- **IMP-004**: Transport is out of scope for this implementation. For production TCP
  syslog delivery with RFC 6587 octet-counting framing, see ADR-2026-08-10-tcp-syslog-cef-transport. File-tailing
  ingestion (filebeat, fluent-bit) is documented in `siems.md`.
- **IMP-005**: CEF escaping: `|` → `\|`, `\` → `\\` in header fields;
  `=` → `\=`, `\n` → `\\n`, `\r` → `\\r` in extension values. Covered by unit tests
  in `cef.rs`.
- **IMP-006**: The `row_hash` and `prev_hash` fields are intentionally absent from CEF
  output — document this explicitly for SIEM operators: the CEF stream alone is not
  chain-verifiable.

## References

- **REF-001**: ADR-2026-07-09-audit-log-single-writer-design — Tamper-Evident JSONL Audit Log (authoritative record)
- **REF-002**: ADR-2026-07-09-audit-middleware-extension-injection — HTTP-Layer Audit Middleware (capture architecture)
- **REF-003**: [ArcSight CEF Implementation Standard v27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.2/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf) (OpenText, April 2024)
- **REF-004**: OCSF v1.x specification — <https://schema.ocsf.io>
- **REF-005**: `crate/access/src/audit/cef.rs`
- **REF-006**: ADR-2026-08-10-tcp-syslog-cef-transport — TCP Syslog CEF Transport (production delivery)

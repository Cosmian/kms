---
title: "ADR-0007: TCP Syslog with RFC 6587 Octet-Counting for CEF Transport"
status: "Accepted"
date: "2026-08-10"
authors: "contributors, security operations engineers"
tags: ["architecture", "decision", "siem", "cef", "syslog", "rsyslog", "interoperability"]
supersedes: ""
superseded_by: ""
---

# ADR-0007: TCP Syslog with RFC 6587 Octet-Counting for CEF Transport

## Status

Accepted

## Context

CEF audit lines (ADR-0005) must be delivered to SIEM receivers. The initial CEF
export pipeline (`ckms audit export --format cef | nc -u`) used **UDP syslog**, which
is fine for ad hoc verification but unsuitable for production:

- **UDP has no delivery guarantee**: packets can be silently dropped or reordered.
- **No framing standard**: a CEF line could span multiple UDP packets if it exceeds
  the MTU (though current CEF lines are well under 1500 bytes).
- **UDP port 514 is privileged** on Linux (requires `root`), forcing operators to use
  non-standard ports (e.g. 5514).

The KMS documentation (`siems.md`) must recommend a production-grade transport for
CEF delivery. The requirements are:

1. **Reliable delivery** — no silent message loss from the transport layer.
2. **Standard framing** — parsable by any compliant syslog daemon without a custom
   parser.
3. **Works with open-source receivers** — the integration test must use only
   open-source Docker images.
4. **No additional KMS code changes** — the transport is between the CEF export
   (stdout) and the SIEM receiver (network).

## Decision

Recommend **TCP syslog with RFC 6587 octet-counting framing** (`<byte-count> <message>`)
as the primary production transport for CEF delivery. Validate it with `rsyslog` in
Docker (`rsyslog/syslog_appliance_alpine`, ASL 2.0).

### Framing

Per RFC 6587 §3.4.1, each frame is:

```text
<byte-count><SP><syslog-message>
```

Where `<byte-count>` is the decimal length of `<syslog-message>` in bytes. The
syslog message carries a standard RFC 3164 PRI header (e.g. `<134>` for
`local0.info`) followed by the CEF line.

Example — sending via bash:

```bash
while IFS= read -r line; do
  msg="<134>$(date '+%b %d %H:%M:%S') kms-audit: ${line}"
  printf '%zu %s' "${#msg}" "${msg}" > /dev/tcp/<host>/5514
done < <(ckms audit export --format cef --path audit.jsonl)
```

Or via `nc` (test path):

```bash
printf '%zu %s' "${#msg}" "${msg}" | nc -w 5 <host> 5514
```

### rsyslog receiver configuration

```conf
module(load="imtcp")
input(type="imtcp" port="5514" Ruleset="kms_cef")
ruleset(name="kms_cef") {
  action(
    type="omfile"
    file="/var/log/kms-cef.log"
    template="RSYSLOG_FileFormat"
  )
}
```

`RSYSLOG_FileFormat` is used (not `RSYSLOG_ForwardFormat`) because it appends `\n`
after each message, producing one line per event — essential for downstream parsing.

### Why octet-counting over non-transparent framing

RFC 6587 defines two TCP framing modes:

| Mode | Delimiter | Pros | Cons |
|------|-----------|------|------|
| Octet-counting | Length prefix | Unambiguous, no escaping needed | Sender must compute length before sending |
| Non-transparent (LF) | `\n` delimiter | Simple, human-friendly | CEF line must not contain raw `\n` (currently escaped, but not guaranteed by protocol) |

Octet-counting is the safer choice for production: it cannot be confused by a CEF
line that accidentally contains a newline (e.g. from an error message in the `reason`
field). Both modes are supported by `rsyslog`, `syslog-ng`, and Splunk TCP inputs.

## Consequences

### Positive

- **POS-001**: Reliable delivery — TCP guarantees ordered, lossless delivery at the
  transport layer.
- **POS-002**: Standard framing — any RFC 6587-compliant syslog daemon can parse the
  stream without a custom parser.
- **POS-003**: The integration test (`test_siem_cef_tcp_syslog.sh`) proves real
  interop with `rsyslog/syslog_appliance_alpine` — not a mock.
- **POS-004**: No KMS code changes required — the transport is entirely in the
  operator's pipeline.
- **POS-005**: Uses a high port (51514 in tests, 5514 recommended for production) —
  no root privilege needed.

### Negative

- **NEG-001**: TCP introduces connection state — the sender must handle connection
  drops and reconnects. The simple `printf … > /dev/tcp/…` pattern re-opens the
  connection per line; production use should use `nc` with keep-alive or a purpose-built
  forwarder.
- **NEG-002**: No TLS in the current integration test — plaintext TCP is validated.
  Production deployments behind untrusted networks should add TLS via `rsyslog`'s
  `StreamDriver` options. This is documented but not tested.
- **NEG-003**: The `rsyslog/syslog_appliance_alpine` image is lightweight but pinned
  to an older `rsyslog` version (2018-era). The test validates framing and delivery,
  not TLS or high-throughput performance.

## Alternatives Considered

### UDP syslog (current ad hoc approach)

- **ALT-001 Description**: `ckms audit export --format cef | nc -u -w 1 <host> 5514`
- **ALT-002 Rejection Reason**: No delivery guarantee. Sufficient for ad hoc
  verification (and retained as the "UDP quick test" path in `siems.md`), but
  not suitable for production or as the recommended path.

### CEF → Kafka → SIEM

- **ALT-003 Description**: Pipe CEF lines to a Kafka topic; the SIEM consumes from
  Kafka. More robust than direct syslog.
- **ALT-004 Rejection Reason**: Adds a Kafka dependency (broker + topic management)
  that many KMS deployments don't have. Kafka is a valid next step for high-volume
  deployments but is not the baseline recommendation. Deferred to a future ADR.

### CEF → HTTP Event Collector (Splunk HEC)

- **ALT-005 Description**: POST CEF lines to a Splunk HEC endpoint as structured
  events.
- **ALT-006 Rejection Reason**: Splunk is proprietary; HEC is Splunk-specific.
  TCP syslog works with any SIEM (ArcSight, QRadar, Sentinel, Splunk, rsyslog
  relay). Deferred for a customer-driven use case.

### OTLP log records as primary CEF transport

- **ALT-007 Description**: Rely on the OTLP audit log export (ADR-0006) to carry
  the CEF attribute to the collector, then route to the SIEM from the collector.
- **ALT-008 Rejection Reason**: OTLP audit export is a complementary path, not a
  replacement. CEF-over-syslog is for operators whose SIEM accepts syslog but does
  not have an OTLP collector. The two paths coexist.

## Implementation Notes

- **IMP-001**: Integration test: `.mise/scripts/test/test_siem_cef_tcp_syslog.sh`
- **IMP-002**: rsyslog config: `.mise/scripts/test/rsyslog.conf`
- **IMP-003**: MISE task: `.mise/tasks/test/siem-cef-tcp-syslog`
- **IMP-004**: Aggregated into `mise run test:siem --suite all`
- **IMP-005**: Documented in `documentation/docs/configuration/siems.md` under
  "CEF over TCP syslog (rsyslog)"
- **IMP-006**: Uses `RSYSLOG_FileFormat` template (not `RSYSLOG_ForwardFormat`)
  to guarantee one line per message. Validated by the integration test.

## References

- **REF-001**: ADR-0005 — CEF v27 as SIEM Export Format (CEF format definition)
- **REF-002**: ADR-0006 — OTLP Log Record Export (complementary native push path)
- **REF-003**: RFC 6587 — Transmission of Syslog Messages over TCP
- **REF-004**: `documentation/docs/configuration/siems.md` — SIEM integration guide
- **REF-005**: `rsyslog/syslog_appliance_alpine` — Docker image (ASL 2.0)
- **REF-006**: `CHANGELOG/feat_audit_integration.md` — branch change log

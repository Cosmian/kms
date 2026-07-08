# Audit SIEM integration

!!! note "Current integration model"

    The KMS does **not** push events to a SIEM directly yet. Instead, the local JSONL file is
    the authoritative audit store: external SIEMs consume it either by tailing the file
    directly or by using the `ckms audit export` CLI tool for format conversion.

    A native push pipeline (OpenTelemetry, syslog/CEF, Splunk HEC) [is a planned feature](https://github.com/Cosmian/kms/issues/881?issue=Cosmian%7Ckms%7C937),
    and will add server-side configuration sections for direct SIEM delivery.

The `ckms audit` subcommands work **entirely offline**: no running KMS server is required.

For the full `ckms audit export` CLI reference — flags, output formats, CEF field mapping, and
examples — see [Audit commands](https://docs.cosmian.com/kms_clients/audit/).

---

## Splunk (recommended)

Splunk tails the JSONL audit file directly using its Universal Forwarder or a local monitor
input. This is the only integration that ingests events continuously with no format
conversion and no custom transport: JSONL in, JSON events out, and delivery state is tracked
by Splunk.

Add to `inputs.conf` on the indexer or a forwarder:

```ini
[monitor:///var/log/cosmian-kms/audit.jsonl]
disabled = false
sourcetype = _json
index = kms_audit
```

With Splunk's built-in `_json` sourcetype, one JSON object per line is parsed as a JSON event
and top-level fields are searchable. Before enabling the monitor, validate field extraction
against representative audit events and make sure the `kms_audit` index exists with the
appropriate retention and access controls.

---

## CEF export for testing and verification

The `ckms audit export --format cef` command converts the JSONL store into CEF and prints it
to stdout. This is a **manual, one-shot** operation intended for verification — sending a
sample of events to a CEF listener to confirm parsing and field mapping. It is **not** a
continuous ingest pipeline; each run re-reads the file from the beginning (or from `--since`)
and there is no delivery guarantee over the wire.

### Ad hoc export to any listener

For a quick one-off check against any CEF listener:

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

---

!!! warning "Restrict access to the audit file"

    The audit file contains actor identities, client IP addresses, object identifiers, and
    operation metadata. Restrict file ownership to the KMS process user and grant read access
    only to the collection agent. Do not expose the file over untrusted networks without
    encryption.

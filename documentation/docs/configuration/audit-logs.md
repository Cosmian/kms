# Audit logging

The Eviden KMS server can record a cryptographically chained, tamper-evident audit trail of
every KMIP operation, including authentication failures. Two backends are available: a local
JSONL file, or a PostgreSQL database for a fleet of instances. See
[Audit events](./audit-events.md) for the fields every event carries.

Audit logging is disabled by default: no backend is started until the feature is enabled.

---

## Choosing a backend

| | File backend | PostgreSQL backend |
| --- | --- | --- |
| Best for | A single instance, or one file per instance | A fleet of instances sharing one audit trail |
| If the backend is unreachable at startup | Starts anyway and buffers events | Refuses to start |
| If content is found corrupted at startup | Seals the old chain, starts a new one, keeps serving | Seals the old chain, starts a new one, keeps serving |
| Sealed-evidence check | Automatic, part of `ckms audit verify` | Manual, see [PostgreSQL backend](./audit-postgresql-backend.md#checking-sealed-evidence-by-hand) |
| Size cap | Yes, `--audit-file-max-size-bytes` | No |

The backend is chosen at configuration time, with no fallback between the two. See
[File backend](./audit-file-backend.md) or [PostgreSQL backend](./audit-postgresql-backend.md)
for the configuration and behavior specific to each.

---

## Configuration

Enabling the pipeline is shared by both backends; each backend then needs its own path or URL.

=== "TOML configuration file"

    ```toml
    [audit]
    enabled = true
    ```

=== "Command line"

    ```bash
    cosmian_kms --audit-enable
    ```

=== "Environment variables"

    ```bash
    export KMS_AUDIT_ENABLE=true
    cosmian_kms
    ```

With no other setting, the file backend starts at its default path,
`<root-data-path>/audit.jsonl`. See [File backend](./audit-file-backend.md) to set a specific
path, or [PostgreSQL backend](./audit-postgresql-backend.md) for a shared database.

!!! warning "Not safe for multiple KMS instances sharing one file"
    The file backend is designed for one writer per file. If you run multiple KMS instances
    (horizontal scaling, Kubernetes replicas), each one needs its own audit file: never point
    several instances at the same path on a shared volume. For a centrally consolidated,
    multi-writer-safe audit trail, use the [PostgreSQL backend](./audit-postgresql-backend.md) instead.

The settings below apply to whichever backend you use:

| CLI flag                      | Environment variable            | Default                        | Description                                                                                                                                                                                                            |
| ----------------------------- | ------------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--audit-enable`              | `KMS_AUDIT_ENABLE`              | `false`                        | Enable the audit pipeline. When `false`, no backend is started.                                                                                                                            |
| `--audit-channel-capacity`    | `KMS_AUDIT_CHANNEL_CAPACITY`    | `4096`                         | Capacity of the in-memory queue between request handling and the backend writer. Raise this if you see `channel full` warnings under sustained load.                                                                               |
| `--audit-trusted-proxy-cidrs` | `KMS_AUDIT_TRUSTED_PROXY_CIDRS` | _(empty)_                      | Comma-separated CIDR blocks (e.g. `10.0.0.0/8,172.16.0.0/12`) of reverse proxies/load balancers allowed to set `client_ip` via `X-Forwarded-For`. See [Client IP and reverse proxies](#client-ip-and-reverse-proxies). |
| `--audit-failure-mode`        | `KMS_AUDIT_FAILURE_MODE`        | `continue`                     | What to do when an event cannot be recorded. `continue`: log the error, keep serving. `reject`: return HTTP 503. See [Audit failure mode](#audit-failure-mode).                                                        |

If you see `AuditFileStore: channel full, dropping audit event` in the server log, raise
`--audit-channel-capacity`. The dropped events are still accounted for: the next successful
write is preceded by an `audit:eviction` event recording how many were lost. See
[Audit events](./audit-events.md#system-events).

### Client IP and reverse proxies

By default (`--audit-trusted-proxy-cidrs` empty), `client_ip` in every audit event is always the
direct TCP peer address: the `X-Forwarded-For` header is ignored entirely.

If the KMS runs **directly reachable** by clients (no reverse proxy/load balancer in front), leave
this unset: the TCP peer address is always the real client.

If the KMS runs **behind a reverse proxy or load balancer**, the direct TCP peer is always the
proxy, not the real client. Set `--audit-trusted-proxy-cidrs` to the proxy's IP/CIDR so the audit
middleware knows it can trust `X-Forwarded-For` coming from that address. Otherwise every audit
event records the proxy's IP instead of the real client's.

**Never** trust `X-Forwarded-For` unconditionally: any direct caller can set that header to an
arbitrary value, corrupting the forensic trail (e.g. framing another IP, or hiding its own).
Restricting trust to known proxy CIDRs prevents this while still letting a legitimate reverse
proxy forward the real client IP.

---

### Audit failure mode

By default (`continue`) the KMS keeps serving even when an audit event cannot be recorded: the
event is dropped, an error is logged, and the request succeeds normally.

Set `--audit-failure-mode reject` to enforce strict auditability: if an event cannot be recorded
(the queue is full or the backend has stopped), the KMS returns **HTTP 503** to the client
instead of the normal KMIP response. The KMIP operation has already executed at this point; the
503 signals that its outcome was not recorded.

!!! warning "`reject` mode can cause service disruption"
    When `failure_mode = reject`, a saturated event queue or a stopped backend will make every
    subsequent KMIP request fail with 503 until the condition is resolved. Only use this mode
    when unlogged operations are strictly unacceptable (e.g.
    regulated environments requiring a complete audit trail).

---

## Verifying the trail

```bash
ckms audit verify --path /var/log/cosmian-kms/audit.jsonl
```

Exit code `0` means the chain is intact; `1` means a broken link, a tampered event, or altered or
missing sealed evidence was found. See
[File backend](./audit-file-backend.md#verifying-a-file-or-a-directory) or
[PostgreSQL backend](./audit-postgresql-backend.md#verifying-and-exporting) for the full set of
options and sample output.

---

## Retention and monitoring

Retain audit data for the compliance window required by your framework, for example PCI-DSS
Req. 10.7 (12 months) or HIPAA §164.312(b) (6 years). Restrict read access to the audit data to
the KMS process user and auditors only: it contains usernames, client IPs, and operation details.

Monitor for the recovery events listed in [Audit events](./audit-events.md#system-events) and the
matching server log lines in the [log reference](./log-reference.md). A torn write is routine
after an ungraceful restart; a seal-and-roll (`audit:reanchor`) is worth investigating.

For SIEM ingestion and CEF export, see [SIEM integration](./siems.md).

### SIEM integration test suite — four top-level `mise test:*` commands

- Added `mise test:audit` — proves ADR-003/004: tamper-evident JSONL, hash chain
  integrity, required fields, Success+Failure coverage. Zero tolerance: exits 1
  if no events written or chain broken.
- Added `mise test:cef --suite <format|syslog|tcp-syslog|all>` — proves ADR-005/007:
  CEF v27 format correctness (validated with `jc` parser), UDP syslog delivery
  (4/4 events guard), TCP rsyslog with RFC 6587 octet-counting (field integrity
  preserved end-to-end).
- Reorganised `mise test:siem` suites to `fluent-bit`, `filebeat`, `otlp`.
  Added `--suite otlp`: starts an OTel Collector container, generates 66 KMIP
  ops to flush the 64-event OTLP batch while KMS is running, then asserts ≥ 64
  log records received, `cef_line` attribute present, `severityText` valid.
- Added `mise test:monitoring` — starts OTel Collector + VictoriaMetrics + Grafana;
  asserts ≥ 100 KMS metric lines on the OTel Prometheus debug endpoint and that
  all required metric families exist; asserts Grafana `/api/health` returns
  `database=ok`.
- All tests include a pre-flight step that removes stale Docker containers
  occupying test ports (prevents port-conflict failures on re-runs).
- Changed all `SKIP: Docker …; exit 0` guards in SIEM test scripts to hard
  errors (`ERROR: …; exit 1`) — no test can be silently skipped.
- Added `audit` and `monitoring` matrix entries to `.github/workflows/test_all.yml`;
  both run non-fips only, excluded from fips matrix.
- Added a single Markdown table to `.mise/scripts/README.md` describing all MISE
  test commands (database, HSM, observability/SIEM) with scripts, ADRs, and
  Docker images used.
- Added Mermaid sequence diagrams to documentation:
  - `audit-logs.md`: audit middleware → JSONL hash chain + OTLP side-car
  - `siems.md`: three models — file tailing, CEF export, OTLP audit push
  - `monitoring-setup.md`: KMS → OTel Collector → VictoriaMetrics ← Grafana
- Updated `documentation/docs/configuration/siems.md` with a full testing table
  and per-command guard documentation.

### CEF-over-TCP syslog integration test (rsyslog)

- Added `mise run test:siem-cef-tcp-syslog` — validates CEF export → TCP syslog
  with RFC 6587 octet-counting framing against a real rsyslog daemon
  (`rsyslog/syslog_appliance_alpine`).
- Added the TCP syslog suite to `mise run test:siem --suite all`.
- Documented TCP syslog configuration for rsyslog in `siems.md`.

### OTLP log record export for audit events

- Added `[audit.otlp]` config section (`endpoint`, `allow_insecure`) to export
  audit events as OTLP log records via HTTP/JSON to an OpenTelemetry collector.
- When `audit_otlp_endpoint` is set, every audit event is enqueued as a
  side-car alongside the file store, with JSONL body and `cef_line` attribute.
- The OTLP export is non-blocking (channel-based, same design as `AuditFileStore`).
- Configurable via `KMS_AUDIT_OTLP_ENDPOINT` / `KMS_AUDIT_OTLP_ALLOW_INSECURE`
  environment variables or TOML `[audit.otlp]`.

### SIEM integration test suite — four top-level `mise test:*` commands

- Added `mise test:audit` — proves ADR-2026-07-09-audit-log-single-writer-design / ADR-2026-07-09-audit-middleware-extension-injection: tamper-evident JSONL, hash chain
  integrity, required fields, Success+Failure coverage. Zero tolerance: exits 1
  if no events written or chain broken.
- Added `mise test:cef --suite <format|syslog|tcp-syslog|all>` — proves ADR-2026-07-09-cef-siem-export-format / ADR-2026-08-10-tcp-syslog-cef-transport:
  CEF v27 format correctness (validated with `jc` parser), UDP syslog delivery
  (4/4 events guard), TCP rsyslog with RFC 6587 octet-counting (field integrity
  preserved end-to-end).
- Reorganised `mise test:siem` suites to `fluent-bit`, `filebeat`.
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
  - `audit-logs.md`: audit middleware → JSONL hash chain, file-tail SIEM pattern
  - `siems.md`: two models — file tailing, CEF export
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

- Removed in favour of the file-tailing pattern: a dedicated agent (Vector, Filebeat,
  Fluent Bit) reads `audit.jsonl` from its last committed offset and forwards events
  with guaranteed delivery.  An in-process OTLP channel cannot provide exhaustive
  delivery guarantees required for compliance audit trails (PCI-DSS Req. 10).

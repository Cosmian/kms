## Security

- **CVE fix (npm)**: upgrade `brace-expansion` to ≥ 5.0.7 via pnpm override
  (ReDoS, [GHSA-v6h2-p8h4-qcjw](https://github.com/advisories/GHSA-v6h2-p8h4-qcjw))
- **CVE fix (npm)**: upgrade `js-yaml` to ≥ 4.3.0 via pnpm override
  (prototype pollution, [GHSA-8j8c-7jfh-h6hx](https://github.com/advisories/GHSA-8j8c-7jfh-h6hx))
- **CVE fix (Rust)**: upgrade `opentelemetry_sdk` from 0.29.0 to 0.32.1
  (SSRF via malicious OTLP endpoint config, [GHSA-r74r-p7x6-m97p](https://github.com/advisories/GHSA-r74r-p7x6-m97p))
  — updated metric data API from `dyn Any` downcasting to typed `AggregatedMetrics` enum

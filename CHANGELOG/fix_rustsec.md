## Security

### Dependency updates

- Bump `quick-xml` from 0.31 to 0.41 — fixes RUSTSEC-2026-0194 (quadratic attribute-check DoS) and RUSTSEC-2026-0195 (unbounded namespace-declaration memory exhaustion)
- Bump `quinn-proto` from 0.11.14 to 0.11.15 — fixes RUSTSEC-2026-0185 (remote memory exhaustion via crafted QUIC STREAM frames)
- Bump `anyhow` from 1.0.102 to 1.0.103 — fixes RUSTSEC-2026-0190 (unsoundness in `Error` downcasting)

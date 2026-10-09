---
title: "ADR-2026-10-10: Limit EST client support in ckms and the Web UI to cacerts and enroll"
status: "Accepted"
date: "2026-10-10"
authors: "KMS maintainers, CLI and Web UI contributors, PKI operators"
tags: ["architecture", "decision", "est", "cli", "ui"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-10: Limit EST client support in ckms and the Web UI to cacerts and enroll

## Status

Proposed | **Accepted** | Rejected | Superseded | Deprecated

## Context

The server side of issue #871 (EST, RFC 7030, and SCEP, RFC 8894) is implemented under
`crate/server/src/routes/est/` and `crate/server/src/routes/scep/`. The issue specified only two client
commands: `ckms est cacerts` and `ckms est enroll`. The CLI and Web UI must mirror each other, so a client
surface has to be chosen. Three questions needed a decision:

1. Which EST/SCEP operations get a CLI command and UI page.
2. How bootstrap (HTTP Basic) credentials are sent: `HttpClient` normally attaches its own default headers
   (KMS bearer/vault token) to every request.
3. What format the issued certificates are returned in, given that the CLI can use OpenSSL but the UI has no
   ASN.1/CMS library.

## Decision

1. **Scope.** Implement exactly `ckms est cacerts` and `ckms est enroll`, plus one Web UI page for each
   (Certificates → Enrollment (EST)). Do not add `est reenroll` or any `scep` command.
2. **Basic authentication.** Add `HttpClient::post_bytes_with_basic_auth`, which builds the request without
   `apply_default_headers`. A device enrolling through EST has no KMS identity yet; sending the client's
   own token alongside `Authorization: Basic` would be wrong and would produce two `Authorization` headers.
   Mutual-TLS authentication keeps using the client certificate already configured in `ckms.toml`.
3. **Output format.** The CLI decodes the base64 PKCS#7 `certs-only` response with OpenSSL and writes
   concatenated PEM certificates. The UI downloads the raw DER PKCS#7 (`.p7b`), which
   `openssl pkcs7 -inform DER -print_certs` converts to PEM.
4. **CLI subcommand names.** The clap variant `CaCerts` is explicitly named `cacerts` to match the issue.

## Consequences

### Positive

- **POS-001**: Matches the issue's own CLI specification; small, reviewable surface.
- **POS-002**: Bootstrap credentials are never mixed with a KMS session token.
- **POS-003**: No new UI dependency (ASN.1/CMS parser or WASM export) is needed.
- **POS-004**: Verified end to end by `tests::est::test_est_cacerts_and_enroll` and a browser run against a live server.

### Negative

- **NEG-001**: CLI and UI outputs differ (PEM vs `.p7b`); UI users need one extra `openssl` command.
- **NEG-002**: Renewal (`simplereenroll`) and SCEP are server-only; operators needing them use third-party
  clients such as `estclient` and `scepclient`, as the interop scripts do.
- **NEG-003**: CLI and Web UI ship together, contrary to the repository's usual one-PR-per-layer cascade.

## Alternatives Considered

### Add `est reenroll` and `scep` commands

- **ALT-001 Description**: Mirror every server endpoint in the CLI and UI.
- **ALT-002 Rejection Reason**: The issue does not list them. Reenroll requires mutual TLS with the certificate
  being renewed. SCEP `PKIOperation` requires building a CMS envelope encrypted to the CA RSA key, which is a
  device-side capability rather than an admin tool.

### Reuse `post_bytes` with an extra `Authorization` header

- **ALT-003 Description**: Append the Basic header via `post_form`-style `extra_headers`.
- **ALT-004 Rejection Reason**: Default headers are applied first, so the request would carry the KMS token
  and two `Authorization` headers; the server reads only the first.

### Parse PKCS#7 in the UI

- **ALT-005 Description**: Add a JS ASN.1 library or a new WASM export to produce PEM in the browser.
- **ALT-006 Rejection Reason**: New dependency or WASM surface for a mirror of two client commands; out of scope.

## Implementation Notes

- **IMP-001**: CLI code is in `crate/clients/clap/src/actions/est/`; `openssl` moved from dev-dependency to
  dependency of `cosmian_kms_cli_actions`, and `KmsCliError::OpenSSL` is no longer test-only.
- **IMP-002**: UI components are `ui/src/actions/Certificates/EstCaCerts.tsx` and `EstEnroll.tsx`; locale keys
  were added to en, zh-CN and fr.
- **IMP-003**: The `ckms` test module is compiled only with `--features non-fips`, and `ensure_ckms_binary()` does
  not rebuild an existing binary; rebuild `ckms` manually when running the test after source changes.
- **IMP-004**: UI fetches use the absolute `serverUrl`; in `vite dev` this is cross-origin and the server sends no
  CORS headers for it, so the pages are meant to be served by the KMS server (same as the CRL download page).

## References

- **REF-001**: `documentation/adr/scep/`, `CHANGELOG/scep.md`, `CHANGELOG/est_cli_ui.md`
- **REF-002**: RFC 7030 (EST), RFC 7617 (HTTP Basic), RFC 8894 (SCEP)
- **REF-003**: `crate/server/src/routes/est/`, `crate/clients/client/src/http_client/client.rs`,
  `crate/clients/clap/src/actions/est/`, `crate/clients/ckms/src/tests/est.rs`

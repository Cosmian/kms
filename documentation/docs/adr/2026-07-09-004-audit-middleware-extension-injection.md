---
title: "ADR-2026-07-09-audit-middleware-extension-injection: HTTP-Layer Audit Middleware with Actix Extension Injection"
status: "Accepted"
date: "2026-07-09"
authors: "contributors, security architects, compliance engineers"
tags: ["architecture", "decision", "audit", "middleware", "actix-web"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-07-09-audit-middleware-extension-injection: HTTP-Layer Audit Middleware with Actix Extension Injection

## Status

Accepted

## Context

Every KMIP operation — including authentication failures — must produce an audit event
(see ADR-2026-07-09-audit-log-single-writer-design). The challenge is _where_ in the call stack to intercept it. The KMS has
a layered architecture:

```text
HTTP client
  │
  ▼  Actix-web middlewares (CORS, EnsureAuth, JwtAuth, TlsAuth, RateLimit, …)
  ▼  KMIP route handler (TTLV deserialisation → dispatch → TTLV serialisation)
  ▼  KMS core (operations: Create, Encrypt, Destroy, …)
  ▼  Database / HSM backends
```

Two hard requirements compete:

1. **401/403 authentication failures must be audited.** This means the audit hook must run
   _outside_ the auth middlewares so it sees their rejection responses.
2. **Per-operation context (`object_uid`, `algorithm`) should be captured.** This context
   only exists _inside_ the KMIP dispatch layer, deep in the stack.

Instrumenting every individual KMIP operation handler (≈40 operations) would satisfy
requirement 2 but misses requirement 1 for failed auth. A pure outer middleware satisfies
requirement 1 but cannot directly see KMIP-layer data (requirement 2).

## Decision

Implement a two-part design:

### Part 1 — Outer HTTP middleware

An Actix-web `Transform` / `Service` wrapper (`AuditMiddleware`) is registered **just
before** the CORS middleware in `start_kms_server.rs`:

- It fires **after the inner service has returned** (post-response hook), recording the
  HTTP status code and wall-clock duration.
- It always runs, even when inner services return 401/403 — unauthenticated events are
  recorded with `user = "unauthenticated"`.
- When `AuditFileStore` is `None` (audit disabled) the middleware is a zero-cost
  pass-through (single `Option::is_none()` check).
- CORS `OPTIONS` preflight requests are not audited (CORS middleware handles them before
  the audit wrapper runs — acceptable, as preflight carries no KMIP semantics).

### Part 2 — Actix extension injection from the KMIP route layer

The KMIP route handler, after TTLV parsing but before (or after) dispatch, injects
structured context into the Actix request extensions:

| Extension type      | Populated by  | Content                                       |
| ------------------- | ------------- | --------------------------------------------- |
| `KmipOperationName` | TTLV parser   | `"Encrypt"`, `"Create"`, `"Create+Destroy"` … |
| `KmipObjectUid`     | route handler | UID from request or server-assigned (Create)  |
| `KmipAlgorithm`     | route handler | `"AES"`, `"RSA"`, …                           |

The outer middleware reads these extensions when composing the `AuditEventDraft`. If an
extension is absent (e.g. non-KMIP endpoint, or extraction failed) the field defaults to
`None` — the audit record is degraded but the request is never affected.

**Infallibility principle**: all TTLV extraction functions are explicitly infallible. A
parsing failure returns `None`; it never propagates an error to the response or panics.
Audit context extraction is best-effort; the KMIP response is authoritative.

### Current state vs. full design

`KmipObjectUid` and `KmipAlgorithm` injection are defined and exported but not yet
populated by all operation handlers (tracked as T1 in `tradeoofs.md`). The extension
mechanism is in place; filling it is incremental per-operation work.

## Consequences

### Positive

- **POS-001**: Authentication failures (401/403) are audited with no per-handler changes.
- **POS-002**: Adding audit coverage to a new KMIP operation requires only populating
  `KmipObjectUid` and `KmipAlgorithm` extensions — no changes to the audit middleware
  or the storage layer.
- **POS-003**: The middleware is a zero-overhead pass-through when audit is disabled.
- **POS-004**: Infallibility guarantees that a buggy TTLV extractor never breaks the
  KMIP response.
- **POS-005**: Middleware ordering is explicit and documented in `start_kms_server.rs`.

### Negative

- **NEG-001**: Until all handlers inject `KmipObjectUid`, the field is `None` — the log
  cannot answer "which key was used", failing FIPS key lifecycle accountability and
  PCI-DSS 10.2.1.2 (tracked: T1).
- **NEG-002**: Batch `RequestMessage` with N `BatchItems` produces one audit event.
  Per-item granularity requires a different enqueue API (tracked: T2).
- **NEG-003**: The `client_ip` is taken from `X-Forwarded-For` without validating the
  peer IP against a trusted-proxy allowlist — spoofable (tracked: T7).
- **NEG-004**: Middleware ordering is implicit in `start_kms_server.rs` registration
  order; a future reordering could accidentally exclude auth-failure events.

## Alternatives Considered

### Per-operation instrumentation in the dispatch layer

- **ALT-001 Description**: Add an `audit(&mut self, event: AuditEventDraft)` call inside
  each of the ~40 `crate/server/src/core/operations/<op>.rs` handlers, after the
  operation completes.
- **ALT-002 Rejection Reason**: Does not capture authentication failures (the dispatch
  layer is never reached on a 401). Requires touching every operation handler — high
  coupling and high churn. A cross-cutting concern belongs in a middleware, not scattered
  across 40 files.

### `From<ServiceResponse>` extraction only (no extension injection)

- **ALT-003 Description**: The outer middleware attempts to infer `object_uid` and
  `algorithm` by deserialising the TTLV _response_ body.
- **ALT-004 Rejection Reason**: TTLV response bodies are not always structured to expose
  UIDs (e.g. `EncryptResponse` does not echo back the key UID). Response bodies can be
  large. Double-parsing the body adds latency and complexity. The extension injection
  approach puts the extraction at the right layer (knows the request context) with no
  double-parsing.

### Actix `HttpRequest::extensions_mut()` in a post-dispatch hook

- **ALT-005 Description**: Use Actix's `on_connect` or a request finaliser callback to
  write audit data after the inner future resolves.
- **ALT-006 Rejection Reason**: Actix-web does not have a first-class post-dispatch hook
  that receives both the request extensions and the final response simultaneously. The
  `Transform`/`Service` wrapper pattern is the idiomatic Actix way to wrap request-response
  pairs; it is well-understood, tested, and used by other middlewares in this codebase.

## Implementation Notes

- **IMP-001**: Middleware: `crate/server/src/middlewares/audit.rs`
- **IMP-002**: Extension types exported from `crate/server/src/middlewares/mod.rs`
- **IMP-003**: Injection site: `crate/server/src/routes/kmip/audit.rs`
  (`inject_kmip_audit_context()` called from KMIP route handlers)
- **IMP-004**: Middleware registration: `crate/server/src/start_kms_server.rs`
  (`.wrap(AuditMiddleware::new(audit_store.clone(), trusted_proxy_cidrs.clone()))` before `.wrap(cors)`)
- **IMP-005**: To fill T1 — inject `KmipObjectUid` from each operation handler's
  request/response TTLV; see `tradeoofs.md` and `.agents/prompts/fill-audit-object-uid.md`
- **IMP-006**: Infallibility rule: all functions in `routes/kmip/audit.rs` must be
  `fn f(..) -> Option<String>` or return a fallback — never `KResult`.

## References

- **REF-001**: ADR-2026-07-09-audit-log-single-writer-design — Tamper-Evident JSONL Audit Log (storage layer decisions)
- **REF-002**: Actix-web middleware docs — `Transform` / `Service` pattern
- **REF-003**: `tradeoofs.md` T1, T2, T7 — known gaps in this design
- **REF-004**: `crate/server/src/middlewares/audit.rs` — "Design decisions" doc comment
- **REF-005**: `crate/server/src/start_kms_server.rs` — middleware registration order

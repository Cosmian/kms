# OCSP Responder (RFC 6960)

## Added

- **OCSP responder endpoints** (`GET /ocsp/{base64url-DER}` and `POST /ocsp/`) conforming
    to RFC 6960, RFC 9654, RFC 5019, and RFC 5280. Both routes are public
    (unauthenticated), matching the existing public CRL endpoint.
    - Returns `good`, `revoked` (with `CRLReason` and `revocationTime`), or `unknown` for
        any certificate serial number queried against the configured CA.
    - Nonce support per RFC 9654 §2.1: configurable `optional`, `required`, or `ignore`
        policy via `--ocsp-nonce-policy`.
    - `nextUpdate` always set, derived from `--ocsp-cache-ttl-secs`.
    - Archive-cutoff extension (RFC 6960 §4.4.4) settable via
        `--ocsp-archive-cutoff-secs`.
    - RFC 5019-compliant HTTP caching headers (`Cache-Control`, `Last-Modified`,
        `Expires`, `ETag`).
    - In-memory response cache (TTL = `ocsp_cache_ttl_secs`) to avoid re-signing
        identical responses; bypassed only when a request actually carries a nonce
        (under any policy other than `ignore`) or once the CA itself is marked
        compromised, so the cache stays effective for the common nonce-less case
        under the default `optional` policy.
    - Delegated OCSP signing key support (RFC 6960 §4.2.2.2) via
        `--ocsp-responder-cert-uid`, following the `PrivateKeyLink` attribute on the
        signer certificate.
    - CA key-compromise cascade (RFC 6960 §2.7): once the CA itself is revoked with a
        compromise reason, every certificate it issued reports `revoked` /
        `cACompromise`, regardless of its own individual state.

- **OCSP server configuration** (new `--ocsp-*` CLI flags and `[ocsp]` TOML section):
    - `--ocsp-enabled` — enable the responder (default `false`; both routes 404 when
        disabled).
    - `--ocsp-ca-uid` — UID of the CA certificate; required when `ocsp_enabled = true`.
    - `--ocsp-responder-cert-uid` — UID of a delegated OCSP-signing certificate.
    - `--ocsp-cache-ttl-secs` — response validity window in seconds (default `86400`
        = 24 h); also used as the in-memory cache TTL.
    - `--ocsp-nonce-policy` — `optional` | `required` | `ignore` (default `optional`).
    - `--ocsp-include-cert-chain` — include the signer certificate chain in
        `BasicResponse`s (default `true`).
    - `--ocsp-archive-cutoff-secs` — archive-cutoff window in seconds (`0` = disabled).

- **`Database::find_certificate_by_serial`** — new method that scans all lifecycle
    states to locate a certificate object by its DER-encoded serial number (hex string).

- **Crypto layer** (`crate/crypto/src/openssl/`):
    - `ocsp_ffi.rs` — raw FFI bindings for the subset of OpenSSL 3.x OCSP C API not yet
        wrapped by the `openssl` crate (`OCSP_basic_add1_status`, `OCSP_basic_sign`,
        `OCSP_basic_add1_nonce`, `OCSP_request_add1_nonce`, `OCSP_check_nonce`, etc.).
    - `ocsp.rs` — safe `build_ocsp_response` builder: constructs a DER-encoded
        `OCSPResponse` from a parsed request, a cert-status record, the signer
        cert/key pair, and nonce + timing parameters.

- **`mise run test:ocsp`** — new external-customer black-box test suite
    (`.mise/tasks/test/ocsp`) that starts a real KMS server, provisions a CA and leaf
    certificates purely through the `ckms` CLI, and drives every scenario through
    standard `openssl ocsp` / `curl` calls (the same tooling a customer would use).
    Wired into `test_all.yml` for both `fips` and `non-fips`.

- **KMIP `Validate`: internal KMS-state cascade for CA-compromise detection.**
    `Validate` now cross-checks every certificate in a submitted chain against its own
    tracked KMS lifecycle state, in addition to the pre-existing CRL check. Any
    certificate the KMS tracks that is not `Active`/`PreActive` anywhere in the chain
    now correctly makes the whole chain `Invalid` — including a compromised
    **self-signed root CA**, which has no CRL Distribution Point of its own and was
    therefore previously undetectable by `Validate` (no external revocation mechanism
    can ever reflect a root CA's own compromise). Works for both UID-supplied and
    raw-bytes-supplied certificate chains.
    - New `Database::find_certificate_state_by_der` — exact-DER-byte-match lookup
        across all certificate lifecycle states, used to resolve internal state for
        raw-bytes-supplied chains.
    - Capped the maximum number of certificates accepted in a single `Validate`
        request (32) to bound the cost of internal-state lookups.

- **`mise run test:pki-revocation`** — new external-customer black-box test suite
    (`.mise/tasks/test/pki-revocation`) validating certificate generation with
    Distribution Point and/or AIA/OCSP responder URLs, and their subsequent
    revocation/compromise detection, across three scenarios: a leaf carrying both a
    CDP and an AIA OCSP URL; a 3-level chain where compromising the intermediate CA
    cascades via CRL; and a 2-level chain where compromising the root CA is caught by
    the new internal-state check with no CRL/OCSP mechanism involved at all. Wired
    into `test_all.yml` for both `fips` and `non-fips`.

- **Documentation**: `documentation/docs/use_cases/pki-revocation.md` now documents the
    OCSP responder (endpoints, configuration, status mapping) and includes a
    copy-pasteable manual verification runbook using `openssl ocsp`. New
    `documentation/docs/use_cases/pki-ocsp.md` page with Mermaid sequence diagrams
    explaining the OCSP protocol flow, delegated-responder trust model, and
    CA-compromise cascade. New "PKI Support" navigation section splitting PKI docs
    into Introduction / Revocation & CRL Distribution / OCSP Responder.

## Security

Hardening fixes identified via an internal threat-model review (STRIDE-A) of this
feature, applied before release — none were exploited in the wild.

- **OCSP responder: unbounded batch requests.** `parse_ocsp_request` had no cap on the
    number of certificate queries (`SingleRequest`/`CertID` entries) accepted in a
    single `OCSPRequest`. Combined with the app-wide 64 MB payload limit, an
    unauthenticated client could submit a single request containing on the order of
    hundreds of thousands of queries, each triggering its own non-indexed,
    six-lifecycle-state database scan. Capped at 128 queries per request, enforced
    before any per-query work is performed.
- **OCSP responder: in-memory response cache defeated under the default
    configuration.** The cache-bypass decision was derived from the *configured*
    nonce policy (`has_nonce = nonce_policy != NoncePolicy::Ignore`) rather than
    whether the specific incoming request actually carried a nonce. Since the
    documented default policy is `optional` (not `ignore`), the cache never activated
    out of the box, forcing a live signing operation on every single request. The
    cache-bypass decision now also checks the actual per-request nonce presence.
- **OCSP responder: stale cached status after CA compromise.** A `good` response
    cached before a CA was marked compromised could continue to be served for up to
    `ocsp_cache_ttl_secs` after the compromise. The cache is now unconditionally
    bypassed once the CA is compromised, and evicted immediately for a specific
    certificate the moment it is revoked (previously only self-corrected via TTL
    expiry).
- **OCSP responder: continued use of an independently-compromised delegated signing
    key.** If a *distinct* delegated responder certificate
    (`--ocsp-responder-cert-uid`) was itself marked compromised, the responder would
    still use it to sign live responses. The responder now refuses to sign in that
    case. (The CA's own key continues to be used for the CA-compromise cascade itself
    — RFC 6960 §2.7 requires the responder to keep truthfully reporting `revoked` for
    every certificate the CA issued once the CA is compromised.)
- **KMIP `Validate`: cross-tenant certificate lifecycle-state disclosure.** The
    raw-bytes certificate path (matching by exact DER bytes) disclosed a matched
    certificate's internal lifecycle state (Active/Compromised/Deactivated/…) to any
    authenticated caller, without checking whether that caller owns (or has a Grant
    on) the underlying object — allowing one tenant to learn another tenant's
    certificate revocation status by supplying its (publicly obtainable) DER bytes.
    The raw-bytes path now enforces the same ownership/Grant permission check the
    UID-based path already relies on before disclosing internal state.

## Fixed

- **Issuer-hash digest algorithm was hardcoded to SHA-256**, causing the responder to
    reject any request whose `CertID` used a different digest (e.g. the SHA-1 default
    used by the standard `openssl ocsp` client) with `unauthorized`, even for a
    perfectly valid request. `verify_issuer_hashes_match_ca` now recomputes the
    reference issuer hash using each query's own `hashAlgorithm`.
- **Nonce extension was triple-wrapped in responses**, causing RFC 9654 nonce
    verification (`OCSP_check_nonce`) to fail in standard clients despite the
    underlying nonce bytes matching. The extension's `extnValue` is now correctly
    unwrapped/re-wrapped exactly once, per the `Nonce ::= OCTET STRING` ASN.1 definition.
- **`nonce_policy = required` returned a raw HTTP 500** (with an HTML body) instead of
    an OCSP `malformedRequest` response when a request carried no nonce, which no
    standard OCSP client can parse as anything but a transport failure. The check now
    runs before response construction and returns a proper unsigned
    `OCSPResponse { malformedRequest }` (RFC 6960 §2.3).
- **Missing `ETag` response header**: RFC 5019 §2.2.6 caching headers were incomplete;
    responses now include a strong `ETag` (SHA-256 of the DER body) alongside
    `Cache-Control`, `Last-Modified`, and `Expires`.
- **Intermittent `unknown` status for a certificate just issued**: `Database`'s
    internal serial-number hex extraction stripped all leading `'0'` characters
    instead of only whole leading zero bytes, desynchronising it from the OCSP
    crypto layer's own hex extraction for ~1-in-16 randomly generated serial numbers
    (any serial whose most-significant remaining byte is `< 0x10`). Fixed to preserve
    the leading zero nibble, matching the canonical form OpenSSL's `BN_bn2hex` produces.

## Changed

- `crate/server_database/Cargo.toml`: added `x509-parser` workspace dependency (used to
    extract the serial number from stored certificate objects).

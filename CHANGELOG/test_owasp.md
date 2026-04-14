# CHANGELOG — test/owasp

## Security

### KMIP Protocol / Parser

- **EXT2-2/A03-2**: Add recursion depth limit (`MAX_TTLV_DEPTH = 64`) to TTLV binary parser to prevent stack-overflow `DoS` via deeply-nested structures; includes unit tests.
- **EXT2-3/A03-3**: Add stack-depth limit (`MAX_XML_STACK_DEPTH = 64`) to TTLV XML deserializer to prevent `DoS` via deeply-nested XML.

### HTTP Server

- **EXT2-1/A04-1**: Reduce HTTP payload size limit from 10 GB to 64 MB (both `PayloadConfig` and `JsonConfig`) to prevent memory exhaustion `DoS`.
- **EXT2-5/A04-2**: Add rate-limiting middleware (`actix-governor`) controlled by `KMS_RATE_LIMIT_PER_SECOND` / `rate_limit_per_second` config field; disabled by default, enabling operators to prevent brute-force and `DoS` attacks.
- **A05-1/A01-1**: Replace `Cors::permissive()` on the main KMIP default scope with `Cors::default()` (same-origin only); enterprise-integration scopes (Google CSE, MS DKE, AWS XKS) intentionally retain permissive CORS as required by their integration contracts.

### Authentication

- **A07-1**: Reject symmetric JWT algorithms (HS256/HS384/HS512) via an explicit asymmetric-only allowlist (`RS*`, `ES*`, `PS*`) checked before `Validation::new(header.alg)`, and explicitly pin `validation.algorithms` to prevent confusion attacks.
- **A07-2**: Replace plain `==` API-token comparison with constant-time `subtle::ConstantTimeEq` to eliminate timing side-channel vulnerability.

### Logging / Credential Masking

- **A09-1**: Mask database URL passwords in `Display` impl of `MainDBConfig` using `mask_db_url_password()` helper (URL-parser-based, with multi-host PostgreSQL fallback).
- **A09-2**: Replace dot-only TLS P12 password masking (`replace('.', '*')`) with a proper `[****]` redaction.

### Audit

- Update `scripts/audit.sh` CORS check to distinguish enterprise-integration scopes (WARN) from main KMIP scope (FAIL), and add JWT algorithm allowlist check that verifies `validation.algorithms` assignment.

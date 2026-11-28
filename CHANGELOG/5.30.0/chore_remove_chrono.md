## Security

### Dependencies
- Remove the unmaintained `chrono` (RUSTSEC-2026-0543) and `humantime` (RUSTSEC-2026-0542) crates from the dependency tree so `cargo deny check` passes without an advisory ignore; `time` replaces `chrono` in `cosmian_kms_crypto` (date anonymization, output format unchanged: numeric UTC offset such as `+00:00`) and `cosmian_kms_server` (JWKS refresh, Google CSE and DKE tokens, AWS secret backend)
- AWS XKS request authentication no longer uses `scratchstack-aws-signature` (which required `chrono`): the `SigV4` header verifier is implemented in `crate/server/src/routes/aws_xks/sigv4.rs` on OpenSSL HMAC-SHA256, validated against the AWS `SigV4` test suite. Stricter than before: duplicate `Authorization` parameters, duplicate or uppercase `SignedHeaders`, signed headers absent from the request and an `x-amz-content-sha256` that differs from the body hash are rejected; presigned (query-string) authentication is rejected
- `cosmian_kms_client` no longer uses `oauth2` (which required `chrono`): the PKCE challenge, `state` and authorization URL of `ckms login oauth` are built locally, with random bytes from `KmsRng`, and the callback `state` is compared in constant time
- The k8s operator parses refresh intervals (`1h`, `30m`, `1h 30m`, `90s`, `500ms`, ...) with a small internal parser instead of `humantime`
- Bump `actix-http` 3.20.3 -> 3.21.3 (RUSTSEC-2026-0552, RUSTSEC-2026-0553, RUSTSEC-2026-0554) and `libz-sys` 1.1.31 -> 1.1.33 (RUSTSEC-2026-0544), with `cargo vet` exemptions

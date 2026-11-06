## Bug Fixes

### Crypto

- Free the OCSP basic response after successful response encoding instead of leaking it on each request.
- Return an error if allocating the requested OCSP signer certificate stack fails instead of silently omitting it.

### HSM

- Serialize PKCS#11 `C_GetInfo` fields without reading uninitialized structure padding; preserve the native layout and zero padding bytes.

## Refactor

### Lint policy

- Remove every clippy suppression from non-test Rust source and deny `allow_attributes` / `allow_attributes_without_reason` workspace-wide; test code uses `#[expect(<lint>, reason = "…")]`. Generated Kubernetes gRPC bindings move to the `cosmian_kms_k8s_plugin_proto` and `cosmian_kms_csi_provider_proto` crates, which carry their own lint tables.
- Box the large `Operation`, `Attribute`, `KeyValue`, batch-item and `ckms` command variants; `from_ttlv` now borrows its `TTLV` argument, `#[kmip_enum]` generates `From<Enum> for u32`, `Database::instantiate` takes a `CacheParams` struct, and `WordMasker::new` is fallible.
- Server configuration structs drop their redundant field-name prefixes; TOML keys, CLI flags and environment variables are unchanged.

### Crypto

- Use existing safe OpenSSL APIs for CRL Number extensions, SCEP CMS construction and attribute OIDs, and OCSP request parsing, digest lookup, certificate stacks, and response serialization.

## Documentation

- Add the `/rust-best-practices` skill (idiomatic Rust baseline adapted from BeautifulRust, MIT) with a non-normative KMS patterns reference, and make `rust.instructions.md` § Clippy and lint suppression the single owner of the zero-suppression policy: zero clippy suppressions in non-test source, tests use `#[expect(<lint>, reason = "…")]`.
- Remove three redundant Rust skills (design patterns, simplification, panic audit): their unique coverage moves to `/rust-best-practices`, `/rust-refactor` (duplication and structural review) and `/kms-caveman [path]` (dedicated panic audit). Consumers in `AGENTS.md`, `CONTRIBUTING.md`, the instructions and the orchestrator skills are migrated.
- Consolidate the Rust review orchestration: `/rust-review-all` runs 9 phases and `/code-quality` 8, the shared orchestrator contract keeps one finding-ownership rule, and reports use an evidence-based schema (`PASS | FAIL | SKIPPED | INCOMPLETE`, verification performed).
- Document the agent decision and verification flow, rule ownership and what is mechanically enforced in `.github/skills/README.md`.

## Testing

- Isolate XML draft and registration vector servers by owner on the `KMS_TEST_DB` backend so unfiltered Locate requests cannot select objects created by unrelated tests.

## CI

- Run `mise run docs:check-ai` (AI-docs validator, including its self-test) in the `build-documentation` job; the validator now also checks skill index rows, routing targets, shared contract phase entries and shell fences.

---
name: kms-test-vector
description: 'Walk through the full KMS test vector creation workflow: directory, manifest.toml, TTLV steps, vector_runner.rs registration, README count. Use when creating test vectors.'
---

# KMS Test Vector Creator

Walk through the complete test vector creation workflow for the Eviden KMS.

## When to Use

- After implementing a new feature or bug fix with behavioral change
- When adding a new KMIP operation
- When adding a negative/error-path test case
- After any change that produces new observable output

**Skip only if** the change is purely refactoring with no behavioral difference and all existing test vectors pass unchanged.

## Step 1 — Determine Vector Category

Find the closest existing vector and create a sibling directory. `ls test_data/vectors/` shows the layout:
`fips/<group>/<name>`, `non-fips/<name>`, `negative/<operation>/<case>`, `hsm/<name>`,
`access_control/<name>`, `kat/..`, `opa/..`, `tls/..`.

```bash
ls test_data/vectors/ test_data/vectors/fips/
```

## Step 2 — Create the Vector Directory

```bash
mkdir -p test_data/vectors/<category>/<vector-name>
```

## Step 3 — Write manifest.toml

Schema: `TestManifest` / `TestStep` in `crate/test_kms_server/src/vector_runner.rs` (read the structs before using an optional field).
Example (`test_data/vectors/fips/symmetric/aes_create_get/manifest.toml`):

```toml
name = "AES-256 Create and Get"
description = "Creates an AES-256 symmetric key and retrieves it via Get"

[[steps]]
operation = "Create"
request = "step1_request.json"
assert_success = true

[steps.capture]
key_id = "UniqueIdentifier"

[[steps]]
operation = "Get"
request = "step2_request.json"
assert_success = true

[steps.assert_fields]
ObjectType = "SymmetricKey"
```

Negative step: `assert_success = false` plus `assert_error_reason = "Object_Not_Found"` or
`assert_error_contains = "already"` (see `test_data/vectors/negative/activate/*/manifest.toml`).

Other optional step fields: `assert_any_field`, `assert_none_field`, `assert_fields_absent`, `assert_count`,
`identity`, `allow_failure`, `capture_nth`, `raw_request`. Optional top-level fields: `backends`, `kmip_version`,
`wire_format`, `server_config`, `server_type`, `identities`, `requires_env`, `requires_hsm_models`.

## Step 4 — Write Request Files

Each request file is the **bare operation payload** (`{"tag": "<Operation>", "value": [...]}`), not a
`RequestMessage` wrapper (unless the step sets `raw_request = true`). Reference:
`test_data/vectors/fips/symmetric/aes_create_get/step1_request.json`:

```json
{
  "tag": "Create",
  "value": [
    {"tag": "ObjectType", "type": "Enumeration", "value": "SymmetricKey"},
    {"tag": "Attributes", "value": [
      {"tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES"},
      {"tag": "CryptographicLength", "type": "Integer", "value": 256}
    ]}
  ]
}
```

Values captured by an earlier step are referenced as `{{key_id}}` (see `step2_request.json` of the same vector).
Source payloads from a similar existing vector — never invent key material or algorithm parameters.
Vectors share one singleton server per backend: never rely on fixed names, tags or UIDs.

## Step 5 — Register in vector_runner.rs

Inside `mod tests` of `crate/test_kms_server/src/vector_runner.rs`, next to the sibling vectors of the same
group, copy a neighbour verbatim (including its `#[cfg(feature = ...)]` attribute — currently `non-fips`):

```rust
#[tokio::test]
async fn test_vec_<name>() -> Result<(), KmsClientError> {
    crate::init_test_logging();
    run_test_vector("test_data/vectors/<path>").await
}
```

## Step 6 — Run and Verify

```bash
# same --features as the neighbouring tests
cargo test -p test_kms_server --features non-fips test_vec_<name>
```

If the test fails: check the request JSON against a passing similar vector, and read
`run_test_vector` in `vector_runner.rs`. Fix any failure before proceeding.

## Step 7 — Update README

`crate/test_kms_server/README.md` is generated: run `mise run docs:sync-vectors` and stage the result.
Never edit it by hand.

The vector lives in the `test_data` submodule: commit it there first, then the gitlink
(see `test-configs.instructions.md` § Submodule workflow).

## Summary Checklist

- [ ] Directory created: `test_data/vectors/<category>/<name>/` (sibling of the closest existing vector)
- [ ] `manifest.toml` written with `name`, `[[steps]]` (`operation`, `request`, `assert_*`, `capture`)
- [ ] Request JSON files are bare payloads sourced from real vectors, using `{{var}}` for captured values
- [ ] `test_vec_<name>` added to `crate/test_kms_server/src/vector_runner.rs` with the neighbours' `cfg`
- [ ] `cargo test -p test_kms_server --features non-fips test_vec_<name>` passes
- [ ] `mise run docs:sync-vectors` run and README staged
- [ ] Vector committed in the `test_data` submodule, then the gitlink

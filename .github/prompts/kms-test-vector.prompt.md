---
agent: agent
description: 'Walk through the full KMS test vector creation workflow: directory, manifest.toml, TTLV steps, vector_runner.rs registration, README count update. Use: /kms-test-vector'
---

# KMS Test Vector Creator

Walk through the complete test vector creation workflow for the Cosmian KMS.

## When to Use

- After implementing a new feature or bug fix with behavioral change
- When adding a new KMIP operation
- When adding a negative/error-path test case
- After any change that produces new observable output

**Skip only if** the change is purely refactoring with no behavioral difference and all existing test vectors pass unchanged.

## Step 1 — Determine Vector Category

Ask the user (or infer from context):

| Change type | Directory |
|-------------|-----------|
| Standard feature / bug fix | `test_data/vectors/<feature-name>/` |
| Negative / error path test | `test_data/vectors/negative/<feature-name>/` |
| HSM-specific behavior | `test_data/vectors/hsm/<hsm-model>/` |
| Non-FIPS-only feature | `test_data/vectors/non-fips/<feature-name>/` |
| Cloud provider integration | `test_data/vectors/<provider>/` |

Check existing vectors to avoid duplication:

```bash
ls test_data/vectors/
```

## Step 2 — Create the Vector Directory

```bash
mkdir -p test_data/vectors/<category>/<vector-name>
```

## Step 3 — Write manifest.toml

Create `test_data/vectors/<category>/<vector-name>/manifest.toml`:

```toml
# Vector manifest for <vector-name>
description = "<What this vector tests — one sentence>"
feature = "fips"          # or "non-fips", "hsm", "interop"
version = "2.1"           # KMIP version: "2.1" or "1.4"

# Steps are executed in order. Each step is a file in this directory.
[[steps]]
name = "01_create_key"
request = "01_create_key_request.json"
response = "01_create_key_response.json"
expected_status = "Success"

[[steps]]
name = "02_get_key"
request = "02_get_key_request.json"
response = "02_get_key_response.json"
expected_status = "Success"

# For negative tests, set expected_status to the expected error:
# expected_status = "InvalidMessage"
# expected_status = "PermissionDenied"
```

## Step 4 — Write TTLV Step Files

Each step needs a request JSON and (optionally) response JSON.

Request files follow the TTLV-over-JSON format used by `crate/kmip/src/`:

```json
{
  "tag": "RequestMessage",
  "value": [
    {
      "tag": "RequestHeader",
      "value": [
        {"tag": "ProtocolVersion", "value": [
          {"tag": "ProtocolVersionMajor", "type": "Integer", "value": 2},
          {"tag": "ProtocolVersionMinor", "type": "Integer", "value": 1}
        ]},
        {"tag": "BatchCount", "type": "Integer", "value": 1}
      ]
    },
    {
      "tag": "BatchItem",
      "value": [
        {"tag": "Operation", "type": "Enumeration", "value": "Create"},
        {"tag": "RequestPayload", "value": [
          // ... operation-specific fields
        ]}
      ]
    }
  ]
}
```

**Source example values from existing test vectors** — never invent key material or algorithm parameters:

```bash
ls test_data/vectors/
cat test_data/vectors/<similar-vector>/<step>.json
```

## Step 5 — Register in vector_runner.rs

Open `crate/test_kms_server/src/vector_runner.rs` and add a new test function:

```rust
#[tokio::test]
async fn test_<vector_name>() {
    run_vector("test_data/vectors/<category>/<vector-name>").await;
}
```

Follow the naming convention of existing tests in that file.

## Step 6 — Run and Verify

```bash
# Run only the new vector
cargo test -p test_kms_server test_<vector_name>
```

If the test fails:

1. Check the error message — does the request JSON have the correct TTLV structure?
2. Compare with a passing similar vector
3. Check `crate/test_kms_server/src/vector_runner.rs` for how vectors are loaded

Fix any failure before proceeding.

## Step 7 — Update README

Open `crate/test_kms_server/README.md`:

1. Add a row to the vector table:

   ```markdown
   | `<category>/<vector-name>` | <KMIP version> | <feature> | <Description> |
   ```

2. Increment the total vector count at the top of the table.

```bash
# Verify the count is accurate
find test_data/vectors -name "manifest.toml" | wc -l
```

## Summary Checklist

- [ ] Directory created: `test_data/vectors/<category>/<name>/`
- [ ] `manifest.toml` written with correct steps and `expected_status`
- [ ] Request JSON files written (sourced from real data, not invented)
- [ ] Response JSON files written (or omitted for negative tests)
- [ ] Test function added to `crate/test_kms_server/src/vector_runner.rs`
- [ ] `cargo test -p test_kms_server test_<name>` passes
- [ ] Row added to `crate/test_kms_server/README.md` + total count updated

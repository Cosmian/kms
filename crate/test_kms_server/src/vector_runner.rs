use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use cosmian_kms_client::{
    KmsClientError,
    cosmian_kmip::ttlv::{KmipFlavor, TTLV, enum_lookup::lookup_enum_code},
};
use serde::Deserialize;

use crate::TestsContext;

/// A test vector manifest loaded from a TOML file.
///
/// Each test vector directory contains a `manifest.toml` and one or more
/// step JSON files (TTLV-JSON request payloads).
///
/// # Example
///
/// ```toml
/// name = "AES Create, Encrypt, Decrypt"
/// description = "Full lifecycle of an AES-256 symmetric key"
/// server_config = "test_data/configs/server/test/auth_plain.toml"
///
/// [[steps]]
/// operation = "Create"
/// request = "step1_request.json"
/// assert_success = true
///
/// [steps.assert_fields]
/// ObjectType = "SymmetricKey"
///
/// [steps.capture]
/// key_id = "UniqueIdentifier"
///
/// [[steps]]
/// operation = "Encrypt"
/// request = "step2_request.json"
/// assert_success = true
///
/// [steps.capture]
/// ciphertext = "Data"
/// ```
#[derive(Debug, Deserialize)]
pub struct TestManifest {
    /// Human-readable name for the test vector
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Path to a TOML server config file (relative to the repo root).
    /// If omitted, defaults to `test_data/configs/server/test/auth_plain.toml`.
    pub server_config: Option<String>,
    /// Wire format: `"json"` (default) or `"binary"`.
    /// When `"binary"`, requests are serialized as TTLV binary bytes, wrapped in a
    /// `RequestMessage` envelope, and sent to `/kmip` with `application/octet-stream`.
    /// Responses are parsed from TTLV binary back to JSON for assertions.
    #[serde(default = "default_json")]
    pub wire_format: String,
    /// KMIP protocol version for binary wire format: `[major, minor]`.
    /// Default is `[2, 1]`. Use `[1, 4]` for KMIP 1.4 integration tests.
    #[serde(default = "default_kmip_version")]
    pub kmip_version: [i32; 2],
    /// Ordered list of KMIP request steps to execute
    pub steps: Vec<TestStep>,
}

/// A single request–response step in a test vector.
#[derive(Debug, Deserialize)]
pub struct TestStep {
    /// KMIP operation name (informational; included in error messages)
    pub operation: String,
    /// Filename of the TTLV-JSON request payload (relative to the vector directory)
    pub request: String,
    /// When `true`, assert that `ResultStatus` == "Success"
    #[serde(default = "default_true")]
    pub assert_success: bool,
    /// Field assertions on the response TTLV.
    /// Keys are TTLV tag names; values are the expected string representations.
    /// The assertion walks the response tree looking for a matching tag and checks
    /// that the leaf value matches the expected string.
    #[serde(default)]
    pub assert_fields: HashMap<String, String>,
    /// Assert that these TTLV tags are **absent** from the response.
    /// Useful to verify fields have been properly removed (e.g. Veeam compatibility).
    #[serde(default)]
    pub assert_fields_absent: Vec<String>,
    /// When `assert_success` is `false`, optionally assert that the error response
    /// contains a specific `ResultReason` value (e.g. `"ItemNotFound"`).
    pub assert_error_reason: Option<String>,
    /// When `assert_success` is `false`, optionally assert that `ResultMessage`
    /// contains this substring.
    pub assert_error_contains: Option<String>,
    /// Values to capture from the response for use in subsequent steps.
    /// Keys are capture variable names (used as `{{name}}` in later request files);
    /// values are the TTLV tag name whose leaf value should be captured.
    #[serde(default)]
    pub capture: HashMap<String, String>,
    /// When `true`, the request JSON file contains a complete `RequestMessage` envelope
    /// (with `RequestHeader`, `BatchItem`(s), etc.) and should be sent as-is without
    /// wrapping. Use this for batched requests (`BatchCount` > 1) or when the request
    /// needs custom header fields (e.g. `Authentication`, `BatchOrderOption`).
    /// Placeholder `{{variable}}` substitution still applies.
    #[serde(default)]
    pub raw_request: bool,
}

const fn default_true() -> bool {
    true
}

fn default_json() -> String {
    "json".to_owned()
}

const fn default_kmip_version() -> [i32; 2] {
    [2, 1]
}

/// Wrap a bare KMIP operation TTLV-JSON in a `RequestMessage` envelope.
///
/// Transforms `{ "tag": "Create", "value": [...] }` into a full
/// `RequestMessage` with `RequestHeader` (protocol version, batch count)
/// and a single `BatchItem` (operation enum + request payload).
fn wrap_in_request_message(
    bare_op_json: &serde_json::Value,
    major: i32,
    minor: i32,
) -> serde_json::Value {
    let tag = bare_op_json
        .get("tag")
        .and_then(|t| t.as_str())
        .unwrap_or("Unknown");
    // Map TTLV tag names to OperationEnumeration variant names
    // (TTLV tags use PascalCase, but some enum variants differ)
    let operation = match tag {
        "Mac" => "MAC",
        "MacVerify" => "MACVerify",
        _ => tag,
    };
    let children = bare_op_json
        .get("value")
        .cloned()
        .unwrap_or(serde_json::json!([]));

    serde_json::json!({
        "tag": "RequestMessage",
        "value": [
            {
                "tag": "RequestHeader",
                "value": [
                    {
                        "tag": "ProtocolVersion",
                        "value": [
                            { "tag": "ProtocolVersionMajor", "type": "Integer", "value": major },
                            { "tag": "ProtocolVersionMinor", "type": "Integer", "value": minor }
                        ]
                    },
                    { "tag": "BatchCount", "type": "Integer", "value": 1 }
                ]
            },
            {
                "tag": "BatchItem",
                "value": [
                    { "tag": "Operation", "type": "Enumeration", "value": operation },
                    {
                        "tag": "RequestPayload",
                        "value": children
                    }
                ]
            }
        ]
    })
}

/// Send a binary TTLV request and return the response as JSON.
///
/// Converts TTLV-JSON → TTLV struct → binary bytes, POSTs to `/kmip`
/// with `application/octet-stream`, then parses the response binary
/// back to TTLV → JSON for assertion.
///
/// When `raw_request` is `true`, `request_json` is already a complete
/// `RequestMessage` and will not be wrapped in an envelope.
async fn send_binary_request(
    client: &cosmian_kms_client::KmsClient,
    binary_url: &str,
    request_json: &serde_json::Value,
    kmip_version: [i32; 2],
    step_index: usize,
    step_operation: &str,
    raw_request: bool,
) -> Result<serde_json::Value, KmsClientError> {
    let kmip_flavor = if kmip_version[0] == 1 {
        KmipFlavor::Kmip1
    } else {
        KmipFlavor::Kmip2
    };

    // Wrap bare operation in RequestMessage envelope, or use as-is for raw requests
    let request_message = if raw_request {
        request_json.clone()
    } else {
        wrap_in_request_message(request_json, kmip_version[0], kmip_version[1])
    };

    // JSON → TTLV struct
    let mut request_ttlv: TTLV = serde_json::from_value(request_message).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': failed to parse TTLV JSON: {e}"
        ))
    })?;

    // Resolve enum names (e.g. "Create", "AES") to their numeric KMIP codes.
    // JSON deserialization sets enum `value` to 0 with only the `name` populated;
    // the binary serializer requires the numeric `value`.
    request_ttlv.resolve_enumeration_values();

    // TTLV struct → binary bytes
    let request_bytes = request_ttlv.to_bytes(kmip_flavor).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': failed to serialize TTLV to binary: {e}"
        ))
    })?;

    // POST binary
    let response = client
        .client
        .client
        .post(binary_url)
        .header("Content-Type", "application/octet-stream")
        .body(request_bytes)
        .send()
        .await
        .map_err(|e| {
            KmsClientError::UnexpectedError(format!(
                "Step {step_index} '{step_operation}': HTTP request failed: {e}"
            ))
        })?;

    let response_bytes = response.bytes().await.map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': cannot read response body: {e}"
        ))
    })?;

    // binary bytes → TTLV struct → JSON
    if response_bytes.is_empty() {
        return Err(KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': empty binary response"
        )));
    }

    let response_ttlv = TTLV::from_bytes(&response_bytes, kmip_flavor).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': failed to parse binary TTLV response: {e}"
        ))
    })?;

    let response_json = serde_json::to_value(&response_ttlv).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': failed to convert TTLV response to JSON: {e}"
        ))
    })?;

    Ok(response_json)
}

/// Load a test vector manifest from a TOML file.
pub fn load_manifest(manifest_path: &Path) -> Result<TestManifest, KmsClientError> {
    let content = std::fs::read_to_string(manifest_path).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot read test vector manifest at {}: {e}",
            manifest_path.display()
        ))
    })?;
    toml::from_str(&content).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot parse test vector manifest at {}: {e}",
            manifest_path.display()
        ))
    })
}

/// Load a TTLV-JSON request payload, substituting `{{variable}}` placeholders
/// with captured values from previous steps.
fn load_request_json(
    path: &Path,
    captures: &HashMap<String, String>,
) -> Result<serde_json::Value, KmsClientError> {
    let mut content = std::fs::read_to_string(path).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot read request JSON at {}: {e}",
            path.display()
        ))
    })?;

    // Substitute all {{variable}} placeholders
    for (name, value) in captures {
        content = content.replace(&format!("{{{{{name}}}}}"), value);
    }

    serde_json::from_str(&content).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot parse request JSON at {} (after placeholder substitution): {e}",
            path.display()
        ))
    })
}

/// Find a leaf value in a TTLV JSON tree by tag name.
///
/// Walks the tree depth-first, returning the first leaf whose `"tag"` matches.
/// For structures (arrays), descends into children.
fn find_field_in_json(value: &serde_json::Value, tag: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            // Check if this node matches the tag
            if let Some(serde_json::Value::String(t)) = map.get("tag") {
                if t == tag {
                    // Return the "value" field as a string
                    if let Some(v) = map.get("value") {
                        return match v {
                            serde_json::Value::String(s) => Some(s.clone()),
                            serde_json::Value::Number(n) => Some(n.to_string()),
                            serde_json::Value::Bool(b) => Some(b.to_string()),
                            serde_json::Value::Array(_) => None, // Structure node, not a leaf
                            _ => Some(v.to_string()),
                        };
                    }
                }
            }
            // Descend into the "value" field if it's an array (Structure)
            if let Some(serde_json::Value::Array(children)) = map.get("value") {
                for child in children {
                    if let Some(found) = find_field_in_json(child, tag) {
                        return Some(found);
                    }
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = find_field_in_json(item, tag) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

/// Assert that a response TTLV JSON contains the expected field values.
fn assert_response_fields(
    response: &serde_json::Value,
    assertions: &HashMap<String, String>,
    step_operation: &str,
) -> Result<(), KmsClientError> {
    for (tag, expected) in assertions {
        let actual = find_field_in_json(response, tag).ok_or_else(|| {
            KmsClientError::UnexpectedError(format!(
                "Step '{step_operation}': expected field '{tag}' not found in response"
            ))
        })?;
        if actual != *expected {
            // Binary TTLV responses encode enumerations as hex (e.g. "0x00000002").
            // If the expected value is a known enum name, resolve it and compare
            // against the hex form.
            let matches_via_enum = actual.starts_with("0x")
                && lookup_enum_code(expected)
                    .is_some_and(|(code, _)| actual == format!("0x{code:08X}"));
            if !matches_via_enum {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step '{step_operation}': field '{tag}' expected '{expected}', got '{actual}'"
                )));
            }
        }
    }
    Ok(())
}

/// Assert that the response indicates success.
///
/// For `ResponseMessage` envelopes, checks `ResultStatus` == "Success".
/// For bare operation responses (e.g. `CreateResponse`), HTTP 200 is sufficient
/// — this function is a no-op when `ResultStatus` is absent (the HTTP check
/// is handled by the caller).
fn assert_success(
    response: &serde_json::Value,
    step_operation: &str,
) -> Result<(), KmsClientError> {
    // If there is a ResultStatus field, verify it is "Success".
    // If not (bare operation response), the HTTP 200 status already confirms success.
    let result_status = find_field_in_json(response, "ResultStatus");
    match result_status.as_deref() {
        Some("Success" | "0x00000000") | None => Ok(()),
        Some(other) => {
            // Also extract ResultMessage if available
            let msg = find_field_in_json(response, "ResultMessage")
                .unwrap_or_else(|| "(no message)".to_owned());
            Err(KmsClientError::UnexpectedError(format!(
                "Step '{step_operation}': expected success, got ResultStatus='{other}', \
                 ResultMessage='{msg}'"
            )))
        }
    }
}

/// Assert that ALL `ResultStatus` fields in a batched response indicate success.
///
/// For raw (batched) requests, the response contains multiple `BatchItem` entries,
/// each with their own `ResultStatus`. This function walks the entire tree and
/// verifies that every `ResultStatus` found equals `"Success"` or `"0x00000000"`.
fn assert_all_success(
    response: &serde_json::Value,
    step_operation: &str,
) -> Result<(), KmsClientError> {
    fn collect_result_statuses(value: &serde_json::Value, results: &mut Vec<(String, String)>) {
        match value {
            serde_json::Value::Object(map) => {
                if let Some(serde_json::Value::String(tag)) = map.get("tag") {
                    if tag == "ResultStatus" {
                        if let Some(v) = map.get("value") {
                            let status = match v {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                _ => v.to_string(),
                            };
                            // Try to find the associated ResultMessage in siblings
                            results.push((status, String::new()));
                            return;
                        }
                    }
                }
                if let Some(serde_json::Value::Array(children)) = map.get("value") {
                    for child in children {
                        collect_result_statuses(child, results);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    collect_result_statuses(item, results);
                }
            }
            _ => {}
        }
    }

    let mut statuses = Vec::new();
    collect_result_statuses(response, &mut statuses);

    for (idx, (status, _)) in statuses.iter().enumerate() {
        if status != "Success" && status != "0x00000000" {
            return Err(KmsClientError::UnexpectedError(format!(
                "Step '{step_operation}': batch item {idx} expected success, \
                 got ResultStatus='{status}'"
            )));
        }
    }

    if statuses.is_empty() {
        // No ResultStatus found at all — same as assert_success: accept it
        // (HTTP 200 is sufficient).
    }

    Ok(())
}

/// Capture values from a response TTLV JSON for use in subsequent steps.
fn capture_values(
    response: &serde_json::Value,
    capture_rules: &HashMap<String, String>,
    captures: &mut HashMap<String, String>,
    step_operation: &str,
) -> Result<(), KmsClientError> {
    for (var_name, tag) in capture_rules {
        let value = find_field_in_json(response, tag).ok_or_else(|| {
            KmsClientError::UnexpectedError(format!(
                "Step '{step_operation}': cannot capture '{var_name}': \
                 tag '{tag}' not found in response"
            ))
        })?;
        captures.insert(var_name.clone(), value);
    }
    Ok(())
}

/// Resolve a path relative to the repository root (two levels up from `CARGO_MANIFEST_DIR`).
fn repo_root() -> Result<PathBuf, KmsClientError> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            KmsClientError::UnexpectedError(
                "cannot resolve repo root from CARGO_MANIFEST_DIR".to_owned(),
            )
        })
}

/// Run a test vector from a directory containing `manifest.toml` and step JSON files.
///
/// This is the main entry point for vector-based regression tests. It:
/// 1. Loads the manifest
/// 2. Starts an isolated KMS server from the specified (or default) TOML config
/// 3. Executes each step sequentially: load request JSON, substitute captured
///    placeholders, POST to `/kmip/2_1`, assert response, capture values
/// 4. Stops the server
///
/// # Arguments
/// * `vector_dir` — Path to the test vector directory (relative to the repo root),
///   e.g. `test_data/vectors/fips/symmetric/aes_create_encrypt_decrypt`
///
/// # Errors
/// Returns an error on any failure (assertion, network, parse error).
pub async fn run_test_vector(vector_dir: &str) -> Result<(), KmsClientError> {
    let root = repo_root()?;
    let vector_path = root.join(vector_dir);

    // Load manifest
    let manifest_path = vector_path.join("manifest.toml");
    let manifest = load_manifest(&manifest_path)?;

    // Resolve server config
    let config_path = manifest.server_config.as_ref().map_or_else(
        || root.join("test_data/configs/server/test/auth_plain.toml"),
        |cfg| root.join(cfg),
    );

    // Start an isolated server
    let context = crate::start_test_server_from_toml(&config_path).await?;

    let result = execute_steps(&context, &manifest, &vector_path).await;

    // Always stop the server, even if steps failed
    context.stop_server().await?;

    // Propagate step errors after cleanup
    result
}

/// Run a test vector against a pre-existing (shared) server context.
///
/// Same as [`run_test_vector`] but reuses an already-running server, which is
/// useful for tests that share a `OnceCell<TestsContext>` server instance.
///
/// # Errors
/// Returns an error on any failure (assertion, network, parse error).
pub async fn run_test_vector_with_context(
    vector_dir: &str,
    context: &TestsContext,
) -> Result<(), KmsClientError> {
    let root = repo_root()?;
    let vector_path = root.join(vector_dir);

    let manifest_path = vector_path.join("manifest.toml");
    let manifest = load_manifest(&manifest_path)?;

    execute_steps(context, &manifest, &vector_path).await
}

/// Execute the steps of a test vector against a running server.
async fn execute_steps(
    context: &TestsContext,
    manifest: &TestManifest,
    vector_path: &Path,
) -> Result<(), KmsClientError> {
    let client = context.get_owner_client();
    let base_url = context
        .owner_client_config
        .http_config
        .server_url
        .trim_end_matches('/')
        .to_owned();

    let is_binary = manifest.wire_format == "binary";
    let json_url = format!("{base_url}/kmip/2_1");
    let binary_url = format!("{base_url}/kmip");

    let mut captures: HashMap<String, String> = HashMap::new();

    for (i, step) in manifest.steps.iter().enumerate() {
        let request_path = vector_path.join(&step.request);
        let request_json = load_request_json(&request_path, &captures)?;

        // Send the request via JSON or binary wire format.
        // When `raw_request` is true, the JSON is already a complete RequestMessage;
        // otherwise, wrap the bare operation in a standard KMIP RequestMessage envelope.
        let (http_success, response_json) = if is_binary {
            // Binary: always HTTP 200; success/failure is in ResultStatus
            let json = send_binary_request(
                &client,
                &binary_url,
                &request_json,
                manifest.kmip_version,
                i,
                &step.operation,
                step.raw_request,
            )
            .await?;
            (true, json)
        } else {
            // JSON wire format: wrap or use as-is depending on raw_request
            let request_message = if step.raw_request {
                request_json.clone()
            } else {
                wrap_in_request_message(
                    &request_json,
                    manifest.kmip_version[0],
                    manifest.kmip_version[1],
                )
            };

            // POST the wrapped JSON TTLV to the KMIP /kmip/2_1 endpoint
            let send_result = client
                .client
                .client
                .post(&json_url)
                .json(&request_message)
                .send()
                .await;

            match send_result {
                Ok(response) => {
                    let status = response.status();
                    let response_text = response.text().await.map_err(|e| {
                        KmsClientError::UnexpectedError(format!(
                            "Step {i} '{}': cannot read response body: {e}",
                            step.operation
                        ))
                    })?;

                    // Try to parse as JSON; for non-JSON error responses, create
                    // a synthetic JSON
                    let response_json: serde_json::Value =
                        serde_json::from_str(&response_text).unwrap_or_else(|_| {
                            serde_json::json!({
                                "tag": "ErrorResponse",
                                "value": [
                                    { "tag": "ResultStatus", "type": "Enumeration", "value": "OperationFailed" },
                                    { "tag": "ResultMessage", "type": "TextString", "value": response_text }
                                ]
                            })
                        });

                    (status.is_success(), response_json)
                }
                Err(e) => {
                    // Transport-level failure (server crash, connection reset,
                    // etc.). When assert_success is false, treat it as an
                    // expected failure and continue.
                    if !step.assert_success {
                        eprintln!(
                            "Step {i} '{}': transport error (expected failure): {e}",
                            step.operation
                        );
                        continue;
                    }
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step {i} '{}': HTTP request failed: {e}",
                        step.operation
                    )));
                }
            }
        };

        // Optionally record the response for debugging / capture mode
        if std::env::var("RECORD_VECTORS").is_ok() {
            let response_path = vector_path.join(format!("step{}_response.json", i + 1));
            if let Ok(pretty) = serde_json::to_string_pretty(&response_json) {
                drop(std::fs::write(&response_path, pretty));
            }
        }

        if step.assert_success {
            // Expect success: HTTP 2xx and ResultStatus == Success
            if !http_success {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {i} '{}': HTTP error — body: {}",
                    step.operation,
                    serde_json::to_string_pretty(&response_json).unwrap_or_default()
                )));
            }
            // For raw (batched) requests, verify ALL ResultStatus fields succeed
            if step.raw_request {
                assert_all_success(&response_json, &step.operation)?;
            } else {
                assert_success(&response_json, &step.operation)?;
            }
        } else {
            // Expect failure: HTTP non-2xx or ResultStatus != Success
            if http_success {
                let result_status = find_field_in_json(&response_json, "ResultStatus");
                if result_status.as_deref() == Some("Success")
                    || result_status.as_deref() == Some("0x00000000")
                {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step {i} '{}': expected failure but got success",
                        step.operation
                    )));
                }
            }

            // Optionally check the specific error reason
            if let Some(expected_reason) = &step.assert_error_reason {
                let actual_reason =
                    find_field_in_json(&response_json, "ResultReason").unwrap_or_default();
                if actual_reason != *expected_reason {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step {i} '{}': expected ResultReason='{expected_reason}', \
                         got '{actual_reason}'",
                        step.operation
                    )));
                }
            }

            // Optionally check that the error message contains a substring
            if let Some(expected_substr) = &step.assert_error_contains {
                let actual_msg =
                    find_field_in_json(&response_json, "ResultMessage").unwrap_or_default();
                if !actual_msg.contains(expected_substr.as_str()) {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step {i} '{}': expected ResultMessage to contain \
                         '{expected_substr}', got '{actual_msg}'",
                        step.operation
                    )));
                }
            }

            // Expected failure — skip further assertions and captures
            continue;
        }

        // Assert specific fields (substitute captured variables in expected values)
        if !step.assert_fields.is_empty() {
            let resolved: HashMap<String, String> = step
                .assert_fields
                .iter()
                .map(|(k, v)| {
                    let resolved_v = captures.iter().fold(v.clone(), |acc, (name, val)| {
                        acc.replace(&format!("{{{{{name}}}}}"), val)
                    });
                    (k.clone(), resolved_v)
                })
                .collect();
            assert_response_fields(&response_json, &resolved, &step.operation)?;
        }

        // Assert that certain fields are absent
        for absent_tag in &step.assert_fields_absent {
            if find_field_in_json(&response_json, absent_tag).is_some() {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {i} '{}': field '{absent_tag}' should be absent but was found \
                     in response",
                    step.operation
                )));
            }
        }

        // Capture values for subsequent steps
        if !step.capture.is_empty() {
            capture_values(
                &response_json,
                &step.capture,
                &mut captures,
                &step.operation,
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::assertions_on_result_states
)]
mod tests {
    use super::*;

    #[test]
    fn test_find_field_in_json() {
        let json = serde_json::json!({
            "tag": "ResponseMessage",
            "value": [
                {
                    "tag": "ResponseHeader",
                    "value": [
                        {
                            "tag": "ProtocolVersion",
                            "value": [
                                { "tag": "ProtocolVersionMajor", "type": "Integer", "value": 2 },
                                { "tag": "ProtocolVersionMinor", "type": "Integer", "value": 1 }
                            ]
                        },
                        { "tag": "BatchCount", "type": "Integer", "value": 1 }
                    ]
                },
                {
                    "tag": "BatchItem",
                    "value": [
                        { "tag": "Operation", "type": "Enumeration", "value": "Create" },
                        { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
                        { "tag": "UniqueIdentifier", "type": "TextString", "value": "abc-123" }
                    ]
                }
            ]
        });

        assert_eq!(
            find_field_in_json(&json, "UniqueIdentifier"),
            Some("abc-123".to_owned())
        );
        assert_eq!(
            find_field_in_json(&json, "ResultStatus"),
            Some("Success".to_owned())
        );
        assert_eq!(
            find_field_in_json(&json, "BatchCount"),
            Some("1".to_owned())
        );
        assert_eq!(find_field_in_json(&json, "NonExistent"), None);
    }

    #[test]
    fn test_substitute_placeholders() {
        let dir = std::env::temp_dir().join("test_vector_placeholder");
        std::fs::create_dir_all(&dir).unwrap();

        let request_content = r#"{
            "tag": "RequestMessage",
            "value": [
                {
                    "tag": "UniqueIdentifier",
                    "type": "TextString",
                    "value": "{{key_id}}"
                }
            ]
        }"#;
        let request_path = dir.join("request.json");
        std::fs::write(&request_path, request_content).unwrap();

        let mut captures = HashMap::new();
        captures.insert("key_id".to_owned(), "my-unique-id-123".to_owned());

        let json = load_request_json(&request_path, &captures).unwrap();
        assert_eq!(json["value"][0]["value"].as_str(), Some("my-unique-id-123"));

        // Cleanup
        drop(std::fs::remove_dir_all(&dir));
    }

    #[test]
    fn test_assert_success_ok() {
        let response = serde_json::json!({
            "tag": "ResponseMessage",
            "value": [{
                "tag": "BatchItem",
                "value": [
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" }
                ]
            }]
        });
        assert!(assert_success(&response, "test_op").is_ok());
    }

    #[test]
    fn test_assert_success_fail() {
        let response = serde_json::json!({
            "tag": "ResponseMessage",
            "value": [{
                "tag": "BatchItem",
                "value": [
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "OperationFailed" },
                    { "tag": "ResultMessage", "type": "TextString", "value": "Key not found" }
                ]
            }]
        });
        let err = assert_success(&response, "test_op").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("OperationFailed"), "Error: {msg}");
        assert!(msg.contains("Key not found"), "Error: {msg}");
    }

    #[test]
    fn test_capture_values() {
        let response = serde_json::json!({
            "tag": "ResponseMessage",
            "value": [{
                "tag": "BatchItem",
                "value": [
                    { "tag": "ResultStatus", "type": "Enumeration", "value": "Success" },
                    { "tag": "UniqueIdentifier", "type": "TextString", "value": "id-456" }
                ]
            }]
        });

        let mut capture_rules = HashMap::new();
        capture_rules.insert("key_id".to_owned(), "UniqueIdentifier".to_owned());

        let mut captures = HashMap::new();
        capture_values(&response, &capture_rules, &mut captures, "Create").unwrap();

        assert_eq!(captures.get("key_id"), Some(&"id-456".to_owned()));
    }

    #[test]
    fn test_load_manifest() {
        let dir = std::env::temp_dir().join("test_vector_manifest");
        std::fs::create_dir_all(&dir).unwrap();

        let manifest_content = r#"
name = "Test Vector Example"
description = "A simple test"

[[steps]]
operation = "Create"
request = "step1_request.json"
assert_success = true

[steps.capture]
key_id = "UniqueIdentifier"

[[steps]]
operation = "Get"
request = "step2_request.json"

[steps.assert_fields]
ObjectType = "SymmetricKey"
"#;
        let manifest_path = dir.join("manifest.toml");
        std::fs::write(&manifest_path, manifest_content).unwrap();

        let manifest = load_manifest(&manifest_path).unwrap();
        assert_eq!(manifest.name, "Test Vector Example");
        assert_eq!(manifest.steps.len(), 2);
        assert_eq!(manifest.steps[0].operation, "Create");
        assert!(manifest.steps[0].assert_success);
        assert_eq!(
            manifest.steps[0].capture.get("key_id"),
            Some(&"UniqueIdentifier".to_owned())
        );
        assert_eq!(manifest.steps[1].operation, "Get");
        assert_eq!(
            manifest.steps[1].assert_fields.get("ObjectType"),
            Some(&"SymmetricKey".to_owned())
        );
        // assert_success defaults to true
        assert!(manifest.steps[1].assert_success);
        assert!(manifest.server_config.is_none());

        // Cleanup
        drop(std::fs::remove_dir_all(&dir));
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes_create_get() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes_create_get").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa_create_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa_create_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ec_p256_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ec_p256_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_derive_key_pbkdf2() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/derive_key_pbkdf2").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_destroy_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/destroy").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_locate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/locate").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_revoke_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/access_control/revoke").await
    }

    // ── New: Parametric key-size variants ─────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes128_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes128_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa4096_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa4096_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ec_p384_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ec_p384_sign_verify").await
    }

    // ── New: KMIP operations coverage ─────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_mac_and_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/mac_and_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_hash_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha256").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rng_retrieve() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rng_retrieve").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_check() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/check").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_activate_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/activate").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_query() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/query").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_attribute_management() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/attribute_management").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_register_export() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/register_export").await
    }

    // ── Integration vectors ───────────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_synology_dsm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/synology_dsm").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_veeam() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/veeam").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_vmware_vcenter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/vmware_vcenter").await
    }

    // ── New KMIP operation vectors ────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_discover_versions() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/discover_versions").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_get_attributes() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/get_attributes").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_get_attribute_list() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/get_attribute_list").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_import_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/import_key").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rng_seed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rng_seed").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_certify_validate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/certify_validate").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_secret_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/secret_data").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_opaque_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/opaque_data").await
    }

    // ── Encryption coverage: symmetric modes ──────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes256_cbc_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_cbc_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes128_cbc_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes128_cbc_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes256_gcm_siv_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_gcm_siv_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_chacha20_poly1305_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/chacha20_poly1305_encrypt_decrypt").await
    }

    // ── Signature coverage: curves and padding schemes ────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ec_p521_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ec_p521_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pkcs1v15_sha256_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pkcs1v15_sha256_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pss_sha256_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pss_sha256_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pss_sha384_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pss_sha384_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pss_sha512_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pss_sha512_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_eddsa_ed25519_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/eddsa_ed25519_sign").await
    }

    // ── Encrypt coverage: key sizes ───────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes192_gcm_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes192_gcm_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes192_cbc_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes192_cbc_encrypt_decrypt").await
    }

    // ── Encrypt coverage: ECB mode (no nonce, no tag) ─────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes128_ecb_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes128_ecb_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes256_ecb_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_ecb_encrypt_decrypt").await
    }

    // ── Encrypt coverage: AAD and non-FIPS SIV ───────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes256_gcm_aad_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_gcm_aad_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes128_gcm_siv_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes128_gcm_siv_encrypt_decrypt").await
    }

    // ── Encrypt coverage: RSA OAEP hash variants and PKCS#1v15 ──────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_oaep_sha384_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_oaep_sha384_encrypt_decrypt")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_oaep_sha512_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_oaep_sha512_encrypt_decrypt")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pkcs1v15_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pkcs1v15_encrypt_decrypt").await
    }

    // ── Dynamic vectors: KMIP operations (hash, MAC, derive key) ──────────

    #[tokio::test]
    async fn test_vec_hash_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha384").await
    }

    #[tokio::test]
    async fn test_vec_hash_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha512").await
    }

    #[tokio::test]
    async fn test_vec_hash_sha3_256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha3_256").await
    }

    #[tokio::test]
    async fn test_vec_hash_sha3_384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha3_384").await
    }

    #[tokio::test]
    async fn test_vec_hash_sha3_512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/hash_sha3_512").await
    }

    #[tokio::test]
    async fn test_vec_mac_hmac_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/mac_hmac_sha384").await
    }

    #[tokio::test]
    async fn test_vec_mac_hmac_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/mac_hmac_sha512").await
    }

    #[tokio::test]
    async fn test_vec_mac_hmac_sha3_256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/mac_hmac_sha3_256").await
    }

    #[tokio::test]
    async fn test_vec_derive_key_pbkdf2_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/derive_key_pbkdf2_sha512").await
    }

    #[tokio::test]
    async fn test_vec_derive_key_hkdf() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/derive_key_hkdf").await
    }

    // ── Dynamic vectors: symmetric ────────────────────────────────────────

    #[tokio::test]
    async fn test_vec_aes192_ecb_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes192_ecb_encrypt_decrypt").await
    }

    #[tokio::test]
    async fn test_vec_aes256_cbc_no_padding_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_cbc_no_padding_encrypt_decrypt")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes128_xts_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes128_xts_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_aes256_xts_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/aes256_xts_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_chacha20_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/symmetric/chacha20_encrypt_decrypt").await
    }

    // ── Dynamic vectors: asymmetric ───────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_eddsa_ed448_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/eddsa_ed448_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ec_k256_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ec_k256_sign_verify").await
    }

    #[tokio::test]
    async fn test_vec_rsa4096_pss_sha256_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa4096_pss_sha256_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_pss_sha1_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_pss_sha1_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ec_p256_ecies_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ec_p256_ecies_encrypt_decrypt").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rsa2048_aes_key_wrap() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/rsa2048_aes_key_wrap").await
    }

    // ── Dynamic vectors: PQC ──────────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_dsa_44_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_dsa_44_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_dsa_65_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_dsa_65_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_dsa_87_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_dsa_87_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_kem_512_encap_decap() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_kem_512_encap_decap").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_kem_768_encap_decap() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_kem_768_encap_decap").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_kem_1024_encap_decap() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_kem_1024_encap_decap").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_128s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_128s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_128f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_128f_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_192s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_192s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_192f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_192f_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_256s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_256s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_sha2_256f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_sha2_256f_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_128s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_128s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_128f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_128f_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_192s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_192s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_192f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_192f_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_256s_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_256s_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_slh_dsa_shake_256f_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/slh_dsa_shake_256f_sign_verify").await
    }

    // ── KAT vectors: hash ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_kat_hash_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha256").await
    }

    #[tokio::test]
    async fn test_kat_hash_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha384").await
    }

    #[tokio::test]
    async fn test_kat_hash_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha512").await
    }

    #[tokio::test]
    async fn test_kat_hash_sha3_256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha3_256").await
    }

    #[tokio::test]
    async fn test_kat_hash_sha3_384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha3_384").await
    }

    #[tokio::test]
    async fn test_kat_hash_sha3_512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/hash/sha3_512").await
    }

    // ── KAT vectors: MAC ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_kat_mac_hmac_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha256").await
    }

    #[tokio::test]
    async fn test_kat_mac_hmac_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha384").await
    }

    #[tokio::test]
    async fn test_kat_mac_hmac_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha512").await
    }

    #[tokio::test]
    async fn test_kat_mac_hmac_sha3_256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha3_256").await
    }

    // ── KAT vectors: symmetric encryption ────────────────────────────────

    #[tokio::test]
    async fn test_kat_sym_aes128_ecb() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes128_ecb").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes192_ecb() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes192_ecb").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes256_ecb() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes256_ecb").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes128_cbc() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes128_cbc").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes192_cbc() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes192_cbc").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes256_cbc() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes256_cbc").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes128_gcm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes128_gcm").await
    }

    #[tokio::test]
    async fn test_kat_sym_aes256_gcm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes256_gcm").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_chacha20_poly1305() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/chacha20_poly1305").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_chacha20_pure() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/chacha20_pure").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_aes128_xts() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes128_xts").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_aes256_xts() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes256_xts").await
    }

    // ── KAT vectors: key derivation ───────────────────────────────────────

    #[tokio::test]
    async fn test_kat_derive_key_hkdf_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/hkdf_sha256").await
    }

    #[tokio::test]
    async fn test_kat_derive_key_pbkdf2_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/pbkdf2_sha256").await
    }

    // ── KAT vectors: MAC (new) ────────────────────────────────────────────

    #[tokio::test]
    async fn test_kat_mac_hmac_sha3_384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha3_384").await
    }

    #[tokio::test]
    async fn test_kat_mac_hmac_sha3_512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha3_512").await
    }

    #[tokio::test]
    async fn test_kat_mac_hmac_sha1() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/mac/hmac_sha1").await
    }

    // ── KAT vectors: symmetric (new) ─────────────────────────────────────

    #[tokio::test]
    async fn test_kat_sym_aes192_gcm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes192_gcm").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc3394_aes128_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc3394_aes128_kek").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc3394_aes192_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc3394_aes192_kek").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc3394_aes256_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc3394_aes256_kek").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc5649_aes128_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc5649_aes128_kek").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc5649_aes192_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc5649_aes192_kek").await
    }

    #[tokio::test]
    async fn test_kat_sym_rfc5649_aes256_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/rfc5649_aes256_kek").await
    }

    // ── KAT vectors: key derivation (new) ────────────────────────────────

    #[tokio::test]
    async fn test_kat_derive_key_hkdf_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/hkdf_sha384").await
    }

    #[tokio::test]
    async fn test_kat_derive_key_hkdf_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/hkdf_sha512").await
    }

    #[tokio::test]
    async fn test_kat_derive_key_pbkdf2_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/pbkdf2_sha384").await
    }

    #[tokio::test]
    async fn test_kat_derive_key_pbkdf2_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/derive_key/pbkdf2_sha512").await
    }

    // ── KAT vectors: asymmetric (new) ────────────────────────────────────

    #[tokio::test]
    async fn test_kat_asym_ed25519_eddsa_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/asymmetric/ed25519_eddsa_sign").await
    }

    #[tokio::test]
    async fn test_kat_asym_rsa2048_oaep_sha256_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/asymmetric/rsa2048_oaep_sha256_decrypt").await
    }

    // ── TLS transport vectors ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_tls_server_tls() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/tls/server_tls").await
    }

    #[tokio::test]
    async fn test_tls_mtls() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/tls/mtls").await
    }

    // ── Integration vectors: FIPS ─────────────────────────────────────────

    #[tokio::test]
    async fn test_integration_mysql() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/mysql").await
    }

    #[tokio::test]
    async fn test_integration_percona() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/percona").await
    }

    #[tokio::test]
    async fn test_integration_fortigate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate").await
    }

    #[tokio::test]
    async fn test_integration_synology_dsm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/synology_dsm").await
    }

    #[tokio::test]
    async fn test_integration_veeam() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/veeam").await
    }

    #[tokio::test]
    async fn test_integration_vast_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/vast_data").await
    }

    #[tokio::test]
    async fn test_integration_vmware_vcenter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/vmware_vcenter").await
    }

    // ── Integration vectors: non-FIPS ─────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_integration_mongodb() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/integrations/mongodb").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_integration_pykmip() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/integrations/pykmip").await
    }

    // ── KAT vectors: non-FIPS symmetric ──────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_aes128_gcm_siv() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes128_gcm_siv").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_sym_aes256_gcm_siv() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/symmetric/aes256_gcm_siv").await
    }

    // ── KAT vectors: non-FIPS asymmetric ─────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_asym_ed448_eddsa_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/asymmetric/ed448_eddsa_sign").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_asym_secp256k1_ecdsa_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/asymmetric/secp256k1_ecdsa_sign").await
    }

    // ── KAT vectors: non-FIPS Covercrypt ─────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_kat_covercrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/covercrypt_decrypt").await
    }

    // ── non-FIPS: CryptographicParameters coverage ───────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_aes128_gcm_siv_with_explicit_nonce() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/aes128_gcm_siv_with_explicit_nonce").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_aes256_gcm_siv_with_explicit_nonce() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/aes256_gcm_siv_with_explicit_nonce").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_aes128_gcm_siv_with_aad() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/aes128_gcm_siv_with_aad").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_aes256_gcm_siv_with_aad() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/aes256_gcm_siv_with_aad").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_chacha20_server_generated_nonce() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/chacha20_server_generated_nonce").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_chacha20_with_explicit_cryptographic_params()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/chacha20_with_explicit_cryptographic_params")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_chacha20_poly1305_with_explicit_nonce() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/chacha20_poly1305_with_explicit_nonce").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_non_fips_cp_chacha20_poly1305_with_aad() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/chacha20_poly1305_with_aad").await
    }

    // ── Negative tests: protocol-level ───────────────────────────────────

    #[tokio::test]
    async fn test_neg_empty_request() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/empty_request").await
    }

    #[tokio::test]
    async fn test_neg_missing_data_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/missing_data_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_missing_data_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/missing_data_decrypt").await
    }

    #[tokio::test]
    async fn test_neg_missing_uid_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/missing_uid_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_nonexistent_key_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/nonexistent_key_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_nonexistent_key_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/nonexistent_key_decrypt").await
    }

    #[tokio::test]
    async fn test_neg_wrong_key_type_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/wrong_key_type_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_destroy_then_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/destroy_then_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_empty_data_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/empty_data_encrypt").await
    }

    #[tokio::test]
    async fn test_neg_invalid_iv_length() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/invalid_iv_length").await
    }

    #[tokio::test]
    async fn test_neg_sign_with_encrypt_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign_with_encrypt_key").await
    }

    // ── Negative tests: CryptographicParameters ─────────────────────────

    #[tokio::test]
    async fn test_neg_cp_encrypt_unsupported_mode() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/encrypt_unsupported_mode").await
    }

    #[tokio::test]
    async fn test_neg_cp_encrypt_unsupported_padding() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/encrypt_unsupported_padding")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_neg_cp_encrypt_mode_algo_mismatch() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/encrypt_mode_algo_mismatch").await
    }

    #[tokio::test]
    async fn test_neg_cp_encrypt_gcm_invalid_tag_length() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/encrypt_gcm_invalid_tag_length")
            .await
    }

    #[tokio::test]
    async fn test_neg_cp_sign_invalid_hash() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/sign_invalid_hash").await
    }

    #[tokio::test]
    async fn test_neg_cp_sign_rsa_with_ecdsa_algo() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/sign_rsa_with_ecdsa_algo").await
    }

    #[tokio::test]
    async fn test_neg_cp_decrypt_wrong_mode() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/decrypt_wrong_mode").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_neg_cp_encrypt_chacha20_with_gcm_mode() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/encrypt_chacha20_with_gcm_mode")
            .await
    }

    #[tokio::test]
    async fn test_neg_cp_hash_unsupported_algo() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/hash_unsupported_algo").await
    }

    #[tokio::test]
    async fn test_neg_cp_mac_unsupported_algo() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/crypto_params/mac_unsupported_algo").await
    }

    // ── Negative tests: decrypt edge cases ──────────────────────────────

    #[tokio::test]
    async fn test_neg_decrypt_missing_iv_cbc() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/decrypt_missing_iv_cbc").await
    }

    #[tokio::test]
    async fn test_neg_decrypt_empty_tag_gcm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/decrypt_empty_tag_gcm").await
    }

    #[tokio::test]
    async fn test_neg_decrypt_truncated_ciphertext() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/decrypt_truncated_ciphertext").await
    }

    #[tokio::test]
    async fn test_neg_decrypt_wrong_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/decrypt_wrong_key").await
    }

    #[tokio::test]
    async fn test_neg_decrypt_corrupted_ciphertext() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/decrypt_corrupted_ciphertext").await
    }

    // ── Negative tests: RSA edge cases ──────────────────────────────────

    #[tokio::test]
    async fn test_neg_rsa_encrypt_oversized_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rsa/rsa_encrypt_oversized_data").await
    }

    #[tokio::test]
    async fn test_neg_rsa_decrypt_with_public_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rsa/rsa_decrypt_with_public_key").await
    }

    #[tokio::test]
    async fn test_neg_rsa_decrypt_garbage() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rsa/rsa_decrypt_garbage").await
    }

    // ── Negative tests: sign/verify edge cases ──────────────────────────

    #[tokio::test]
    async fn test_neg_verify_corrupted_signature() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign_verify/verify_corrupted_signature").await
    }

    #[tokio::test]
    async fn test_neg_verify_wrong_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign_verify/verify_wrong_key").await
    }

    #[tokio::test]
    async fn test_neg_sign_with_public_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign_verify/sign_with_public_key").await
    }

    // ── Negative tests: MAC edge cases ──────────────────────────────────

    #[tokio::test]
    async fn test_neg_mac_with_non_hmac_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac/mac_with_non_hmac_key").await
    }

    #[tokio::test]
    async fn test_neg_mac_verify_wrong_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac/mac_verify_wrong_data").await
    }

    // ── Negative tests: hash edge cases ─────────────────────────────────

    #[tokio::test]
    async fn test_neg_hash_missing_algorithm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/hash/hash_missing_algorithm").await
    }

    #[tokio::test]
    async fn test_neg_hash_init_and_final_both_true() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/hash/hash_init_and_final_both_true").await
    }

    // ── Negative tests: derive key edge cases ───────────────────────────

    #[tokio::test]
    async fn test_neg_derive_key_pbkdf2_no_salt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/derive_key/derive_key_pbkdf2_no_salt").await
    }

    #[tokio::test]
    async fn test_neg_derive_key_negative_iterations() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/derive_key/derive_key_negative_iterations")
            .await
    }

    // ── Negative tests: lifecycle edge cases ────────────────────────────

    #[tokio::test]
    async fn test_neg_encrypt_pre_active_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/encrypt_pre_active_key").await
    }

    #[tokio::test]
    async fn test_neg_create_invalid_algorithm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/create_invalid_algorithm").await
    }

    #[tokio::test]
    async fn test_neg_create_zero_length_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/create_zero_length_key").await
    }

    // ── Negative tests: type mismatch ───────────────────────────────────

    #[tokio::test]
    async fn test_neg_import_malformed_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/type_mismatch/import_malformed_key").await
    }

    #[tokio::test]
    async fn test_neg_encrypt_with_secret_data() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/type_mismatch/encrypt_with_secret_data").await
    }

    #[tokio::test]
    async fn test_neg_revoke_already_destroyed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/type_mismatch/revoke_already_destroyed").await
    }
}

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use cosmian_kms_client::{
    KmsClient, KmsClientConfig, KmsClientError,
    cosmian_kmip::{
        kmip_2_1::extra::tagging::VENDOR_ID_COSMIAN,
        ttlv::{KmipFlavor, TTLV, enum_lookup::lookup_enum_code},
    },
    reexport::cosmian_kms_access::access::Access,
};
use serde::Deserialize;
use tokio::sync::OnceCell;

use crate::TestsContext;

/// Singleton server for vector tests on the `SQLite` backend.
static ONCE_VECTOR_SQLITE: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `PostgreSQL` backend.
static ONCE_VECTOR_POSTGRESQL: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `MySQL` backend.
static ONCE_VECTOR_MYSQL: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `Redis-findex` backend.
static ONCE_VECTOR_REDIS_FINDEX: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring mTLS cert-auth (`cert_auth.toml`).
static ONCE_VECTOR_CERT_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring server-only TLS (`auth_https.toml`).
static ONCE_VECTOR_AUTH_HTTPS: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring `SoftHSM2` + KEK.
static ONCE_VECTOR_HSM_KEK: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests where the HSM KEK is configured but **not yet created**.
/// Used to verify that `wrap_and_cache` does not attempt to self-wrap when the first
/// operation creates the KEK itself (regression for PR #968 self-wrap bug).
static ONCE_VECTOR_HSM_KEK_UNCREATED: OnceCell<TestsContext> = OnceCell::const_new();

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
    /// Server type to use for this vector.
    ///
    /// Controls which singleton server is started:
    /// - `"hsm_kek"` — `SoftHSM2` with a Key Encryption Key (uses `ONCE_VECTOR_HSM_KEK`)
    /// - anything else or omitted — standard backend-driven servers
    pub server_type: Option<String>,
    /// Environment variables required to run this vector.
    ///
    /// If any variable in this list is not set, the vector is skipped gracefully.
    /// Used for HSM tests that require `HSM_SLOT_ID` to be set by the CI script.
    #[serde(default)]
    pub requires_env: Vec<String>,
    /// Database backends this vector should be tested against.
    ///
    /// Defaults to `["sqlite"]`. When `KMS_TEST_BACKENDS` env var is set
    /// (comma-separated list), the runner intersects it with this list and
    /// runs the vector once per matching backend.
    ///
    /// Supported values: `"sqlite"`, `"postgresql"`, `"mysql"`, `"redis-findex"`.
    ///
    /// Each backend maps to a config TOML override:
    /// - `sqlite` → default (`auth_plain.toml` or `server_config`)
    /// - `postgresql` → `test_data/configs/server/test/postgres.toml`
    /// - `mysql` → `test_data/configs/server/test/mysql.toml`
    /// - `redis-findex` → `test_data/configs/server/test/redis_findex.toml`
    #[serde(default = "default_backends")]
    pub backends: Vec<String>,
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
    /// Named client identities for multi-user tests.
    ///
    /// Keys are identity names (e.g. "owner", "user"); values contain cert/key paths
    /// relative to the repo root.  Steps reference identities via their `identity` field.
    /// If a step's identity is not found here, the default owner client is used.
    ///
    /// Example:
    /// ```toml
    /// [identities.owner]
    /// client_cert = "test_data/certificates/client_server/owner/owner.client.acme.com.crt"
    /// client_key  = "test_data/certificates/client_server/owner/owner.client.acme.com.key"
    ///
    /// [identities.user]
    /// client_cert = "test_data/certificates/client_server/user/user.client.acme.com.crt"
    /// client_key  = "test_data/certificates/client_server/user/user.client.acme.com.key"
    /// ```
    #[serde(default)]
    pub identities: HashMap<String, IdentityConfig>,
    /// Ordered list of KMIP request steps to execute
    pub steps: Vec<TestStep>,
}

/// TLS client-certificate identity for a specific user in a test vector.
///
/// Paths are relative to the repository root.
/// On macOS (native-tls / Security.framework), PEM identity loading is not
/// supported. The runner auto-detects a `.p12` file next to the `.crt` and
/// uses it with password `"password"` (standard test infrastructure convention).
#[derive(Debug, Deserialize, Clone)]
pub struct IdentityConfig {
    /// Path to the PEM client certificate
    pub client_cert: String,
    /// Path to the PEM client private key
    pub client_key: String,
}

/// A single request–response step in a test vector.
#[derive(Debug, Deserialize)]
pub struct TestStep {
    /// KMIP operation name (informational; included in error messages).
    ///
    /// Use `"GrantAccess"` or `"RevokeAccess"` for the Cosmian access-control
    /// REST endpoints (`POST /access/grant` and `POST /access/revoke`).  These
    /// are not KMIP operations; the request file should be a JSON object with
    /// fields `user_id`, `unique_identifier`, and `operation_types`.
    pub operation: String,
    /// Filename of the TTLV-JSON request payload (relative to the vector directory).
    /// For `GrantAccess`/`RevokeAccess` steps the file must contain a JSON object
    /// matching the `Access` struct (`user_id`, `unique_identifier`, `operation_types`).
    pub request: String,
    /// When `true`, assert that `ResultStatus` == "Success" (KMIP) or HTTP 2xx (REST).
    #[serde(default = "default_true")]
    pub assert_success: bool,
    /// Field assertions on the response TTLV.
    /// Keys are TTLV tag names; values are the expected string representations.
    /// The assertion walks the response tree looking for a matching tag and checks
    /// that the leaf value matches the expected string.
    #[serde(default)]
    pub assert_fields: HashMap<String, String>,
    /// Like `assert_fields`, but checks that the expected value is present in **any**
    /// occurrence of the tag in the response (useful for `Locate` responses that
    /// return multiple `UniqueIdentifier` items — only one of them needs to match).
    #[serde(default)]
    pub assert_any_field: HashMap<String, String>,
    /// Opposite of `assert_any_field`: asserts that **no** occurrence of the tag has
    /// the given value. Useful to verify that a specific object is NOT returned by
    /// Locate (e.g. a key not granted to the requesting user).
    /// Supports `{{captured}}` and `{{$ENV}}` variable substitution.
    #[serde(default)]
    pub assert_none_field: HashMap<String, String>,
    /// Assert that these TTLV tags are **absent** from the response.
    /// Useful to verify fields have been properly removed (e.g. Veeam compatibility).
    #[serde(default)]
    pub assert_fields_absent: Vec<String>,
    /// Assert the number of occurrences of a given TTLV tag in the response.
    /// Keys are TTLV tag names; values are the expected count.
    /// Useful for `Locate` responses to verify exactly how many objects are returned.
    ///
    /// Example: `assert_count = { UniqueIdentifier = 2 }` checks that the response
    /// contains exactly 2 `UniqueIdentifier` tags.
    #[serde(default)]
    pub assert_count: HashMap<String, usize>,
    /// When `assert_success` is `false`, optionally assert that the error response
    /// contains a specific `ResultReason` value (e.g. `"Item_Not_Found"`).
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
    /// Named identity to use for this step (must match a key in `[identities]`).
    ///
    /// When absent, defaults to `"owner"` (the default client from `TestsContext`).
    /// Set to `"user"` (or any other name defined in `[identities]`) to send this
    /// request using a different client certificate.
    ///
    /// Example in manifest:
    /// ```toml
    /// [[steps]]
    /// operation = "Get"
    /// request   = "step_get.json"
    /// identity  = "user"
    /// ```
    pub identity: Option<String>,
    /// When `true`, the step outcome (success or failure) is ignored.
    /// Useful for cleanup/setup steps that may or may not succeed (e.g. destroying
    /// a key that may not exist from a prior run).
    #[serde(default)]
    pub allow_failure: bool,
}

const fn default_true() -> bool {
    true
}

fn default_json() -> String {
    "json".to_owned()
}

fn default_backends() -> Vec<String> {
    vec![
        "sqlite".to_owned(),
        "postgresql".to_owned(),
        "mysql".to_owned(),
        "redis-findex".to_owned(),
    ]
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
    let w = match tag {
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
                    { "tag": "Operation", "type": "Enumeration", "value": w },
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
/// with captured values from previous steps, and `{{$ENV_VAR}}` placeholders
/// with environment variable values.
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

    // Substitute environment variable placeholders {{$VAR_NAME}} first
    while let Some(start) = content.find("{{$") {
        let rest = &content[start + 3..];
        let end = rest.find("}}").ok_or_else(|| {
            KmsClientError::UnexpectedError(format!(
                "Unclosed env-var placeholder in {}: found '{{{{$' without matching '}}}}'",
                path.display()
            ))
        })?;
        let var_name = &rest[..end];
        let var_value = crate::test_env::get(var_name)
            .or_else(|| std::env::var(var_name).ok())
            .ok_or_else(|| {
                KmsClientError::UnexpectedError(format!(
                    "Environment variable '{var_name}' referenced in {} is not set",
                    path.display()
                ))
            })?;
        content = format!(
            "{}{var_value}{}",
            &content[..start],
            &content[start + 3 + end + 2..]
        );
    }

    // Substitute all {{variable}} placeholders (captured values)
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

/// Resolve `{{$ENV_VAR}}` and `{{captured}}` placeholders in an assertion value.
///
/// Returns an error if a referenced environment variable is not set or a captured
/// placeholder was never populated. This ensures test vectors never silently
/// pass with empty/default values.
fn resolve_assertion_value(
    template: &str,
    captures: &HashMap<String, String>,
) -> Result<String, KmsClientError> {
    let mut result = template.to_owned();
    // Substitute environment variable placeholders {{$VAR_NAME}}
    while let Some(start) = result.find("{{$") {
        let rest = &result[start + 3..];
        if let Some(end) = rest.find("}}") {
            let var_name = &rest[..end];
            let var_value = crate::test_env::get(var_name)
                .or_else(|| std::env::var(var_name).ok())
                .ok_or_else(|| {
                    KmsClientError::UnexpectedError(format!(
                        "resolve_assertion_value: environment variable '{var_name}' \
                         referenced in assertion template '{template}' is not set — \
                         refusing to silently use an empty string"
                    ))
                })?;
            result = format!("{}{}{}", &result[..start], var_value, &rest[end + 2..]);
        } else {
            break;
        }
    }
    // Substitute captured variable placeholders {{name}}
    for (name, value) in captures {
        result = result.replace(&format!("{{{{{name}}}}}"), value);
    }
    // Fail loudly if any unresolved placeholder remains (typo in capture name)
    if let Some(pos) = result.find("{{") {
        if result[pos..].contains("}}") {
            return Err(KmsClientError::UnexpectedError(format!(
                "resolve_assertion_value: unresolved placeholder in assertion \
                 template '{template}' — result after substitution: '{result}'. \
                 Check for typos in capture variable names."
            )));
        }
    }
    Ok(result)
}

/// Collect ALL leaf values for a given tag name in the TTLV JSON tree.
fn find_all_fields_in_json(value: &serde_json::Value, tag: &str) -> Vec<String> {
    let mut results = Vec::new();
    find_all_fields_impl(value, tag, &mut results);
    results
}

fn find_all_fields_impl(value: &serde_json::Value, tag: &str, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(t)) = map.get("tag") {
                if t == tag {
                    if let Some(v) = map.get("value") {
                        let s = match v {
                            serde_json::Value::String(s) => Some(s.clone()),
                            serde_json::Value::Number(n) => Some(n.to_string()),
                            serde_json::Value::Bool(b) => Some(b.to_string()),
                            serde_json::Value::Array(_) => None,
                            _ => Some(v.to_string()),
                        };
                        if let Some(s) = s {
                            out.push(s);
                        }
                    }
                }
            }
            if let Some(serde_json::Value::Array(children)) = map.get("value") {
                for child in children {
                    find_all_fields_impl(child, tag, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                find_all_fields_impl(item, tag, out);
            }
        }
        _ => {}
    }
}

/// Find the first leaf value in a TTLV JSON tree matching the given tag name.
fn find_field_in_json(value: &serde_json::Value, tag: &str) -> Option<String> {
    find_all_fields_in_json(value, tag).into_iter().next()
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
fn assert_all_success(
    response: &serde_json::Value,
    step_operation: &str,
) -> Result<(), KmsClientError> {
    for (idx, status) in find_all_fields_in_json(response, "ResultStatus")
        .iter()
        .enumerate()
    {
        if status != "Success" && status != "0x00000000" {
            return Err(KmsClientError::UnexpectedError(format!(
                "Step '{step_operation}': batch item {idx} expected success, \
                 got ResultStatus='{status}'"
            )));
        }
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

/// Parse the `KMS_TEST_BACKENDS` environment variable into a list of backend names.
///
/// Format: comma-separated, e.g. `"sqlite,postgresql,mysql"`.
/// Falls back to `KMS_TEST_DB` (single value, used by CI scripts).
/// Defaults to `["sqlite"]` when neither variable is set.
///
/// Returns `(backends, explicitly_requested)` where `explicitly_requested` is
/// `true` when the caller set `KMS_TEST_BACKENDS` or `KMS_TEST_DB` — in that
/// case a missing connection env var is a hard error, not a graceful skip.
fn requested_backends() -> (Vec<String>, bool) {
    if let Ok(v) = std::env::var("KMS_TEST_BACKENDS") {
        let backends = v.split(',').map(|s| s.trim().to_owned()).collect();
        return (backends, true);
    }
    if let Ok(db) = std::env::var("KMS_TEST_DB") {
        let backend = match db.as_str() {
            "redis" => "redis-findex".to_owned(),
            other => other.to_owned(),
        };
        return (vec![backend], true);
    }
    (vec!["sqlite".to_owned()], false)
}

/// Check whether a backend is available to test.
///
/// Returns `true` when any of the following hold:
/// - The backend is `sqlite` (always available)
/// - `KMS_TEST_DB` explicitly names this backend (user asserts it is reachable;
///   the connection URL is provided by the server config TOML)
/// - `KMS_TEST_BACKENDS` lists this backend (same assertion)
/// - The legacy per-backend connection env var is set (`KMS_POSTGRES_URL`, etc.)
fn backend_available(backend: &str) -> bool {
    // If the user explicitly requested this specific backend, treat it as available.
    // The KMS server will use its own config TOML (which contains the URL), so
    // no separate connection env var is needed.
    if std::env::var("KMS_TEST_DB")
        .ok()
        .as_deref()
        .map(|v| if v == "redis" { "redis-findex" } else { v })
        == Some(backend)
    {
        return true;
    }
    if let Ok(v) = std::env::var("KMS_TEST_BACKENDS") {
        if v.split(',').any(|b| b.trim() == backend) {
            return true;
        }
    }
    // Fall back to checking the legacy per-backend connection env var.
    match backend {
        "postgresql" => std::env::var("KMS_POSTGRES_URL").is_ok(),
        "mysql" => std::env::var("KMS_MYSQL_URL").is_ok(),
        "redis-findex" => {
            std::env::var("KMS_REDIS_URL").is_ok() || std::env::var("REDIS_HOST").is_ok()
        }
        _ => true, // sqlite is always available
    }
}

/// Get or initialize a singleton test server for the given backend.
async fn get_or_init_vector_server(backend: &str) -> Result<&'static TestsContext, KmsClientError> {
    let root = repo_root()?;
    let (cell, toml, env_var) = match backend {
        "postgresql" => (&ONCE_VECTOR_POSTGRESQL, "postgres.toml", "KMS_POSTGRES_URL"),
        "mysql" => (&ONCE_VECTOR_MYSQL, "mysql.toml", "KMS_MYSQL_URL"),
        "redis-findex" => (
            &ONCE_VECTOR_REDIS_FINDEX,
            "redis_findex.toml",
            "KMS_REDIS_URL",
        ),
        _ => (&ONCE_VECTOR_SQLITE, "auth_plain.toml", ""),
    };
    let p = root.join("test_data/configs/server/test").join(toml);
    // Override the database URL from the environment when set (e.g. MariaDB on
    // port 3308 or Percona on port 3307 reuse the "mysql" backend with a
    // different connection URL).
    let url_override = if env_var.is_empty() {
        None
    } else {
        std::env::var(env_var).ok()
    };
    cell.get_or_try_init(|| async move {
        crate::start_test_server_with_patch(
            &p,
            |config| {
                if let Some(url) = &url_override {
                    config.db.database_url = Some(url.clone());
                }
            },
            crate::TestClientOptions::default(),
        )
        .await
    })
    .await
}

/// Run a test vector from a directory containing `manifest.toml` and step JSON files.
///
/// This is the main entry point for vector-based regression tests. It:
/// 1. Loads the manifest
/// 2. Determines which backends to test (intersection of manifest `backends`
///    field and `KMS_TEST_BACKENDS` env var)
/// 3. For each backend: uses a singleton shared server, executes steps
///
/// # Multi-backend support
///
/// Set `KMS_TEST_BACKENDS=sqlite,postgresql,mysql` to run vectors against multiple
/// database backends. The connection URL for each backend is taken from the server
/// config TOML; no separate env var is required when the backend is explicitly
/// requested. Backends not listed are skipped gracefully.
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

    // Check required environment variables; skip gracefully if any is missing
    for env_var in &manifest.requires_env {
        if crate::test_env::get(env_var).is_none() && std::env::var(env_var).is_err() {
            eprintln!(
                "SKIP vector '{}': required env var '{env_var}' is not set",
                manifest.name
            );
            return Ok(());
        }
    }

    // If server_type is set, use a dedicated server instead of the backend-driven ones
    if let Some(server_type) = &manifest.server_type {
        match server_type.as_str() {
            "hsm_kek" => {
                let context = ONCE_VECTOR_HSM_KEK
                    .get_or_try_init(|| async {
                        crate::start_default_test_kms_server_with_softhsm2_and_kek_for_vectors()
                            .await
                    })
                    .await?;
                eprintln!(
                    "▶ Running vector '{}' on server_type 'hsm_kek'",
                    manifest.name
                );
                return execute_steps(context, &manifest, &vector_path).await;
            }
            "hsm_kek_uncreated" => {
                let context = ONCE_VECTOR_HSM_KEK_UNCREATED
                    .get_or_try_init(|| async {
                        crate::start_default_test_kms_server_with_softhsm2_kek_uncreated_for_vectors()
                            .await
                    })
                    .await?;
                eprintln!(
                    "▶ Running vector '{}' on server_type 'hsm_kek_uncreated'",
                    manifest.name
                );
                return execute_steps(context, &manifest, &vector_path).await;
            }
            other => {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Unknown server_type '{other}' in manifest for vector '{}'",
                    manifest.name
                )));
            }
        }
    }

    // Determine which backends to test
    let (requested, explicit) = requested_backends();
    let backends_to_run: Vec<&String> = manifest
        .backends
        .iter()
        .filter(|b| requested.iter().any(|r| r == *b))
        .collect();

    if backends_to_run.is_empty() {
        // Vector does not target any of the requested backends — skip gracefully.
        eprintln!(
            "SKIP vector '{}': its backends {:?} are not in the current run set {:?}",
            manifest.name, manifest.backends, requested
        );
        return Ok(());
    }

    for backend in &backends_to_run {
        if !backend_available(backend) {
            if explicit {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Backend '{backend}' was explicitly requested but its connection \
                     env var is not set (postgresql→KMS_POSTGRES_URL, \
                     mysql→KMS_MYSQL_URL, redis-findex→KMS_REDIS_URL/REDIS_HOST)"
                )));
            }
            eprintln!(
                "SKIP vector '{}' on backend '{backend}': connection env var not set",
                manifest.name
            );
            continue;
        }

        eprintln!(
            "▶ Running vector '{}' on backend '{backend}'",
            manifest.name
        );

        // Manifests with a custom server_config use a per-config singleton server.
        // Each config file gets its own OnceCell to prevent race conditions where a
        // different config (e.g. auth_https.toml without mTLS) could poison the
        // ONCE_VECTOR_CERT_AUTH cell and cause all cert-auth tests to run against
        // the wrong server (reproduces non-deterministically on slower runners like ARM).
        if let Some(server_config) = &manifest.server_config {
            let config_path = root.join(server_config);
            let context = match server_config.as_str() {
                "test_data/configs/server/test/auth_https.toml" => {
                    ONCE_VECTOR_AUTH_HTTPS
                        .get_or_try_init(|| crate::start_test_server_from_toml(&config_path))
                        .await?
                }
                _ => {
                    // Default: cert_auth.toml and any future mTLS configs
                    ONCE_VECTOR_CERT_AUTH
                        .get_or_try_init(|| crate::start_test_server_from_toml(&config_path))
                        .await?
                }
            };
            execute_steps(context, &manifest, &vector_path).await?;
        } else {
            let context = get_or_init_vector_server(backend).await?;
            execute_steps(context, &manifest, &vector_path).await?;
        }
    }

    Ok(())
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

/// Execute a `GrantAccess` or `RevokeAccess` step via the Cosmian REST API.
async fn execute_access_step(
    client: &KmsClient,
    request_json: &serde_json::Value,
    step: &TestStep,
    i: usize,
) -> Result<(), KmsClientError> {
    let access: Access = serde_json::from_value(request_json.clone()).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Step {} '{}': cannot parse Access request: {e}",
            i, step.operation
        ))
    })?;
    let result = if step.operation == "GrantAccess" {
        client.grant_access(access).await
    } else {
        client.revoke_access(access).await
    };
    match result {
        Ok(_) => {
            if !step.assert_success && !step.allow_failure {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': expected failure but got success",
                    i, step.operation
                )));
            }
        }
        Err(e) => {
            if step.allow_failure {
                // Best-effort step — ignore the error
            } else if step.assert_success {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': expected success, got error: {e}",
                    i, step.operation
                )));
            } else if let Some(substr) = &step.assert_error_contains {
                let msg = e.to_string();
                if !msg.contains(substr.as_str()) {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step {} '{}': expected error containing '{}', got: {e}",
                        i, step.operation, substr
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Build one `KmsClient` per named identity declared in `manifest.identities`.
///
/// Always uses PEM (`.crt` + `.key`) so the runner works in both FIPS and
/// non-FIPS builds (PKCS12KDF is not available in FIPS mode).
fn build_identity_clients(
    context: &TestsContext,
    manifest: &TestManifest,
    root: &Path,
) -> Result<HashMap<String, KmsClient>, KmsClientError> {
    let mut identity_clients: HashMap<String, KmsClient> = HashMap::new();
    for (name, id_cfg) in &manifest.identities {
        let cert_path = root.join(&id_cfg.client_cert);
        let key_path = root.join(&id_cfg.client_key);
        let mut http_cfg = context.owner_client_config.http_config.clone();
        http_cfg.tls_client_pem_cert_path = Some(cert_path.to_string_lossy().into_owned());
        http_cfg.tls_client_pem_key_path = Some(key_path.to_string_lossy().into_owned());
        http_cfg.tls_client_pkcs12_path = None;
        http_cfg.tls_client_pkcs12_password = None;
        let cfg = KmsClientConfig {
            http_config: http_cfg,
            vendor_id: VENDOR_ID_COSMIAN.to_owned(),
            ..KmsClientConfig::default()
        };
        let client = KmsClient::new_with_config(cfg).map_err(|e| {
            KmsClientError::UnexpectedError(format!(
                "Failed to build client for identity '{name}': {e}"
            ))
        })?;
        identity_clients.insert(name.clone(), client);
    }
    Ok(identity_clients)
}

/// Execute the steps of a test vector against a running server.
async fn execute_steps(
    context: &TestsContext,
    manifest: &TestManifest,
    vector_path: &Path,
) -> Result<(), KmsClientError> {
    let base_url = context
        .owner_client_config
        .http_config
        .server_url
        .trim_end_matches('/')
        .to_owned();

    // Build per-identity KmsClients from the manifest's `[identities.*]` section.
    let root = repo_root()?;
    let identity_clients = build_identity_clients(context, manifest, &root)?;

    let is_binary = manifest.wire_format == "binary";
    let json_url = format!("{base_url}/kmip/2_1");
    let binary_url = format!("{base_url}/kmip");

    let mut captures: HashMap<String, String> = HashMap::new();

    for (i, step) in manifest.steps.iter().enumerate() {
        // Resolve which client to use for this step
        let step_identity = step.identity.as_deref().unwrap_or("owner");
        let client = identity_clients
            .get(step_identity)
            .map_or_else(|| context.get_owner_client(), Clone::clone);

        let request_path = vector_path.join(&step.request);
        let request_json = load_request_json(&request_path, &captures)?;

        // GrantAccess and RevokeAccess use the Cosmian REST API rather than TTLV.
        if matches!(step.operation.as_str(), "GrantAccess" | "RevokeAccess") {
            execute_access_step(&client, &request_json, step, i).await?;
            continue;
        }

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
                    // etc.). When assert_success is false or allow_failure is set,
                    // treat it as an expected failure and continue.
                    if !step.assert_success || step.allow_failure {
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
            // When allow_failure is set, skip all assertions — the step is best-effort
            if step.allow_failure {
                continue;
            }
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

            // Require at least one error assertion when assert_success=false.
            // Without this guard, any failure would silently pass the test.
            if step.assert_error_reason.is_none() && step.assert_error_contains.is_none() {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {i} '{}': assert_success=false but neither \
                     'assert_error_reason' nor 'assert_error_contains' is set — \
                     refusing to accept any arbitrary error as expected. \
                     Add an error assertion to the manifest.",
                    step.operation
                )));
            }

            // Expected failure — skip further assertions and captures
            continue;
        }

        // Assert specific fields (substitute env vars and captured variables in expected values)
        if !step.assert_fields.is_empty() {
            let mut resolved: HashMap<String, String> = HashMap::new();
            for (k, v) in &step.assert_fields {
                resolved.insert(k.clone(), resolve_assertion_value(v, &captures)?);
            }
            assert_response_fields(&response_json, &resolved, &step.operation)?;
        }

        // Assert that the expected value appears in ANY occurrence of the field
        // (used for Locate responses that return multiple UniqueIdentifiers)
        if !step.assert_any_field.is_empty() {
            for (tag, expected_template) in &step.assert_any_field {
                let expected = resolve_assertion_value(expected_template, &captures)?;
                let all_values = find_all_fields_in_json(&response_json, tag);
                if !all_values.contains(&expected) {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step '{}': field '{tag}' expected to contain '{expected}', \
                         but got: [{}]",
                        step.operation,
                        all_values.join(", ")
                    )));
                }
            }
        }

        // Assert that the expected value does NOT appear in any occurrence of the field
        // (used to verify a specific object is not returned by Locate)
        if !step.assert_none_field.is_empty() {
            for (tag, forbidden_template) in &step.assert_none_field {
                let forbidden = resolve_assertion_value(forbidden_template, &captures)?;
                let all_values = find_all_fields_in_json(&response_json, tag);
                if all_values.contains(&forbidden) {
                    return Err(KmsClientError::UnexpectedError(format!(
                        "Step '{}': field '{tag}' must NOT contain '{forbidden}', \
                         but it was found in: [{}]",
                        step.operation,
                        all_values.join(", ")
                    )));
                }
            }
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

        // Assert occurrence counts
        for (tag, expected_count) in &step.assert_count {
            let actual_count = find_all_fields_in_json(&response_json, tag).len();
            if actual_count != *expected_count {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {i} '{}': expected {expected_count} occurrence(s) of '{tag}', \
                     got {actual_count}",
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

    #[tokio::test]
    async fn test_vec_rekey() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey").await
    }

    #[tokio::test]
    async fn test_vec_rekey_locate_by_name() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_locate_by_name").await
    }

    #[tokio::test]
    async fn test_vec_rekey_deactivated_succeeds() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_deactivated_succeeds").await
    }

    #[tokio::test]
    async fn test_vec_rekey_with_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_with_links").await
    }

    #[tokio::test]
    async fn test_vec_rekey_with_offset() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_with_offset").await
    }

    #[tokio::test]
    async fn test_vec_rekey_double_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_double_chain").await
    }

    #[tokio::test]
    async fn test_vec_rekey_name_removed_from_old() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_name_removed_from_old").await
    }

    #[tokio::test]
    async fn test_vec_rekey_old_key_still_decrypts() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_old_key_still_decrypts").await
    }

    #[tokio::test]
    async fn test_vec_rekey_kmip14() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_kmip14").await
    }

    #[tokio::test]
    async fn test_vec_rekey_wrapping_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_wrapping_key").await
    }

    #[tokio::test]
    async fn test_vec_rekey_wrapped_key() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_wrapped_key").await
    }

    #[tokio::test]
    async fn test_vec_rekey_wrapping_key_with_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_wrapping_key_with_links")
            .await
    }

    #[tokio::test]
    async fn test_vec_rekey_wrapping_key_double_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_wrapping_key_double_chain")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_kmip14() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_kmip14").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_kmip14_binary() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_kmip14_binary").await
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
    async fn test_integration_fortigate_credential_type() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_credential_type").await
    }

    #[tokio::test]
    async fn test_integration_fortigate_locate_filter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_locate_filter").await
    }

    #[tokio::test]
    async fn test_integration_fortigate_locate_get() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_locate_get").await
    }

    #[tokio::test]
    async fn test_integration_fortigate_locate_many_similar_names() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_locate_many_similar_names")
            .await
    }

    #[tokio::test]
    async fn test_integration_fortigate_locate_multi_tunnel() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_locate_multi_tunnel").await
    }

    #[tokio::test]
    async fn test_integration_fortigate_locate_no_match() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/fortigate_locate_no_match").await
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

    #[tokio::test]
    async fn test_integration_kmip_1_3_symmetric() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/kmip_1_3_symmetric").await
    }

    #[tokio::test]
    async fn test_integration_kmip_1_3_asymmetric() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/integrations/kmip_1_3_asymmetric").await
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

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_integration_edb_tde_pykmip_variant() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/integrations/edb_tde_pykmip_variant").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_integration_edb_tde_thales_variant() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/integrations/edb_tde_thales_variant").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_integration_edb_tde_key_rotation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/integrations/edb_tde_key_rotation").await
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

    // MD5 is not FIPS-approved; this test documents that RSA-PSS/MD5 succeeds
    // only when the legacy OpenSSL provider is active (non-FIPS mode).
    #[cfg(feature = "non-fips")]
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

    #[tokio::test]
    async fn test_neg_create_hsm_key_without_hsm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/create_hsm_key_without_hsm").await
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

    // ── Negative tests: state machine violations ────────────────────────

    #[tokio::test]
    async fn test_neg_double_activate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/double_activate").await
    }

    #[tokio::test]
    async fn test_neg_activate_destroyed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/deactivate_pre_active").await
    }

    #[tokio::test]
    async fn test_neg_reactivate_deactivated() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/lifecycle/reactivate_deactivated").await
    }

    // ── Negative tests: duplicate tags (ambiguous key selection) ─────────

    #[tokio::test]
    async fn test_neg_duplicate_tags_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/duplicate_tags_encrypt").await
    }

    // ── Negative tests: KMIP spec error coverage ──────────────────────

    #[tokio::test]
    async fn test_neg_spec_activate_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/activate/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_activate_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/activate/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_add_attribute_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/add_attribute/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_add_attribute_read_only_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/add_attribute/read_only_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_certify_invalid_object_type() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/certify/invalid_object_type").await
    }

    #[tokio::test]
    async fn test_neg_spec_certify_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/certify/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_check_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/check/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_invalid_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create/invalid_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_invalid_attribute_value() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create/invalid_attribute_value").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_invalid_field() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create/invalid_field").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_read_only_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create/read_only_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_key_pair_invalid_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create_key_pair/invalid_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_key_pair_invalid_attribute_value() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create_key_pair/invalid_attribute_value").await
    }

    #[tokio::test]
    async fn test_neg_spec_create_key_pair_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create_key_pair/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_decrypt_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_decrypt_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/decrypt/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_delete_attribute_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/delete_attribute/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_destroy_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/destroy/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_destroy_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/destroy/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_bad_cryptographic_parameters() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/bad_cryptographic_parameters").await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_incompatible_cryptographic_usage_mask()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/incompatible_cryptographic_usage_mask")
            .await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_invalid_field() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/invalid_field").await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_invalid_object_type() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/invalid_object_type").await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_unsupported_cryptographic_parameters()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/unsupported_cryptographic_parameters")
            .await
    }

    #[tokio::test]
    async fn test_neg_spec_encrypt_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/encrypt/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_export_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/export/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_export_key_format_type_not_supported() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/export/key_format_type_not_supported").await
    }

    #[tokio::test]
    async fn test_neg_spec_get_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/get/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_get_key_format_type_not_supported() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/get/key_format_type_not_supported").await
    }

    #[tokio::test]
    async fn test_neg_spec_get_attribute_list_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/get_attribute_list/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_get_attributes_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/get_attributes/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_import_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/import/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_mac_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_mac_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_mac_verify_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac_verify/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_mac_verify_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/mac_verify/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_modify_attribute_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/modify_attribute/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_modify_attribute_read_only_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/modify_attribute/read_only_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_register_invalid_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/register/invalid_attribute").await
    }

    #[tokio::test]
    async fn test_neg_spec_register_invalid_attribute_value() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/register/invalid_attribute_value").await
    }

    #[tokio::test]
    async fn test_neg_spec_register_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/register/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_revoke_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/revoke/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_set_attribute_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/set_attribute/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_set_attribute_read_only_attribute() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/set_attribute/read_only_attribute").await
    }

    #[tokio::test]
    async fn test_neg_hsm_rotate_offset_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/set_attribute/hsm_rotate_offset_rejected").await
    }

    #[tokio::test]
    async fn test_neg_spec_sign_invalid_message() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign/invalid_message").await
    }

    #[tokio::test]
    async fn test_neg_spec_sign_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_sign_wrong_key_lifecycle_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/sign/wrong_key_lifecycle_state").await
    }

    #[tokio::test]
    async fn test_neg_spec_signature_verify_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/signature_verify/item_not_found").await
    }

    #[tokio::test]
    async fn test_neg_spec_signature_verify_wrong_key_lifecycle_state() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/signature_verify/wrong_key_lifecycle_state")
            .await
    }

    #[tokio::test]
    async fn test_neg_spec_validate_item_not_found() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/validate/item_not_found").await
    }

    // ── Negative tests: ReCertify ───────────────────────────────────────

    #[tokio::test]
    async fn test_neg_recertify_missing_uid() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/recertify_missing_uid").await
    }

    #[tokio::test]
    async fn test_neg_recertify_nonexistent() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/recertify_nonexistent").await
    }

    #[tokio::test]
    async fn test_neg_recertify_not_a_certificate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/recertify_not_a_certificate").await
    }

    // ── KMIP operations: Batch requests ─────────────────────────────────

    #[tokio::test]
    async fn test_vec_batch_create_get() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/batch_create_get").await
    }

    #[tokio::test]
    async fn test_vec_batch_hash_query() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/batch_hash_query").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_with_offset_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_with_offset_state")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_with_offset_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_with_offset_state").await
    }

    #[tokio::test]
    async fn test_vec_rekey_wrapped_deactivated_succeeds() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_wrapped_deactivated_succeeds")
            .await
    }

    #[tokio::test]
    async fn test_neg_rekey_preactive_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_preactive_fails").await
    }

    #[tokio::test]
    async fn test_neg_rekey_keypair_preactive_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_keypair_preactive_fails").await
    }

    #[tokio::test]
    async fn test_neg_rekey_non_latest_sql() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_non_latest_sql").await
    }

    #[tokio::test]
    async fn test_neg_rekey_non_latest_hsm() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_non_latest_hsm").await
    }

    #[tokio::test]
    async fn test_neg_rekey_keypair_non_latest() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_keypair_non_latest").await
    }

    // ── KMIP operations: ReKeyKeyPair (non-FIPS only) ────────────────────
    // These vectors do not supply PrivateKeyAttributes/PublicKeyAttributes with
    // FIPS-compliant CryptographicUsageMask values, and some use PQC algorithms
    // only available in non-FIPS mode.

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_rsa() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ec() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ec").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ec_with_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ec_with_links").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_rsa_with_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa_with_links").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ec_locate_by_name() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ec_locate_by_name")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ec_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ec_sign_verify").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_rsa_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa_encrypt_decrypt")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_p384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_p384").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_p521() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_p521").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_rsa4096() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa4096").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ml_kem_768() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_kem_768").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ml_kem_1024() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_kem_1024").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ml_dsa_65() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_dsa_65").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ml_dsa_87() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_dsa_87").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_slh_dsa_sha2_128f() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_slh_dsa_sha2_128f")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_with_offset() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_with_offset").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_double_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_double_chain").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_deactivated_succeeds() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_deactivated_succeeds")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_no_public_link_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_no_public_link_fails")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_change_algo_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_change_algo_fails")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_old_key_still_active() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_old_key_still_active")
            .await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_name_removed_from_old() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/fips/kmip_operations/rekey_keypair_name_removed_from_old",
        )
        .await
    }

    // ── Non-FIPS ReKeyKeyPair vectors ───────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_ed25519() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/rekey_keypair_ed25519").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_x25519() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/rekey_keypair_x25519").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_secp256k1() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/rekey_keypair_secp256k1").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_rekey_keypair_covercrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/non-fips/rekey_keypair_covercrypt").await
    }

    // ── KMIP operations: certificate chain and revoke ───────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_certify_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/certify_chain").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_certify_revoke_validate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/certify_revoke_validate").await
    }

    // ── KMIP operations: ReCertify ──────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_recertify_self_signed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/recertify_self_signed").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_recertify_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/recertify_chain").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_recertify_with_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/recertify_with_links").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_recertify_with_offset() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/recertify_with_offset").await
    }

    // ── KMIP operations: Locate filters ─────────────────────────────────

    #[tokio::test]
    async fn test_vec_locate_by_state() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/locate_by_state").await
    }

    #[tokio::test]
    async fn test_vec_locate_by_usage_mask() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/locate_by_usage_mask").await
    }

    #[tokio::test]
    async fn test_vec_locate_by_tag() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/locate_by_tag").await
    }

    // ── Access control: owner/user certificate identities ───────────────

    #[tokio::test]
    async fn test_vec_access_grant_aes() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/grant_access_aes").await
    }

    #[tokio::test]
    async fn test_vec_access_revoke() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/revoke_access").await
    }

    #[tokio::test]
    async fn test_vec_access_unauthorized() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/unauthorized_access").await
    }

    #[tokio::test]
    async fn test_vec_access_owner_full() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/owner_full_permissions").await
    }

    #[tokio::test]
    async fn test_vec_access_grant_partial() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/grant_partial_permissions").await
    }

    #[tokio::test]
    async fn test_vec_access_revoke_key_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/revoke_key_lifecycle").await
    }

    #[tokio::test]
    async fn test_vec_access_privilege_escalation_self_grant() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/privilege_escalation_self_grant").await
    }

    #[tokio::test]
    async fn test_vec_access_privilege_escalation_non_owner_grant() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/privilege_escalation_non_owner_grant")
            .await
    }

    #[tokio::test]
    async fn test_vec_access_privilege_escalation_destroy() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/access_control/privilege_escalation_destroy_without_permission",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_access_privilege_escalation_rekey() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/access_control/privilege_escalation_rekey_without_permission",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_access_privilege_escalation_activate() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/access_control/privilege_escalation_activate_without_permission",
        )
        .await
    }

    // ── HSM + KEK vectors ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_kek_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_encrypt_decrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_sign_verify").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_aes256_create_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_aes256_create_encrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_rsa2048_create_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_rsa2048_create_sign").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_ec_p256_create_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_ec_p256_create_sign").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_ed25519_create_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_ed25519_create_sign").await
    }

    #[tokio::test]
    async fn test_vec_hsm_kek_rekey_wrapped() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_rekey_wrapped").await
    }

    /// Regression test for the HSM self-wrap bug (PR #968):
    /// `wrap_and_cache` must not attempt to wrap an HSM-resident key with the
    /// server-wide KEK when the key being created IS the configured KEK UID.
    #[tokio::test]
    async fn test_vec_hsm_kek_bootstrap_self_create() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_bootstrap_self_create").await
    }

    // ── HSM Resident: Keyset (rotate_name / CKA_LABEL) ───────────────────

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_set_rotate_name() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_set_rotate_name").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_rekey_and_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_rekey_and_decrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_double_rotation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_double_rotation").await
    }

    #[tokio::test]
    #[cfg(not(feature = "non-fips"))]
    async fn test_vec_hsm_kek_rsa1024_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_rsa1024_rejected").await
    }

    // ── HSM Resident: Key Creation ───────────────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_resident_aes128_create_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_aes128_create_encrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_aes256_create_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_aes256_create_encrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa4096_create_sign() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa4096_create_sign").await
    }

    // ── HSM Resident: Encryption ─────────────────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_resident_aes256_encrypt_cbc() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_aes256_encrypt_cbc").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_encrypt_oaep_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha256").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_encrypt_oaep_sha1() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha1").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_encrypt_pkcs1v15() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_encrypt_pkcs1v15").await
    }

    // ── HSM Resident: Signing ────────────────────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_pkcs1v15() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_pkcs1v15").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_sha1() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_sha1").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_sha256() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_sha256").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_sha384() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_sha384").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_sha512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_sha512").await
    }

    // ── HSM Resident: Negative tests ─────────────────────────────────────

    #[tokio::test]
    #[cfg(not(feature = "non-fips"))]
    async fn test_vec_hsm_resident_rsa1024_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa1024_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_ec_p256_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_ec_p256_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_ec_p384_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_ec_p384_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_ed25519_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_ed25519_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_non_aes_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_non_aes_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_aes256_encrypt_ecb_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_aes256_encrypt_ecb_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_ecdsa_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_ecdsa_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_rsa2048_sign_dsa_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_rsa2048_sign_dsa_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_wrong_prefix() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/wrong_prefix").await
    }

    #[tokio::test]
    async fn test_vec_hsm_no_kek_baseline() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/no_kek_baseline").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_encrypt_all() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/hsm_resident_encrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_sign_all() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/hsm_resident_sign").await
    }

    // ── HSM permission vectors ────────────────────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_perm_admin_create_encrypt_destroy() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/admin_create_encrypt_destroy").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_admin_grant_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/admin_grant_encrypt_decrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_get_not_wildcard() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/get_not_wildcard").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_admin_grant_revoke() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/admin_grant_revoke").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_user_cannot_create() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/user_cannot_create").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_user_cannot_destroy() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/user_cannot_destroy").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_user_cannot_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/user_cannot_encrypt").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_user_cannot_grant() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/user_cannot_grant").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_cannot_grant_destroy() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/cannot_grant_destroy").await
    }

    #[tokio::test]
    async fn test_vec_hsm_perm_locate_visibility() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/permissions/locate_visibility").await
    }

    // ── Serialization round-trip vectors ────────────────────────────────────────
    // Verify that objects and attributes survive the KMIP 3.0 DB serialization
    // (KMIP3: prefix for objects, raw 3.0 JSON for attributes).

    #[tokio::test]
    async fn test_vec_serial_create_locate_roundtrip() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/serialization/create_locate_roundtrip").await
    }

    #[tokio::test]
    async fn test_vec_serial_create_encrypt_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/serialization/create_encrypt_decrypt_roundtrip")
            .await
    }

    #[tokio::test]
    async fn test_vec_serial_rsa_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/serialization/rsa_sign_verify_roundtrip").await
    }

    #[tokio::test]
    async fn test_vec_serial_attributes_preservation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/serialization/attributes_preservation").await
    }

    #[tokio::test]
    async fn test_vec_serial_import_destroy_reimport() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/serialization/import_destroy_reimport").await
    }

    // ─── Keyset resolution & try-each-key vectors ────────────────────────────

    #[tokio::test]
    async fn test_vec_keyset_encrypt_latest() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_encrypt_latest").await
    }

    #[tokio::test]
    async fn test_vec_keyset_encrypt_bare_name() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_encrypt_bare_name").await
    }

    #[tokio::test]
    async fn test_vec_keyset_decrypt_try_each() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_decrypt_try_each").await
    }

    #[tokio::test]
    async fn test_vec_keyset_decrypt_double_rotation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_decrypt_double_rotation")
            .await
    }

    #[tokio::test]
    async fn test_vec_keyset_encrypt_latest_after_rotation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/fips/kmip_operations/keyset_encrypt_latest_after_rotation",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_keyset_decrypt_at_latest() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_decrypt_at_latest").await
    }

    #[tokio::test]
    async fn test_vec_keyset_rotate_name_at_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_rotate_name_at_rejected").await
    }
}

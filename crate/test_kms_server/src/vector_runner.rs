use std::{
    collections::HashMap,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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
use tokio::sync::{Mutex, OnceCell};

use crate::TestsContext;

/// Singleton server for vector tests on the `SQLite` backend.
static ONCE_VECTOR_SQLITE: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `PostgreSQL` backend.
static ONCE_VECTOR_POSTGRESQL: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `MySQL` backend.
static ONCE_VECTOR_MYSQL: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests on the `Redis-findex` backend.
static ONCE_VECTOR_REDIS_FINDEX: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring mTLS cert-auth (`auth/cert.toml`).
static ONCE_VECTOR_CERT_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring server-only TLS (`auth/tls.toml`).
static ONCE_VECTOR_AUTH_HTTPS: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for Operator/CryptoOfficer test vectors (`auth/cert_roles.toml`).
static ONCE_VECTOR_CERT_AUTH_OPERATOR_CRYPTO_OFFICER: OnceCell<TestsContext> =
    OnceCell::const_new();
/// Singleton server for vector tests requiring `SoftHSM2` + KEK.
static ONCE_VECTOR_HSM_KEK: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests where the HSM KEK is configured but **not yet created**.
/// Used to verify that `wrap_and_cache` does not attempt to self-wrap when the first
/// operation creates the KEK itself (regression for PR #968 self-wrap bug).
static ONCE_VECTOR_HSM_KEK_UNCREATED: OnceCell<TestsContext> = OnceCell::const_new();
/// Singleton server for vector tests requiring `SoftHSM2` **without** a KEK.
static ONCE_VECTOR_HSM: OnceCell<TestsContext> = OnceCell::const_new();
/// Serialises **all** HSM test vectors that target the same `SoftHSM2` slot
/// (`hsm_kek`, `hsm_kek_uncreated`, and `hsm` server types all use
/// `HSM_SLOT_ID`).
///
/// A single slot-level mutex is required because the two KMS server instances
/// (`hsm` and `hsm_kek`) share PKCS#11 object handles across separate
/// `BaseHsm` caches.  When both run concurrently, one instance can close a
/// session whose handles the other still holds in cache, producing
/// `CKR_OBJECT_HANDLE_INVALID` (130) failures in the losing thread.
static HSM_SLOT_MUTEX: Mutex<()> = Mutex::const_new(());
/// Guards the one-time cleanup of stale `vec_*` HSM objects that accumulate
/// across `cargo test` invocations.  The cleanup must run while `HSM_SLOT_MUTEX`
/// is held so that it cannot delete keys being used by a concurrently-running
/// `hsm_kek` test.
static HSM_CLEANUP_DONE: OnceCell<()> = OnceCell::const_new();

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
/// server_config = "test_data/configs/server/auth/plain.toml"
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
    /// If omitted, defaults to `test_data/configs/server/auth/plain.toml`.
    pub server_config: Option<String>,
    /// Server type to use for this vector.
    ///
    /// Controls which singleton server is started:
    /// - `"hsm_kek"` — `SoftHSM2` with a Key Encryption Key (uses `ONCE_VECTOR_HSM_KEK`)
    /// - `"hsm_kek_uncreated"` — `SoftHSM2` + KEK UID configured but key not yet created
    /// - `"hsm"` — `SoftHSM2` without any KEK (uses `ONCE_VECTOR_HSM`)
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
    /// - `sqlite` → default (`auth/plain.toml` or `server_config`)
    /// - `postgresql` → `test_data/configs/server/db/postgres.toml`
    /// - `mysql` → `test_data/configs/server/db/mysql.toml`
    /// - `redis-findex` → `test_data/configs/server/db/redis_findex.toml`
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

/// Client identity for a specific user in a test vector.
///
/// Supports two mutually exclusive authentication modes:
/// - **mTLS** (`client_cert` + `client_key`): paths relative to the repository root.
/// - **JWT** (`access_token_env`): the named env var holds a Bearer JWT.
///
/// When `access_token_env` is set the mTLS fields are ignored.
#[derive(Debug, Deserialize, Clone)]
pub struct IdentityConfig {
    /// Path to the PEM client certificate (mTLS identity).
    /// Leave empty when `access_token_env` is set.
    #[serde(default)]
    pub client_cert: String,
    /// Path to the PEM client private key (mTLS identity).
    /// Leave empty when `access_token_env` is set.
    #[serde(default)]
    pub client_key: String,
    /// Name of an environment variable that holds a Bearer JWT for this identity.
    ///
    /// When set, the runner reads the JWT from the named env var and uses it
    /// as the `access_token` for all requests from this identity.  `client_cert`
    /// and `client_key` are ignored when this field is present.
    ///
    /// The env var must be populated (e.g. by the test-setup function) before
    /// the vector executes.
    ///
    /// Example:
    /// ```toml
    /// [identities.user_role]
    /// access_token_env = "KMS_TEST_OPA_USER_ROLE_JWT"
    /// ```
    #[serde(default)]
    pub access_token_env: Option<String>,
}

/// Captures the Nth occurrence of a repeated TTLV tag from a response.
///
/// Used with `capture_nth` in a manifest step to capture individual share UIDs from
/// `CreateSplitKeyResponse`, which returns N `UniqueIdentifier` tags (one per share).
///
/// Example:
/// ```toml
/// [steps.capture_nth.share2_id]
/// tag   = "UniqueIdentifier"
/// index = 1
/// ```
#[derive(Debug, Deserialize)]
pub struct CaptureNthEntry {
    /// TTLV tag name to search for in the response.
    pub tag: String,
    /// Zero-based index into all occurrences of the tag.
    pub index: usize,
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
    /// Capture the Nth occurrence of a repeated TTLV tag into named variables.
    ///
    /// Complements `capture` (which always takes the first occurrence) for responses
    /// that emit multiple values under the same tag, e.g. `CreateSplitKeyResponse`
    /// which returns one `UniqueIdentifier` per share.
    ///
    /// Example:
    /// ```toml
    /// [steps.capture_nth.share2_id]
    /// tag   = "UniqueIdentifier"
    /// index = 1
    /// ```
    #[serde(default)]
    pub capture_nth: HashMap<String, CaptureNthEntry>,
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
        .post_bytes(binary_url, request_bytes, "application/octet-stream")
        .await
        .map_err(|e| {
            KmsClientError::UnexpectedError(format!(
                "Step {step_index} '{step_operation}': HTTP request failed: {e}"
            ))
        })?;

    let response_bytes = response.bytes();

    // binary bytes → TTLV struct → JSON
    if response_bytes.is_empty() {
        return Err(KmsClientError::UnexpectedError(format!(
            "Step {step_index} '{step_operation}': empty binary response"
        )));
    }

    let response_ttlv = TTLV::from_bytes(response_bytes, kmip_flavor).map_err(|e| {
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

    // Substitute {{hex:variable}} placeholders (hex-encode captured values)
    for (name, value) in captures {
        let hex_placeholder = format!("{{{{hex:{name}}}}}");
        if content.contains(&hex_placeholder) {
            let hex_value = hex::encode(value.as_bytes());
            content = content.replace(&hex_placeholder, &hex_value);
        }
    }

    // Substitute all {{variable}} placeholders (captured values).
    // Values are embedded verbatim inside JSON string literals, so characters
    // that are special in JSON (backslash, double-quote, and ASCII control
    // characters) must be escaped.  This is critical on Windows where file
    // paths contain backslashes (e.g. "C:\Users\…\kms_vector_0.pem") that
    // would otherwise produce invalid JSON escape sequences.
    for (name, value) in captures {
        let json_escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        content = content.replace(&format!("{{{{{name}}}}}"), &json_escaped);
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
    // When `KMS_TEST_DB` names the same backend as the requested vector backend,
    // reuse the shared default server (`ONCE`) rather than starting a second
    // server against the same database.  Two independent servers each configured
    // with `clear_database = true` pointing at the same DB would race: whichever
    // initialises second wipes out objects that the other has already written,
    // causing non-deterministic "object not found" failures in the certify tests.
    let effective_kms_db = std::env::var("KMS_TEST_DB").ok().map(|v| match v.as_str() {
        "redis" => "redis-findex".to_owned(),
        other => other.to_owned(),
    });
    if effective_kms_db.as_deref() == Some(backend) {
        return Ok(crate::start_default_test_kms_server().await);
    }

    let root = repo_root()?;
    let (cell, toml, env_var) = match backend {
        "postgresql" => (
            &ONCE_VECTOR_POSTGRESQL,
            "db/postgres.toml",
            "KMS_POSTGRES_URL",
        ),
        "mysql" => (&ONCE_VECTOR_MYSQL, "db/mysql.toml", "KMS_MYSQL_URL"),
        "redis-findex" => (
            &ONCE_VECTOR_REDIS_FINDEX,
            "db/redis_findex.toml",
            "KMS_REDIS_URL",
        ),
        _ => (&ONCE_VECTOR_SQLITE, "auth/plain.toml", ""),
    };
    let p = root.join("test_data/configs/server").join(toml);
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
                // Serialise PKCS#11 access: SoftHSM2 state is not safe under concurrent
                // access on the same slot (CKR_OBJECT_HANDLE_INVALID races).
                let _hsm_guard = HSM_SLOT_MUTEX.lock().await;
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
                let _hsm_guard = HSM_SLOT_MUTEX.lock().await;
                eprintln!(
                    "▶ Running vector '{}' on server_type 'hsm_kek_uncreated'",
                    manifest.name
                );
                return execute_steps(context, &manifest, &vector_path).await;
            }
            "hsm" => {
                let context = ONCE_VECTOR_HSM
                    .get_or_try_init(|| async {
                        crate::start_default_test_kms_server_with_softhsm2_for_vectors().await
                    })
                    .await?;
                // Serialise PKCS#11 access: all HSM server types share the same slot.
                let _hsm_guard = HSM_SLOT_MUTEX.lock().await;
                // Purge stale `vec_*` objects from previous test runs exactly once,
                // while the slot mutex is held (prevents deleting keys that an
                // `hsm_kek` test just created on the shared slot).
                HSM_CLEANUP_DONE
                    .get_or_try_init(|| async {
                        crate::test_server::cleanup_hsm_slot_objects(&context.get_owner_client())
                            .await;
                        Ok::<(), cosmian_kms_client::KmsClientError>(())
                    })
                    .await?;
                eprintln!("▶ Running vector '{}' on server_type 'hsm'", manifest.name);
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
        // different config (e.g. auth/tls.toml without mTLS) could poison the
        // ONCE_VECTOR_CERT_AUTH cell and cause all cert-auth tests to run against
        // the wrong server (reproduces non-deterministically on slower runners like ARM).
        if let Some(server_config) = &manifest.server_config {
            let config_path = root.join(server_config);
            let context = match server_config.as_str() {
                "test_data/configs/server/auth/tls.toml" => {
                    ONCE_VECTOR_AUTH_HTTPS
                        .get_or_try_init(|| crate::start_test_server_from_toml(&config_path))
                        .await?
                }
                "test_data/configs/server/auth/cert_roles.toml" => {
                    ONCE_VECTOR_CERT_AUTH_OPERATOR_CRYPTO_OFFICER
                        .get_or_try_init(|| crate::start_test_server_from_toml(&config_path))
                        .await?
                }
                _ => {
                    // Default: auth/cert.toml and any future mTLS configs
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

/// Counter for unique temp file paths in vector tests.
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Convert a filesystem path to a valid `file://` URI suitable for use in
/// X.509 certificate extensions (`crlDistributionPoints`, etc.).
///
/// The standard form is `file:///absolute/path`. On Windows, the drive letter
/// is preserved and backslashes are converted to forward slashes:
/// `C:\foo\bar` → `file:///C:/foo/bar`.
/// On Unix, `/foo/bar` → `file:///foo/bar` (the leading `/` provides the third
/// slash after `file://`).
pub(crate) fn path_to_file_uri(path: &Path) -> String {
    #[cfg(windows)]
    {
        // Replace backslashes with forward slashes and prepend three slashes so
        // the drive letter is part of the path component, not the authority.
        format!("file:///{}", path.to_string_lossy().replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        // On POSIX the path already starts with '/', giving the third slash.
        format!("file://{}", path.to_string_lossy())
    }
}

/// Execute an `AllocTempFile` pseudo-step.
///
/// The request JSON must have: `{ "capture_as": "variable_name", "extension": "pem" }`
/// Optionally: `"additional_captures": { "name": "template with {{var}}" }`
///
/// This does not create the file — it just allocates a unique path and captures
/// it so subsequent steps can reference it via `{{variable_name}}`.
/// Additional captures allow deriving new variables from the allocated path.
fn execute_alloc_temp_file_step(
    request_json: &serde_json::Value,
    step: &TestStep,
    i: usize,
    captures: &mut HashMap<String, String>,
) -> Result<(), KmsClientError> {
    let capture_as = request_json
        .get("capture_as")
        .and_then(|v| v.as_str())
        .unwrap_or("temp_file_path");
    let extension = request_json
        .get("extension")
        .and_then(|v| v.as_str())
        .unwrap_or("tmp");

    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "kms_vector_{counter}_{}.{extension}",
        std::process::id()
    ));

    captures.insert(capture_as.to_owned(), path.to_string_lossy().into_owned());
    // Also expose a valid file:// URI form under "<capture_as>_url" so that
    // manifest templates can use it directly in certificate extension strings
    // (the raw Windows path "C:\..." is not a valid file:// URI).
    captures.insert(format!("{capture_as}_url"), path_to_file_uri(&path));

    // Resolve additional_captures templates against the current captures
    if let Some(additional) = request_json
        .get("additional_captures")
        .and_then(|v| v.as_object())
    {
        for (name, template_val) in additional {
            if let Some(template) = template_val.as_str() {
                let mut resolved = template.to_owned();
                for (var_name, var_value) in captures.iter() {
                    resolved = resolved.replace(&format!("{{{{{var_name}}}}}"), var_value);
                }
                captures.insert(name.clone(), resolved);
            }
        }
    }

    if !step.assert_success && !step.allow_failure {
        return Err(KmsClientError::UnexpectedError(format!(
            "Step {} '{}': AllocTempFile always succeeds but assert_success=false",
            i, step.operation
        )));
    }
    Ok(())
}

/// Execute a `GenerateCrl` step via the Cosmian REST API.
///
/// The request JSON must have: `{ "issuer_id": "{{cert_id}}" }`
/// Optionally: `"format": "pem"|"der"`, `"validity_days": N`, `"output_path": "{{var}}"`
///
/// If `output_path` is provided, the CRL is written there (supports variable
/// substitution). Otherwise a unique temp file is allocated.
/// The file path is always captured as `crl_file_path`.
async fn execute_generate_crl_step(
    client: &KmsClient,
    request_json: &serde_json::Value,
    step: &TestStep,
    i: usize,
    captures: &mut HashMap<String, String>,
) -> Result<(), KmsClientError> {
    let issuer_id = request_json
        .get("issuer_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            KmsClientError::UnexpectedError(format!(
                "Step {} '{}': GenerateCrl request must have 'issuer_id' field",
                i, step.operation
            ))
        })?;
    let format = request_json
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("pem");
    let validity_days = request_json
        .get("validity_days")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok());
    let output_path = request_json
        .get("output_path")
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    let mut endpoint = format!("/certificates/{issuer_id}/crl?format={format}");
    if let Some(days) = validity_days {
        write!(endpoint, "&validity_days={days}").map_err(|e| {
            KmsClientError::UnexpectedError(format!(
                "Step {i} '{}': failed to format endpoint: {e}",
                step.operation
            ))
        })?;
    }

    let result: Result<Vec<u8>, _> = client.get_bytes::<()>(&endpoint, None).await;

    match result {
        Ok(bytes) => {
            if !step.assert_success && !step.allow_failure {
                return Err(KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': expected failure but got success",
                    i, step.operation
                )));
            }
            // Determine output path
            let crl_path = output_path.map_or_else(
                || {
                    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
                    std::env::temp_dir().join(format!(
                        "kms_vector_crl_{counter}_{}.{format}",
                        std::process::id()
                    ))
                },
                PathBuf::from,
            );
            std::fs::write(&crl_path, &bytes).map_err(|e| {
                KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': failed to write CRL to {}: {e}",
                    i,
                    step.operation,
                    crl_path.display()
                ))
            })?;
            // Capture the file path for use in subsequent steps
            captures.insert(
                "crl_file_path".to_owned(),
                crl_path.to_string_lossy().into_owned(),
            );
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
/// Two identity modes are supported:
/// - **mTLS**: `client_cert` + `client_key` fields point to PEM files.
/// - **JWT**: `access_token_env` names an env var that holds the Bearer token.
///
/// Always uses PEM (not PKCS#12) for mTLS so the runner works in both FIPS and
/// non-FIPS builds (`PKCS12KDF` is not available in FIPS mode).
fn build_identity_clients(
    context: &TestsContext,
    manifest: &TestManifest,
    root: &Path,
) -> Result<HashMap<String, KmsClient>, KmsClientError> {
    let mut identity_clients: HashMap<String, KmsClient> = HashMap::new();
    for (name, id_cfg) in &manifest.identities {
        let mut http_cfg = context.owner_client_config.http_config.clone();

        // Always clear PKCS#12 — only PEM-based mTLS is supported in the vector runner.
        http_cfg.tls_client_pkcs12_path = None;
        http_cfg.tls_client_pkcs12_password = None;

        if let Some(env_name) = &id_cfg.access_token_env {
            // JWT-based identity: read the Bearer token from the named env var.
            let jwt = std::env::var(env_name).map_err(|_e| {
                KmsClientError::UnexpectedError(format!(
                    "identity '{name}': env var '{env_name}' (access_token_env) is not set"
                ))
            })?;
            // Strip an optional "Bearer " prefix: the HTTP client adds it when building
            // the Authorization header, so storing a pre-prefixed value would produce
            // "Authorization: Bearer Bearer <token>" and fail authentication.
            let jwt = jwt
                .strip_prefix("Bearer ")
                .map(str::to_owned)
                .unwrap_or(jwt);
            http_cfg.access_token = Some(jwt);
            // Clear any mTLS settings inherited from the context config.
            http_cfg.tls_client_pem_cert_path = None;
            http_cfg.tls_client_pem_key_path = None;
        } else {
            // mTLS identity: use certificate + key paths from the manifest.
            let cert_path = root.join(&id_cfg.client_cert);
            let key_path = root.join(&id_cfg.client_key);
            http_cfg.tls_client_pem_cert_path = Some(cert_path.to_string_lossy().into_owned());
            http_cfg.tls_client_pem_key_path = Some(key_path.to_string_lossy().into_owned());
        }

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

        // GenerateCrl calls the REST endpoint and writes CRL to a temp file.
        if step.operation == "GenerateCrl" {
            execute_generate_crl_step(&client, &request_json, step, i, &mut captures).await?;
            continue;
        }

        // AllocTempFile allocates a unique path and captures it as a variable.
        if step.operation == "AllocTempFile" {
            execute_alloc_temp_file_step(&request_json, step, i, &mut captures)?;
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
            let send_result = client.client.post_json(&json_url, &request_message).await;

            match send_result {
                Ok(response) => {
                    let status = response.status;
                    let response_text = response.text().map_err(|e| {
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

        // Capture the Nth occurrence of a repeated tag (e.g. share UIDs from CreateSplitKeyResponse)
        for (var_name, rule) in &step.capture_nth {
            let all = find_all_fields_in_json(&response_json, &rule.tag);
            let value = all.get(rule.index).ok_or_else(|| {
                KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': capture_nth '{var_name}': tag '{}' has only {} occurrence(s), \
                     but index {} was requested",
                    i,
                    step.operation,
                    rule.tag,
                    all.len(),
                    rule.index
                ))
            })?;
            captures.insert(var_name.clone(), value.clone());
        }

        // Capture the Nth occurrence of a repeated tag (e.g. share UIDs from CreateSplitKeyResponse)
        for (var_name, rule) in &step.capture_nth {
            let all = find_all_fields_in_json(&response_json, &rule.tag);
            let value = all.get(rule.index).ok_or_else(|| {
                KmsClientError::UnexpectedError(format!(
                    "Step {} '{}': capture_nth '{var_name}': tag '{}' has only {} occurrence(s), \
                     but index {} was requested",
                    i,
                    step.operation,
                    rule.tag,
                    all.len(),
                    rule.index
                ))
            })?;
            captures.insert(var_name.clone(), value.clone());
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
    async fn test_vec_rekey_compromised_succeeds() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_compromised_succeeds").await
    }

    #[tokio::test]
    async fn test_vec_rekey_deactivated_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_deactivated_fails").await
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
    async fn test_vec_rekey_old_key_decrypt_succeeds() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_old_key_decrypt_succeeds")
            .await
    }

    #[tokio::test]
    async fn test_vec_rekey_manual_clears_interval() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_manual_clears_interval").await
    }

    #[tokio::test]
    async fn test_vec_rekey_manual_clears_offset() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_manual_clears_offset").await
    }

    #[tokio::test]
    async fn test_vec_rekey_keypair_rsa_old_decrypts() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa_old_decrypts")
            .await
    }

    #[tokio::test]
    async fn test_vec_rekey_mac_keyset() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_mac_keyset").await
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

    // ── PQC: Export as Raw ──────────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_dsa_44_export_raw() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_dsa_44_export_raw").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_ml_kem_768_export_raw() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/asymmetric/ml_kem_768_export_raw").await
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

    // ── KAT: ReKey (symmetric) lifecycle ─────────────────────────────────

    #[tokio::test]
    async fn test_kat_rekey_state_transitions() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/state_transitions").await
    }

    #[tokio::test]
    async fn test_kat_rekey_rotate_generation_counter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/rotate_generation_counter").await
    }

    #[tokio::test]
    async fn test_kat_rekey_rotate_latest_flag() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/rotate_latest_flag").await
    }

    #[tokio::test]
    async fn test_kat_rekey_rotate_interval_cleared() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/rotate_interval_cleared").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keyset_uid() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/keyset_uid").await
    }

    #[tokio::test]
    async fn test_kat_rekey_replacement_and_replaced_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/replacement_and_replaced_links").await
    }

    #[tokio::test]
    async fn test_kat_rekey_deactivated_rejects_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/deactivated_rejects_encrypt").await
    }

    #[tokio::test]
    async fn test_kat_rekey_deactivated_accepts_decrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey/deactivated_accepts_decrypt").await
    }

    // ── KAT: ReKeyKeyPair (asymmetric) lifecycle ──────────────────────────

    #[tokio::test]
    async fn test_kat_rekey_keypair_state_transitions() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/state_transitions").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keypair_rotate_generation_counter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/rotate_generation_counter").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keypair_rotate_latest_flag() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/rotate_latest_flag").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keypair_replacement_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/replacement_links").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keypair_old_sk_deactivated_rejects_sign() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/old_sk_deactivated_rejects_sign").await
    }

    #[tokio::test]
    async fn test_kat_rekey_keypair_old_pk_deactivated_accepts_verify() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/rekey_keypair/old_pk_deactivated_accepts_verify")
            .await
    }

    // ── KAT: ReCertify lifecycle ──────────────────────────────────────────

    #[tokio::test]
    async fn test_kat_recertify_state_transitions() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/recertify/state_transitions").await
    }

    #[tokio::test]
    async fn test_kat_recertify_rotate_generation_counter() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/recertify/rotate_generation_counter").await
    }

    #[tokio::test]
    async fn test_kat_recertify_rotate_latest_flag() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/recertify/rotate_latest_flag").await
    }

    #[tokio::test]
    async fn test_kat_recertify_replacement_and_replaced_links() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/kat/recertify/replacement_and_replaced_links").await
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
    async fn test_neg_set_attribute_readonly_rotate_generation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/set_attribute/readonly_rotate_generation").await
    }

    #[tokio::test]
    async fn test_neg_set_attribute_readonly_rotate_date() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/set_attribute/readonly_rotate_date").await
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
    async fn test_neg_rekey_offset_preactive_cannot_encrypt() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/rekey_offset_preactive_cannot_encrypt").await
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
    async fn test_vec_rekey_keypair_rsa_sign_verify() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_rsa_sign_verify")
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
    async fn test_vec_rekey_keypair_ml_kem_512() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_kem_512").await
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
    async fn test_vec_rekey_keypair_ml_dsa_44() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_ml_dsa_44").await
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
    async fn test_vec_rekey_keypair_deactivated_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/rekey_keypair_deactivated_fails")
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

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_crl_validation_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/crl_validation_lifecycle").await
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

    // ── Role separation vectors ───────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_access_operator_role_blocked_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/operator_role_blocked_lifecycle").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_access_crypto_officer_role_allowed_ops() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/access_control/crypto_officer_role_allowed_ops").await
    }

    // ── Split-key (XOR) round-trip vectors ──────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_create_split_key_sss() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/create_split_key_sss").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_create_split_key_xor() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/create_split_key_xor").await
    }

    // ── Split-key negative vectors ────────────────────────────────────────

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_create_split_key_threshold_too_low() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create_split_key_threshold_too_low").await
    }

    #[cfg(feature = "non-fips")]
    #[tokio::test]
    #[ignore = "test vector data not yet generated — run with RECORD_VECTORS=1"]
    async fn test_vec_create_split_key_parts_less_than_threshold() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/create_split_key_parts_less_than_threshold")
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

    #[tokio::test]
    async fn test_vec_hsm_kek_rekey_kek() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/kek_rekey_kek").await
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
    async fn test_vec_hsm_resident_keyset_full_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_full_lifecycle").await
    }

    // ── HSM No-KEK: Keyset addressing, re-key guards, chain-walk semantics ──

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_basic() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_basic").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_addressing() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_addressing").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_consecutive() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_consecutive").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_uid_lifecycle() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_uid_lifecycle").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_rekey_non_latest() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_rekey_non_latest").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_rekey_by_name() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_rekey_by_name").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_rekey_by_hsm_uid() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_rekey_by_hsm_uid").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_rekey_by_keyset_name() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_rekey_by_keyset_name").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_duplicate_rekey() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_duplicate_rekey").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_no_kek_encrypt_gen_select() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_no_kek_encrypt_gen_select").await
    }

    // ── HSM Negative: Keyset name constraints ─────────────────────────────

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_rotate_name_bare_rejected() -> Result<(), KmsClientError>
    {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_rotate_name_bare_rejected").await
    }

    #[tokio::test]
    async fn test_vec_hsm_resident_keyset_rotate_name_gen_suffix_rejected()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/hsm/resident_keyset_rotate_name_gen_suffix_rejected")
            .await
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

    // ── K8s KMS Plugin vectors ────────────────────────────────────────────

    /// Verifies the AES-256-GCM wrap/unwrap flow used by `kubernetes-kms-plugin`
    /// when `kube-apiserver` calls Encrypt (wrap DEK) and Decrypt (unwrap DEK).
    #[tokio::test]
    async fn test_vec_k8s_plugin_dek_wrap_unwrap() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/k8s_plugin/dek_wrap_unwrap").await
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
    async fn test_vec_keyset_encrypt_at_first() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_encrypt_at_first").await
    }

    #[tokio::test]
    async fn test_vec_keyset_encrypt_at_generation_n() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_encrypt_at_generation_n")
            .await
    }

    #[tokio::test]
    async fn test_vec_keyset_decrypt_at_first() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_decrypt_at_first").await
    }

    #[tokio::test]
    async fn test_vec_keyset_decrypt_at_generation_n() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_decrypt_at_generation_n")
            .await
    }

    #[tokio::test]
    async fn test_vec_keyset_rotate_name_at_rejected() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_rotate_name_at_rejected").await
    }

    #[tokio::test]
    async fn test_vec_keyset_invalid_generation() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_invalid_generation").await
    }

    // ── Process-window (ProtectStopDate / ProcessStartDate) ───────────────────

    #[tokio::test]
    async fn test_vec_process_window_encrypt_expired_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/fips/kmip_operations/process_window_encrypt_expired_fails",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_process_window_encrypt_not_yet_active_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/fips/kmip_operations/process_window_encrypt_not_yet_active_fails",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_keyset_chain_skips_expired_window() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_chain_skips_expired_window")
            .await
    }

    #[tokio::test]
    async fn test_vec_keyset_encrypt_expired_window_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector(
            "test_data/vectors/fips/kmip_operations/keyset_encrypt_expired_window_fails",
        )
        .await
    }

    #[tokio::test]
    async fn test_vec_keyset_uid_scheme() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_uid_scheme").await
    }

    #[tokio::test]
    async fn test_vec_keyset_gen0_via_address() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_gen0_via_address").await
    }

    #[tokio::test]
    async fn test_vec_keyset_create_uid_mismatch_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_create_uid_mismatch_fails").await
    }

    #[tokio::test]
    async fn test_vec_keyset_create_no_uid_with_rotate_name_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_create_no_uid_with_rotate_name_fails")
            .await
    }

    #[tokio::test]
    async fn test_vec_keyset_setattribute_uid_mismatch_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_setattribute_uid_mismatch_fails").await
    }

    #[tokio::test]
    async fn test_vec_keyset_addattribute_uid_mismatch_fails() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/negative/keyset_addattribute_uid_mismatch_fails").await
    }

    // ─── Keyset sign/verify chain walk ────────────────────────────────────

    #[tokio::test]
    async fn test_vec_keyset_ec_sign_verify_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_ec_sign_verify_chain").await
    }

    #[tokio::test]
    async fn test_vec_keyset_mac_verify_chain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_mac_verify_chain").await
    }

    // ─── Keyset GetAttributes resolution ─────────────────────────────────

    #[tokio::test]
    async fn test_vec_keyset_getattributes_resolution() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/keyset_getattributes_resolution")
            .await
    }

    // ─── ReCertify gaps ──────────────────────────────────────────────────

    // The CreateKeyPair step uses ECDH + mask in CommonAttributes, consistent
    // with all other ReCertify test vectors (which are also #[cfg(feature = "non-fips")]).
    // In FIPS mode the private_key_mask must be explicit in PrivateKeyAttributes;
    // a CommonAttributes-only mask gives None and fails the FIPS check.
    #[cfg(feature = "non-fips")]
    #[tokio::test]
    async fn test_vec_recertify_old_cert_stays_active() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/fips/kmip_operations/recertify_old_cert_stays_active")
            .await
    }

    // ── Auto-discovered KMIP version-matrix vectors ─────────────────────────

    /// Walks `test_data/vectors/fips/kmip_versions/` and runs every vector
    /// directory that contains a `manifest.toml`.
    ///
    /// This avoids manually registering hundreds of version × operation
    /// combinations. Failures report the vector directory name so you can
    /// re-run a single vector via:
    /// ```
    /// cargo test -p test_kms_server --lib -- kmip_version_matrix
    /// ```
    #[tokio::test]
    async fn test_kmip_version_matrix() -> Result<(), KmsClientError> {
        crate::init_test_logging();

        let root = super::repo_root()?;
        let base = root.join("test_data/vectors/fips/kmip_versions");
        if !base.exists() {
            eprintln!("Skipping kmip_version_matrix: {base:?} not found");
            return Ok(());
        }

        let mut vector_dirs: Vec<std::path::PathBuf> = Vec::new();
        // Walk version subdirectories (v1_0, v1_1, …)
        let mut versions: Vec<_> = std::fs::read_dir(&base)
            .map_err(|e| KmsClientError::Default(format!("read_dir {base:?}: {e}")))?
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
            .map(|e| e.path())
            .collect();
        versions.sort();
        for ver_dir in versions {
            let mut ops: Vec<_> = std::fs::read_dir(&ver_dir)
                .map_err(|e| KmsClientError::Default(format!("read_dir {ver_dir:?}: {e}")))?
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
                .map(|e| e.path())
                .collect();
            ops.sort();
            for op_dir in ops {
                if op_dir.join("manifest.toml").exists() {
                    vector_dirs.push(op_dir);
                }
            }
        }

        eprintln!(
            "kmip_version_matrix: discovered {} vectors",
            vector_dirs.len()
        );

        let mut failures: Vec<(String, String)> = Vec::new();
        for dir in &vector_dirs {
            // run_test_vector expects a path relative to the repo root
            let rel_path = dir.strip_prefix(&root).unwrap_or(dir);
            let dir_str = rel_path.to_string_lossy().to_string();
            eprintln!("Running vector: {dir_str}");
            match run_test_vector(&dir_str).await {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("FAILED: {dir_str}: {e}");
                    failures.push((dir_str, e.to_string()));
                }
            }
        }

        if !failures.is_empty() {
            let report = failures
                .iter()
                .map(|(dir, err)| format!("  {dir}\n    {err}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(KmsClientError::Default(format!(
                "{} of {} vectors failed:\n{report}",
                failures.len(),
                vector_dirs.len()
            )));
        }

        eprintln!(
            "kmip_version_matrix: all {} vectors passed",
            vector_dirs.len()
        );
        Ok(())
    }

    // ── OPA authorization policy vectors ────────────────────────────────────────
    // Mode 1 (disabled): no OPA — baseline that proves the infrastructure does not
    // break normal owner operations.
    // Mode 2 (exclusive): OPA is the sole authority; KMS legacy check is skipped.
    // Mode 3 (enforcing): both OPA and KMS legacy must allow.
    //
    // "allowed" variants require KMS_OPA_URL + KMS_AUTH_SERVER_URL (real services).
    // "denied"  variants require KMS_OPA_URL only (mTLS two-cert scenario).
    // All four external-service tests skip gracefully when the env vars are absent.
    //
    // auth_verifier variants exercise the `AuthVerifier` bearer-token middleware path
    // (handle_auth_verifier → roles + domain extracted from JWT) as opposed to the
    // OIDC jwt_auth_provider path tested by the standard "allowed" variants.

    /// Singleton OPA-enabled KMS servers (one per mode × `test_type`).
    static ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED: OnceCell<TestsContext> = OnceCell::const_new();
    /// Shared cert-auth OPA server for both exclusive and enforcing "denied" variants.
    /// Both modes exercise the same scenario (non-owner, no roles → deny), so a single
    /// server avoids concurrent macOS Keychain PKCS#12 loading conflicts.
    static ONCE_VECTOR_OPA_DENIED: OnceCell<TestsContext> = OnceCell::const_new();
    static ONCE_VECTOR_OPA_ENFORCING_ALLOWED: OnceCell<TestsContext> = OnceCell::const_new();
    /// Auth Verifier path: exclusive mode — exercises `handle_auth_verifier` (not `handle_jwt`).
    static ONCE_VECTOR_OPA_AUTH_VERIFIER_EXCLUSIVE: OnceCell<TestsContext> = OnceCell::const_new();
    /// Auth Verifier path: enforcing mode.
    static ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING: OnceCell<TestsContext> = OnceCell::const_new();
    /// Auth Verifier path: exclusive mode, `SuperAdmin` JWT as the owner.
    /// Separate cell so the `SuperAdmin` test owns its own server and its JWT
    /// is always used for initialization regardless of test execution order.
    static ONCE_VECTOR_OPA_AUTH_VERIFIER_SUPER_ADMIN: OnceCell<TestsContext> =
        OnceCell::const_new();
    /// OPA exclusive mode + cert auth + NO `crypto_officer_users`: proves native KMS
    /// COs without JWT cannot create in exclusive mode (OPA is sole authority).
    static ONCE_VECTOR_OPA_EXCLUSIVE_NATIVE_CO_DENIED: OnceCell<TestsContext> =
        OnceCell::const_new();
    /// OPA enforcing mode + cert auth + `crypto_officer_users` set: proves native KMS
    /// COs (privileged, no JWT) can create because the KMS privilege bypass applies
    /// in enforcing mode (not exclusive mode).
    static ONCE_VECTOR_OPA_ENFORCING_NATIVE_CO_ALLOWED: OnceCell<TestsContext> =
        OnceCell::const_new();

    /// Start (or reuse) an OPA-enabled KMS server for "allowed" vectors.
    ///
    /// Reads the `CryptoOfficer` JWT from `KMS_TEST_OPA_OFFICER_JWT`, which must be
    /// set by the `mise test:opa_rbac` bash script before invoking this test.
    /// The script starts the auth server, provisions test users via
    /// `provision_opa_users.sh`, and exports all required JWT env vars.
    ///
    /// Returns `None` when `KMS_OPA_URL`, `KMS_AUTH_SERVER_URL`, or
    /// `KMS_TEST_OPA_OFFICER_JWT` is not set (graceful skip instead of failure).
    ///
    /// Required env vars (set by the bash script):
    ///   `KMS_OPA_URL`                       — OPA REST API base URL
    ///   `KMS_AUTH_SERVER_URL`               — auth server JWKS base URL
    ///   `KMS_TEST_OPA_OFFICER_JWT`          — `CryptoOfficer` JWT (kms-opa-test)
    ///   `KMS_TEST_OPA_USER_ROLE_JWT`        — User role JWT (kms-opa-test)
    ///   `KMS_TEST_OPA_AUDITOR_JWT`          — Auditor JWT (kms-opa-test)
    ///   `KMS_TEST_OPA_DOMAIN_ADMIN_OTHER_JWT` — `DomainAdmin` JWT (kms-opa-other)
    ///   `KMS_TEST_OPA_OTHER_DOMAIN_JWT`     — `CryptoOfficer` JWT (kms-opa-other)
    /// Start (or reuse) an OPA-enabled KMS server for "allowed" vectors.
    ///
    /// Patches `auth/plain.toml` with OPA URL, mode, and a `IdP` pointing to the
    /// auth server's JWKS endpoint. The owner client sends the `CryptoOfficer` JWT
    /// as a Bearer token; since KMS test mode uses `insecure_decode`, no real
    /// JWKS fetch occurs and the JWT is accepted as-is.
    ///
    /// Returns `None` when `KMS_OPA_URL`, `KMS_AUTH_SERVER_URL`, or
    /// `KMS_TEST_OPA_OFFICER_JWT` is not set.
    async fn get_or_init_opa_allowed_server(
        cell: &'static OnceCell<TestsContext>,
        opa_mode: &'static str,
    ) -> Result<Option<&'static TestsContext>, KmsClientError> {
        let Ok(opa_url) = std::env::var("KMS_OPA_URL") else {
            return Ok(None);
        };
        let Ok(auth_server_url) = std::env::var("KMS_AUTH_SERVER_URL") else {
            return Ok(None);
        };

        // Read the pre-provisioned CryptoOfficer JWT set by the bash script
        // (test_opa_rbac.sh Phase 3 / provision_opa_users.sh).
        let Ok(officer_jwt) = std::env::var("KMS_TEST_OPA_OFFICER_JWT") else {
            eprintln!(
                "SKIP: KMS_TEST_OPA_OFFICER_JWT not set — \
                 run `mise test:opa_rbac` to provision users and export JWT env vars"
            );
            return Ok(None);
        };

        let config_path = crate::test_config_path("auth/plain.toml");
        let ctx = cell
            .get_or_try_init(|| {
                let opa_url_c = opa_url.clone();
                let auth_url_c = auth_server_url.clone();
                let jwt_c = officer_jwt.clone();
                async move {
                    crate::start_test_server_with_patch(
                        &config_path,
                        move |cfg| {
                            cfg.opa.opa_url = Some(opa_url_c);
                            cfg.opa.opa_mode = opa_mode.to_owned();
                            cfg.idp_auth.jwt_auth_provider = Some(vec![format!(
                                "cosmian-auth-test,{auth_url_c}/public/jwks"
                            )]);
                            // Disable Google CSE: auth/plain.toml enables it, but server
                            // startup tries to create the CSE RSA key as the default user
                            // who has no OPA roles → denied in enforcing/exclusive mode.
                            cfg.google_cse_config.google_cse_enable = false;
                        },
                        crate::TestClientOptions {
                            http: cosmian_kms_client::reexport::cosmian_http_client::HttpClientConfig {
                                access_token: Some(jwt_c),
                                ..Default::default()
                            },
                            send_jwt: false,
                            send_client_cert: false,
                            send_api_token: true,
                        },
                    )
                    .await
                }
            })
            .await?;

        Ok(Some(ctx))
    }

    /// Start (or reuse) an OPA-enabled KMS server for "denied" vectors.
    ///
    /// Patches `auth/cert.toml` with OPA URL + mode. The two TLS identities
    /// (owner cert vs user cert) map to distinct KMS usernames. The user cert
    /// has no JWT → no roles → OPA denies (not owner, no `SuperAdmin`/`CryptoOfficer`).
    ///
    /// Returns `None` when `KMS_OPA_URL` is not set.
    async fn get_or_init_opa_denied_server(
        cell: &'static OnceCell<TestsContext>,
        opa_mode: &'static str,
    ) -> Result<Option<&'static TestsContext>, KmsClientError> {
        let Ok(opa_url) = std::env::var("KMS_OPA_URL") else {
            return Ok(None);
        };

        let config_path = crate::test_config_path("auth/cert.toml");
        let ctx = cell
            .get_or_try_init(|| {
                let opa_url_c = opa_url.clone();
                async move {
                    crate::start_test_server_with_patch(
                        &config_path,
                        move |cfg| {
                            cfg.opa.opa_url = Some(opa_url_c);
                            cfg.opa.opa_mode = opa_mode.to_owned();
                            // Use a dedicated port so the OPA denied server does not
                            // conflict with ONCE_VECTOR_CERT_AUTH (auth/cert.toml port 9999).
                            cfg.http.port = 13001;
                            // Disable Google CSE: auth/cert.toml enables it, but the OPA
                            // server startup would try to create the CSE RSA key as the
                            // default user who has no OPA roles → denied in enforcing mode.
                            cfg.google_cse_config.google_cse_enable = false;
                            // The test vector owner uses mTLS cert with CN "owner.client@acme.com".
                            // Cert-auth users carry no JWT roles, so OPA would deny their Create.
                            // Adding the owner as a privileged_user lets the KMS bypass OPA for
                            // the Create step while OPA still denies the non-owner cert user for
                            // all subsequent operations (Get, Destroy).
                            cfg.privileged_users = Some(vec!["owner.client@acme.com".to_owned()]);
                            // Disable the socket server to avoid conflicting on the
                            // fixed socket port across concurrent test processes.
                            cfg.socket_server.socket_server_start = false;
                            cfg.db.sqlite_path =
                                PathBuf::from(format!("/tmp/kms_test_opa_{opa_mode}_denied"));
                            cfg.workspace.root_data_path =
                                PathBuf::from(format!("/tmp/kms_test_opa_{opa_mode}_denied_ws"));
                        },
                        crate::TestClientOptions::default(),
                    )
                    .await
                }
            })
            .await?;

        Ok(Some(ctx))
    }

    #[tokio::test]
    async fn test_vec_opa_mode_disabled() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        run_test_vector("test_data/vectors/opa/mode_disabled").await
    }

    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_allowed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_allowed", ctx).await
    }

    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_denied_server(&ONCE_VECTOR_OPA_DENIED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_denied", ctx).await
    }

    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_allowed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_ENFORCING_ALLOWED, "enforcing").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_enforcing_allowed", ctx).await
    }

    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        // Reuse the shared denied server (same deny reason: non-owner, no roles).
        // Both exclusive and enforcing deny via OPA; the mode check only differs
        // in whether legacy KMS access control is also checked (both deny here).
        let Some(ctx) = get_or_init_opa_denied_server(&ONCE_VECTOR_OPA_DENIED, "enforcing").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_enforcing_denied", ctx).await
    }

    /// OPA negative: `User` role cannot `Get` (export key material) on a non-owned key.
    ///
    /// The `user_ops` set in `kms.rego` deliberately excludes `Get` (which exposes raw key
    /// bytes).  Even though the user has a valid JWT and a recognised role, OPA returns
    /// `allow = false` because `Get ∉ user_ops`.
    ///
    /// Requires `KMS_OPA_URL` + `KMS_AUTH_SERVER_URL`; JWT env vars are provisioned by
    /// `mise test:opa_rbac` / `provision_opa_users.sh`.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_user_role_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_user_role_denied", ctx)
            .await
    }

    /// OPA negative: cross-domain isolation — `CryptoOfficer` in domain `kms-opa-other`
    /// must NOT access objects created in domain `kms-opa-test`.
    ///
    /// The `same_domain` helper in `kms.rego` requires `input.user_domain ==
    /// input.object_domain`.  A `CryptoOfficer` with `as_domain = "kms-opa-other"` trying
    /// to `Get` a key owned by `kms-opa-test` fails this check → `allow = false`.
    ///
    /// Requires `KMS_OPA_URL` + `KMS_AUTH_SERVER_URL`; JWT env vars are provisioned by
    /// `mise test:opa_rbac` / `provision_opa_users.sh`.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_wrong_domain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_wrong_domain", ctx).await
    }

    /// OPA negative: `Auditor` role denied `Destroy` — not in `auditor_ops`.
    ///
    /// The `auditor_ops` set in `kms.rego` grants read-only metadata access
    /// (`Locate`, `Get`, `GetAttributes`, …). `Destroy` is a key-lifecycle
    /// operation reserved for `CryptoOfficer`/`DomainAdmin`. Even with a valid
    /// JWT and the `Auditor` role, OPA returns `allow = false`.
    ///
    /// Ref: kms.rego `auditor_ops` set (NIST SP 800-53 AU-9 separation-of-duties;
    ///      PCI-DSS v4.0 Req 10 — auditor must not be able to erase evidence).
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auditor_destroy_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_auditor_destroy_denied",
            ctx,
        )
        .await
    }

    /// OPA positive: `Auditor` role allowed `GetAttributes` on a non-owned key.
    ///
    /// `GetAttributes` IS in `auditor_ops` and the Auditor's domain matches the
    /// key's domain (`kms-opa-test`). OPA returns `allow = true` without the
    /// Auditor owning the key or having been granted access by the owner.
    /// This validates the domain-scoped read-only path end-to-end.
    ///
    /// Ref: kms.rego `auditor_ops` set; NIST SP 800-57 Part 2 §4.3.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auditor_get_attributes_allowed()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_auditor_get_attributes_allowed",
            ctx,
        )
        .await
    }

    /// OPA negative: `DomainAdmin` in `kms-opa-other` denied access to a key
    /// that belongs to `kms-opa-test`.
    ///
    /// `DomainAdmin` has full control — but only within their own domain
    /// (the `same_domain` helper fails when `user_domain != object_domain`).
    /// This proves domain isolation holds even for the most privileged non-super role.
    ///
    /// Ref: kms.rego `DomainAdmin` rule (ANSI/INCITS 359-2004 §4.2 Constrained RBAC;
    ///      NIST SP 800-53 Rev 5 AC-6 least privilege).
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_domain_admin_wrong_domain() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_domain_admin_wrong_domain",
            ctx,
        )
        .await
    }

    /// OPA positive: multi-tenancy — `CryptoOfficer` in `kms-opa-other` domain
    /// can create, retrieve, and destroy their own key within their own domain.
    ///
    /// Counterpart to `mode_exclusive_wrong_domain`: proves that domain isolation
    /// blocks cross-domain access but does NOT block intra-domain operations.
    /// The `same_domain` helper succeeds because `user_domain == object_domain ==
    /// kms-opa-other`.
    ///
    /// Requires `KMS_OPA_URL`, `KMS_AUTH_SERVER_URL`, and `KMS_TEST_OPA_OTHER_DOMAIN_JWT`
    /// (set by `mise test:opa_rbac` / `provision_opa_users.sh`).
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_other_domain_allowed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) =
            get_or_init_opa_allowed_server(&ONCE_VECTOR_OPA_EXCLUSIVE_ALLOWED, "exclusive").await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac` to provision auth server and OPA"
                    .to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_other_domain_allowed",
            ctx,
        )
        .await
    }

    // ── Auth Verifier bearer-token path (exercises `handle_auth_verifier`) ──────
    //
    // The tests above all use `jwt_auth_provider` → `handle_jwt` to extract roles
    // and domain.  The tests below use the `AuthVerifier` middleware path (as
    // configured by `[auth_verifier]` in the server TOML), which formerly lost
    // `roles` and `domain` because `AuthVerifierClaims` only carried `sub`.
    //
    // Required env vars (same as the "allowed" variants above, plus SuperAdmin JWT):
    //   `KMS_OPA_URL`                  — OPA REST API base URL
    //   `KMS_AUTH_SERVER_URL`          — Cosmian auth server HTTPS URL
    //   `KMS_TEST_OPA_SUPER_ADMIN_JWT` — SuperAdmin JWT (kms-opa-test realm)
    //   `KMS_TEST_OPA_OFFICER_JWT`     — CryptoOfficer JWT (kms-opa-test realm)
    //   `KMS_TEST_OPA_AUDITOR_JWT`     — Auditor JWT (kms-opa-test realm)
    //   `KMS_TEST_OPA_USER_ROLE_JWT`   — User role JWT (kms-opa-test realm)

    /// Start (or reuse) an OPA-enabled KMS server configured with the `AuthVerifier`
    /// bearer-token middleware (not `jwt_auth_provider`).
    ///
    /// This is the production configuration used when `[auth_verifier]` is set in
    /// `opa.toml`. The bearer token is processed by `handle_auth_verifier`, which
    /// (after the bug fix) extracts `roles` and `domain` (`as_rid`) from the JWT.
    ///
    /// Returns `None` when `KMS_OPA_URL`, `KMS_AUTH_SERVER_URL`, or
    /// `KMS_TEST_OPA_OFFICER_JWT` is not set.
    async fn get_or_init_opa_auth_verifier_server(
        cell: &'static OnceCell<TestsContext>,
        opa_mode: &'static str,
        jwt_env: &'static str,
    ) -> Result<Option<&'static TestsContext>, KmsClientError> {
        let Ok(opa_url) = std::env::var("KMS_OPA_URL") else {
            return Ok(None);
        };
        let Ok(auth_server_url) = std::env::var("KMS_AUTH_SERVER_URL") else {
            return Ok(None);
        };
        let Ok(owner_jwt) = std::env::var(jwt_env) else {
            eprintln!(
                "SKIP: {jwt_env} not set — \
                 run `mise test:opa_rbac` to provision users and export JWT env vars"
            );
            return Ok(None);
        };

        let config_path = crate::test_config_path("auth/plain.toml");
        let ctx = cell
            .get_or_try_init(|| {
                let opa_url_c = opa_url.clone();
                let auth_url_c = auth_server_url.clone();
                let jwt_c = owner_jwt.clone();
                async move {
                    crate::start_test_server_with_patch(
                        &config_path,
                        move |cfg| {
                            cfg.opa.opa_url = Some(opa_url_c);
                            cfg.opa.opa_mode = opa_mode.to_owned();
                            // Configure the AuthVerifier middleware — the path under test.
                            // Use `/public/jwks` (the auth server's JWKS endpoint) as the
                            // explicit JWKS URI; the default `/.well-known/jwks.json` may not
                            // be available on the test auth server.
                            cfg.auth_verifier.auth_verifier_url = Some(auth_url_c.clone());
                            cfg.auth_verifier.auth_verifier_jwks_uri =
                                Some(format!("{auth_url_c}/public/jwks"));
                            cfg.auth_verifier.auth_verifier_realm =
                                Some(vec!["kms-opa-test".to_owned()]);
                            // Accept the self-signed test TLS certificate.
                            cfg.auth_verifier.auth_verifier_accept_invalid_certs = true;
                            // Disable the OIDC jwt_auth_provider — we want only the
                            // AuthVerifier middleware active so bearer tokens are routed
                            // through `handle_auth_verifier` (the path that was broken).
                            cfg.idp_auth.jwt_auth_provider = None;
                            // Disable Google CSE: startup would create a CSE RSA key as the
                            // default user who has no OPA roles → denied in exclusive/enforcing.
                            cfg.google_cse_config.google_cse_enable = false;
                            // Unique SQLite paths per auth_verifier + mode + jwt combination
                            // so concurrent test suites don't share the same database file.
                            let tag = format!("opa_av_{opa_mode}_{jwt_env}");
                            cfg.db.sqlite_path =
                                PathBuf::from(format!("/tmp/kms_test_{tag}"));
                            cfg.workspace.root_data_path =
                                PathBuf::from(format!("/tmp/kms_test_{tag}_ws"));
                        },
                        crate::TestClientOptions {
                            http: cosmian_kms_client::reexport::cosmian_http_client::HttpClientConfig {
                                access_token: Some(jwt_c),
                                ..Default::default()
                            },
                            send_jwt: false,
                            send_client_cert: false,
                            send_api_token: true,
                        },
                    )
                    .await
                }
            })
            .await?;

        Ok(Some(ctx))
    }

    /// Auth Verifier path — OPA exclusive: `CryptoOfficer` can run the full
    /// key-lifecycle flow (Create → Get → Destroy) via the `AuthVerifier` middleware.
    ///
    /// Regression test for the bug where `handle_auth_verifier` did not extract
    /// `roles` or `domain` from the JWT, causing OPA to see `input.roles = []`
    /// and deny all non-owner operations.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auth_verifier_officer_allowed()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_EXCLUSIVE,
            "exclusive",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_allowed", ctx).await
    }

    /// Auth Verifier path — OPA enforcing: `CryptoOfficer` can run the full
    /// key-lifecycle flow via the `AuthVerifier` middleware with enforcing mode
    /// (both OPA and native KMS access control must allow).
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_auth_verifier_officer_allowed()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING,
            "enforcing",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_enforcing_allowed", ctx).await
    }

    /// Auth Verifier path — `SuperAdmin` can create a key in exclusive OPA mode.
    ///
    /// `SuperAdmin` is the top of the role hierarchy (ANSI/INCITS 359 §4.2):
    /// OPA's `allow if { input.roles[_] == "SuperAdmin" }` rule applies regardless
    /// of domain. This test verifies that the `auth_verifier` path correctly forwards
    /// the `SuperAdmin` role to OPA so it can make the right decision.
    ///
    /// This was the failing scenario reported in the bug: a user with role `SuperAdmin`
    /// received `401: User does not have create access-right` because `roles` was
    /// always `[]` in `handle_auth_verifier`.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auth_verifier_super_admin_allowed()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        // Dedicated cell so the SuperAdmin JWT is used for server init regardless
        // of the order in which auth_verifier tests run.
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_SUPER_ADMIN,
            "exclusive",
            "KMS_TEST_OPA_SUPER_ADMIN_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_allowed", ctx).await
    }

    /// Auth Verifier path — `User` role denied `Get` (key export) on a non-owned key.
    ///
    /// The `user_ops` set in `kms.rego` excludes `Get` to prevent raw key-material
    /// export by non-owners. This verifies that the `auth_verifier` path correctly
    /// forwards the `User` role so OPA can deny the operation.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auth_verifier_user_role_denied()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_EXCLUSIVE,
            "exclusive",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context("test_data/vectors/opa/mode_exclusive_user_role_denied", ctx)
            .await
    }

    /// Auth Verifier path — `Auditor` role denied `Destroy` on a key.
    ///
    /// `Destroy` is not in `auditor_ops`. This verifies that the `Auditor` role
    /// is correctly forwarded through the `auth_verifier` path to OPA.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_auth_verifier_auditor_destroy_denied()
    -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_EXCLUSIVE,
            "exclusive",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_auditor_destroy_denied",
            ctx,
        )
        .await
    }

    // ── Enforcing mode: Gate 2 (KMS legacy) no longer re-denies OPA-approved ops ──

    /// OPA enforcing: Auditor (non-owner, same domain) can `GetAttributes` on a key
    /// they don't own.
    ///
    /// Regression test for the bug where in enforcing mode the KMS legacy ownership
    /// check (Gate 2) re-denied operations that OPA Gate 1 already approved.
    /// Symptom: Web UI Locate page showed all fields as N/A except the UID.
    ///
    /// After the fix: OPA approval is authoritative for non-HSM objects in enforcing
    /// mode; `user_has_permission` returns `Ok(true)` immediately after OPA allows.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_co_get_attributes_allowed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING,
            "enforcing",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_enforcing_co_get_attributes_allowed",
            ctx,
        )
        .await
    }

    // ── Negative: enforcing mode — bad/empty JWT roles ───────────────────────

    /// Start (or reuse) an OPA+cert KMS server for native-CO cert tests.
    ///
    /// `add_co_users`: when `true`, sets `crypto_officer_users = ["owner.client@acme.com"]`
    /// so the cert user is privileged and bypasses OPA in enforcing mode.
    /// When `false`, no CO list is set → cert user is not privileged → OPA check runs.
    ///
    /// Returns `None` when `KMS_OPA_URL` is not set.
    async fn get_or_init_opa_native_co_server(
        cell: &'static OnceCell<TestsContext>,
        opa_mode: &'static str,
        add_co_users: bool,
        db_tag: &'static str,
    ) -> Result<Option<&'static TestsContext>, KmsClientError> {
        let Ok(opa_url) = std::env::var("KMS_OPA_URL") else {
            return Ok(None);
        };

        let config_path = crate::test_config_path("auth/cert.toml");
        let ctx = cell
            .get_or_try_init(|| {
                let opa_url_c = opa_url.clone();
                async move {
                    crate::start_test_server_with_patch(
                        &config_path,
                        move |cfg| {
                            cfg.opa.opa_url = Some(opa_url_c);
                            cfg.opa.opa_mode = opa_mode.to_owned();
                            if add_co_users {
                                // Privileged cert CO: KMS bypasses OPA Gate 1 in enforcing mode.
                                cfg.roles.crypto_officer_users =
                                    Some(vec!["owner.client@acme.com".to_owned()]);
                            }
                            cfg.google_cse_config.google_cse_enable = false;
                            cfg.socket_server.socket_server_start = false;
                            cfg.db.sqlite_path =
                                PathBuf::from(format!("/tmp/kms_test_opa_{db_tag}"));
                            cfg.workspace.root_data_path =
                                PathBuf::from(format!("/tmp/kms_test_opa_{db_tag}_ws"));
                        },
                        crate::TestClientOptions::default(),
                    )
                    .await
                }
            })
            .await?;

        Ok(Some(ctx))
    }

    /// OPA enforcing: empty JWT roles deny Create.
    ///
    /// A bearer token with `roles: []` (no role assigned) is sent. OPA evaluates
    /// no allow rule → deny. Proves that a misconfigured or role-free token cannot
    /// bypass Gate 1 in enforcing mode.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_empty_roles_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING,
            "enforcing",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_enforcing_empty_roles_denied",
            ctx,
        )
        .await
    }

    /// OPA enforcing: unknown role denies Create.
    ///
    /// A bearer token with `roles: ["Hacker"]` is sent. No allow rule in kms.rego
    /// matches this role name → deny.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_unknown_role_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING,
            "enforcing",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_enforcing_unknown_role_denied",
            ctx,
        )
        .await
    }

    /// OPA enforcing: Auditor role denied Create.
    ///
    /// `Create` is not in `auditor_ops` (auditors are read-only). Even in enforcing
    /// mode, OPA Gate 1 blocks the operation before KMS Gate 2 is reached.
    #[tokio::test]
    #[ignore = "requires OPA + auth server: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_auditor_create_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_auth_verifier_server(
            &ONCE_VECTOR_OPA_AUTH_VERIFIER_ENFORCING,
            "enforcing",
            "KMS_TEST_OPA_OFFICER_JWT",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "required env vars not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_enforcing_auditor_create_denied",
            ctx,
        )
        .await
    }

    // ── Cert-auth native KMS CO: exclusive denied / enforcing allowed ─────────

    /// OPA exclusive: native KMS CO (cert, not in `crypto_officer_users`) denied Create.
    ///
    /// The server is configured WITHOUT `crypto_officer_users`. The mTLS cert client
    /// has no JWT → OPA receives `input.roles = []` → deny. OPA is the sole authority
    /// in exclusive mode; the KMS privilege bypass does not apply.
    #[tokio::test]
    #[ignore = "requires OPA: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_exclusive_native_co_cert_denied() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_native_co_server(
            &ONCE_VECTOR_OPA_EXCLUSIVE_NATIVE_CO_DENIED,
            "exclusive",
            false, // no crypto_officer_users → cert user is not privileged
            "exclusive_native_co_denied",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "KMS_OPA_URL not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_exclusive_native_co_cert_denied",
            ctx,
        )
        .await
    }

    /// OPA enforcing: native KMS CO (cert, in `crypto_officer_users`) allowed Create.
    ///
    /// The server is configured with `crypto_officer_users = ["owner.client@acme.com"]`.
    /// The privileged cert user bypasses OPA Gate 1 (KMS native trust in enforcing mode),
    /// then passes Gate 2 as the object owner → Create succeeds.
    ///
    /// Counterpart to `test_vec_opa_mode_exclusive_native_co_cert_denied`: shows that
    /// the same cert user IS allowed in enforcing mode when explicitly privileged.
    #[tokio::test]
    #[ignore = "requires OPA: run via `mise test:opa_rbac`"]
    async fn test_vec_opa_mode_enforcing_native_co_cert_allowed() -> Result<(), KmsClientError> {
        crate::init_test_logging();
        let Some(ctx) = get_or_init_opa_native_co_server(
            &ONCE_VECTOR_OPA_ENFORCING_NATIVE_CO_ALLOWED,
            "enforcing",
            true, // crypto_officer_users set → cert user IS privileged
            "enforcing_native_co_allowed",
        )
        .await?
        else {
            return Err(KmsClientError::Default(
                "KMS_OPA_URL not set — run `mise test:opa_rbac`".to_owned(),
            ));
        };
        run_test_vector_with_context(
            "test_data/vectors/opa/mode_enforcing_native_co_cert_allowed",
            ctx,
        )
        .await
    }
}

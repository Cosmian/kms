//! JSON request/response types for the Vault KV v2-compatible `/kv/` API.
//!
//! The wire format follows Vault KV v2: every response is wrapped in a
//! top-level `data` envelope; version metadata uses `created_time`
//! (RFC 3339), `deletion_time` (RFC 3339, or `""` when not deleted), and
//! `destroyed` (bool).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// `POST /<mount>/data/{path}` request body.
#[derive(Deserialize)]
pub(crate) struct PutSecretRequest {
    /// Arbitrary key/value pairs — the secret payload itself.
    pub data: HashMap<String, serde_json::Value>,
    /// Vault KV v2 `options` block.
    #[serde(default)]
    pub options: PutSecretOptions,
}

/// `options` block of a put request.
///
/// `ttl` is a Cosmian extension (see issue #863 acceptance criteria), not part
/// of stock Vault KV v2: when set, the written version is destroyed
/// automatically once the duration elapses (checked by the KV TTL cron tick).
#[derive(Deserialize, Default)]
pub(crate) struct PutSecretOptions {
    pub ttl: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DataWrapper<T> {
    pub data: T,
}

/// `data` payload of a successful `PUT`/`POST` response.
#[derive(Serialize)]
pub(crate) struct PutSecretData {
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
}

/// `data` payload of a successful `GET .../data/{path}` response.
#[derive(Serialize)]
pub(crate) struct GetSecretData {
    pub data: HashMap<String, serde_json::Value>,
    pub metadata: VersionMetadata,
}

/// Per-version metadata, shared by the `data` and `metadata` response shapes.
#[derive(Serialize, Deserialize, Clone, Default)]
pub(crate) struct VersionMetadata {
    pub version: u64,
    pub created_time: String,
    #[serde(default)]
    pub deletion_time: String,
    #[serde(default)]
    pub destroyed: bool,
}

/// `data` payload of a successful `GET .../metadata/{path}` response.
#[derive(Serialize)]
pub(crate) struct ReadMetadataResponseData {
    pub current_version: u64,
    pub oldest_version: u64,
    pub created_time: String,
    pub updated_time: String,
    pub versions: HashMap<String, VersionMetadata>,
}

/// `data` payload of a successful `GET .../metadata/{prefix}?list=true` response.
#[derive(Serialize)]
pub(crate) struct ListData {
    pub keys: Vec<String>,
}

/// `data` payload of `GET /v1/sys/internal/ui/mounts/{path}`, read by the `vault`/`bao` CLI
/// pre-flight to choose between KV v1 and v2.
#[derive(Serialize)]
pub(crate) struct MountInfo {
    /// Mount path with a trailing slash, as Vault reports it.
    pub path: String,
    #[serde(rename = "type")]
    pub mount_type: &'static str,
    pub description: &'static str,
    pub options: MountOptions,
}

/// `options` of a mount; `version = "2"` selects the KV v2 wire format in the CLI.
#[derive(Serialize)]
pub(crate) struct MountOptions {
    pub version: &'static str,
}

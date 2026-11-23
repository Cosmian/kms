//! JSON request/response types for the Vault KV v2-compatible `/kv/` API.
//!
//! The wire format follows Vault KV v2: every response is wrapped in a
//! top-level `data` envelope; version metadata uses `created_time`
//! (RFC 3339), `deletion_time` (RFC 3339, or `""` when not deleted), and
//! `destroyed` (bool).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::Zeroize;

/// A secret payload: a JSON object of arbitrary values whose strings, nested strings and keys
/// are wiped when it is dropped. Intentionally neither `Debug` nor `Clone`.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub(crate) struct KvSecretMap(pub Map<String, Value>);

impl Drop for KvSecretMap {
    fn drop(&mut self) {
        zeroize_map(&mut self.0);
    }
}

/// Wipe every key and string held by `map`, recursively, and empty it.
fn zeroize_map(map: &mut Map<String, Value>) {
    for (mut key, mut value) in std::mem::take(map) {
        zeroize_value(&mut value);
        key.zeroize();
    }
}

/// Wipe every string held by `value`, recursively. Numbers have no wipeable storage.
fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(zeroize_value),
        Value::Object(map) => zeroize_map(map),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// `POST /<mount>/data/{path}` request body.
#[derive(Deserialize)]
pub(crate) struct PutSecretRequest {
    /// Arbitrary JSON object — the secret payload itself.
    pub data: KvSecretMap,
    /// Vault KV v2 `options` block.
    #[serde(default)]
    pub options: PutSecretOptions,
}

/// `options` block of a put request.
#[derive(Deserialize, Default)]
pub(crate) struct PutSecretOptions {
    /// Cosmian extension: the written version is destroyed once this duration elapses.
    pub ttl: Option<String>,
    /// Vault check-and-set: `0` writes only if the path does not exist, `N` only if the
    /// current version is `N`.
    pub cas: Option<u64>,
    /// Cosmian extension: the owner the caller expects the path to have. Required to write a
    /// path owned by another identity; must name the caller when the path does not exist.
    pub expected_owner: Option<String>,
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
    pub data: KvSecretMap,
    pub metadata: VersionMetadata,
}

/// Per-version metadata, shared by the `data` and `metadata` response shapes.
#[derive(Serialize)]
pub(crate) struct VersionMetadata {
    pub version: u64,
    pub created_time: String,
    pub deletion_time: String,
    pub destroyed: bool,
}

/// `data` payload of a successful `GET .../metadata/{path}` response.
#[derive(Serialize)]
pub(crate) struct ReadMetadataResponseData {
    pub current_version: u64,
    pub oldest_version: u64,
    pub created_time: String,
    pub updated_time: String,
    pub versions: BTreeMap<u64, VersionMetadata>,
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn zeroize_wipes_nested_strings_and_keeps_scalars() {
        let mut value = json!(["secret", ["x", {"c": "y"}], 7, true]);
        zeroize_value(&mut value);
        assert_eq!(value, json!(["", ["", {}], 7, true]));
        let mut map = json!({"k": "v"});
        zeroize_value(&mut map);
        // Maps are emptied once their keys and values are wiped.
        assert_eq!(map, json!({}));
    }

    #[test]
    fn secret_map_round_trips_arbitrary_json_values() {
        let input = json!({"s": "v", "n": 1.5, "i": -3, "b": false, "z": null,
                           "a": [1, "two", {"three": [3]}], "o": {"deep": {"er": "x"}}});
        let map: KvSecretMap = serde_json::from_value(input.clone()).expect("valid object");
        assert_eq!(serde_json::to_value(&map).expect("serializable"), input);
    }

    #[test]
    fn put_request_rejects_non_object_data() {
        for body in [
            json!({"data": "x"}),
            json!({"data": [1]}),
            json!({"data": null}),
            json!({}),
        ] {
            assert!(
                serde_json::from_value::<PutSecretRequest>(body.clone()).is_err(),
                "{body}"
            );
        }
    }
}

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ── CRD spec ──────────────────────────────────────────────────────────────────

/// `KMSSecret` CRD — tells the operator to materialise a Cosmian KMS object
/// into a Kubernetes `Secret`.
///
/// Example:
/// ```yaml
/// apiVersion: kms.cosmian.com/v1
/// kind: KMSSecret
/// metadata:
///   name: postgres-credentials
///   namespace: velo-infra
/// spec:
///   secretId: "5f3a1b2c-…"
///   targetSecret: postgres-credentials
///   key: password
///   refreshInterval: 1h
/// ```
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "kms.cosmian.com",
    version = "v1",
    kind = "KMSSecret",
    namespaced,
    status = "KMSSecretStatus",
    printcolumn = r#"{"name":"Secret ID","type":"string","jsonPath":".spec.secretId"}"#,
    printcolumn = r#"{"name":"Target","type":"string","jsonPath":".spec.targetSecret"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct KMSSecretSpec {
    /// UID of the Cosmian KMS object to retrieve.
    pub secret_id: String,

    /// Name of the `Secret` to create/update in the same namespace.
    pub target_secret: String,

    /// Key name inside the `Secret.data` map.  Defaults to `"value"`.
    #[serde(default = "default_key")]
    pub key: String,

    /// How often to re-fetch the secret from KMS (e.g. `"1h"`, `"30m"`).
    /// Falls back to the operator-wide `defaultRefreshInterval` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<String>,

    /// Extra labels to copy onto the managed `Secret`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,

    /// List of `Deployment` names (in the same namespace) to rolling-restart
    /// when the secret value changes. `StatefulSet` restarts are handled by
    /// the separate `restart_stateful_sets` field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restart_deployments: Vec<String>,

    /// List of `StatefulSet` names to rolling-restart on secret rotation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restart_stateful_sets: Vec<String>,
}

fn default_key() -> String {
    "value".to_owned()
}

// ── CRD status ────────────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
pub struct KMSSecretStatus {
    /// `"True"` when the secret is up-to-date in K8s, `"False"` on error.
    pub ready: String,
    /// Human-readable message describing the last reconciliation result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// SHA-256 hex digest of the last successfully synced secret value.
    /// Used to detect changes and avoid unnecessary restarts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_secret_hash: Option<String>,
    /// RFC 3339 timestamp of the last successful sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
}

use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{kmip_operations::Get, kmip_types::UniqueIdentifier},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{
    error::CsiProviderError,
    v1alpha1::{
        File, MountRequest, MountResponse, ObjectVersion, VersionRequest, VersionResponse,
        csi_driver_provider_server::CsiDriverProvider,
    },
};

/// Provider name reported in `Version()` responses.
const PROVIDER_RUNTIME_NAME: &str = "cosmian-kms";
/// Provider semver version reported in `Version()` responses.
const PROVIDER_RUNTIME_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default file mode (0o400 in octal = 256 decimal: owner-read-only).
const DEFAULT_FILE_MODE: i32 = 0o400;

// ── SecretProviderClass parameter deserialization ────────────────────────────

/// Deserialized `attributes` JSON sent in `MountRequest`.
///
/// `SecretProviderClass` `spec.parameters` is serialised as a JSON object by
/// the CSI driver.  The `objects` field contains a YAML-encoded list of
/// [`ObjectSpec`] entries.
#[derive(Deserialize, Debug)]
struct Attributes {
    objects: String,
}

/// A single entry from the `objects` YAML list in `spec.parameters`.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ObjectSpec {
    /// The filename used for the mounted secret file (relative path).
    object_name: String,
    /// KMS Unique Identifier (UID) of the object to fetch.
    /// Accepts `kmsUID` (as specified in the `SecretProviderClass` example) and
    /// the camelCase form `kmsUid` produced by `rename_all = "camelCase"`.
    #[serde(alias = "kmsUID")]
    kms_uid: String,
    /// Optional expected version — empty string means "latest".
    ///
    /// The version of an object is the lower-hex SHA-256 digest of its content (see
    /// [`content_version`]); when set, the mount fails unless the fetched content has
    /// exactly this version.
    #[serde(default)]
    object_version: String,
}

// ── Service implementation ───────────────────────────────────────────────────

/// gRPC service implementing the Kubernetes Secrets Store CSI Driver Provider
/// v1alpha1 API.
///
/// `Mount()` calls are delegated to a [`KmsClient`] pointing at a Cosmian KMS
/// server.  Secret bytes are returned as file contents to the CSI driver, which
/// writes them to the pod tmpfs volume.
pub struct CsiProviderService {
    client: KmsClient,
}

impl CsiProviderService {
    /// Create a new service backed by `client`.
    #[must_use]
    pub const fn new(client: KmsClient) -> Self {
        Self { client }
    }
}

#[tonic::async_trait]
impl CsiDriverProvider for CsiProviderService {
    /// Return provider name and version — polled by the CSI driver to confirm
    /// the provider socket is alive.
    async fn version(
        &self,
        request: Request<VersionRequest>,
    ) -> Result<Response<VersionResponse>, Status> {
        let driver_version = request.into_inner().version;
        info!(driver_version, "CSI provider Version() called");
        Ok(Response::new(VersionResponse {
            version: driver_version,
            runtime_name: PROVIDER_RUNTIME_NAME.to_owned(),
            runtime_version: PROVIDER_RUNTIME_VERSION.to_owned(),
        }))
    }

    /// Fetch secrets from the KMS and return their contents as files.
    ///
    /// For each object declared in the `SecretProviderClass`, the provider:
    /// 1. Calls `KmsClient::get()` with the declared `kmsUID`.
    /// 2. Extracts the raw key/secret bytes.
    /// 3. Computes a SHA-256 hex digest of the bytes as the object version.
    /// 4. Fails if the object declares an `objectVersion` that differs from that digest.
    /// 5. Returns a `File` entry at the `objectName` path.
    ///
    /// If the computed version differs from the version stored in
    /// `current_object_version`, the CSI driver will trigger pod secret
    /// rotation within its next reconcile interval.
    async fn mount(
        &self,
        request: Request<MountRequest>,
    ) -> Result<Response<MountResponse>, Status> {
        let req = request.into_inner();
        debug!(target_path = %req.target_path, "CSI provider Mount() called");

        let specs = parse_attributes(&req.attributes).map_err(Status::from)?;

        // Build a lookup map: kms_uid → current version (for rotation detection).
        let current_versions: std::collections::HashMap<String, String> = req
            .current_object_version
            .iter()
            .map(|ov| (ov.id.clone(), ov.version.clone()))
            .collect();

        let mut files = Vec::with_capacity(specs.len());
        let mut object_versions = Vec::with_capacity(specs.len());

        for spec in &specs {
            let bytes = fetch_secret_bytes(&self.client, &spec.kms_uid)
                .await
                .map_err(Status::from)?;

            let version = content_version(&bytes);
            check_pinned_version(spec, &version).map_err(Status::from)?;

            // Warn when rotation is detected so operators can monitor logs.
            if let Some(prev_version) = current_versions.get(&spec.kms_uid) {
                if prev_version != &version {
                    warn!(
                        kms_uid = %spec.kms_uid,
                        object_name = %spec.object_name,
                        prev_version,
                        new_version = %version,
                        "secret version changed — rotation triggered"
                    );
                }
            }

            info!(
                kms_uid = %spec.kms_uid,
                object_name = %spec.object_name,
                version = %version,
                "fetched secret"
            );

            files.push(File {
                path: spec.object_name.clone(),
                mode: DEFAULT_FILE_MODE,
                contents: bytes.to_vec(),
            });
            object_versions.push(ObjectVersion {
                id: spec.kms_uid.clone(),
                version,
            });
        }

        Ok(Response::new(MountResponse {
            files,
            object_version: object_versions,
            error: None,
        }))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Parse the JSON `attributes` string from a `MountRequest` into a list of
/// [`ObjectSpec`] entries.
fn parse_attributes(attributes: &str) -> Result<Vec<ObjectSpec>, CsiProviderError> {
    let attrs: Attributes = serde_json::from_str(attributes).map_err(|e| {
        CsiProviderError::InvalidAttributes(format!(
            "attributes is not valid JSON: {e} — raw: {attributes}"
        ))
    })?;

    let specs: Vec<ObjectSpec> = serde_saphyr::from_str(&attrs.objects).map_err(|e| {
        CsiProviderError::InvalidAttributes(format!("objects field is not valid YAML: {e}"))
    })?;

    if specs.is_empty() {
        return Err(CsiProviderError::NoObjects);
    }
    Ok(specs)
}

/// Retrieve raw bytes for a KMS object identified by `uid`.
async fn fetch_secret_bytes(
    client: &KmsClient,
    uid: &str,
) -> Result<Zeroizing<Vec<u8>>, CsiProviderError> {
    debug!(uid, "fetching secret bytes from KMS");

    let response = client
        .get(Get {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            ..Get::default()
        })
        .await
        .map_err(CsiProviderError::KmsClient)?;

    let bytes = response
        .object
        .key_block()
        .map_err(|e| CsiProviderError::UnextractableObject {
            uid: uid.to_owned(),
            cause: format!("key_block(): {e}"),
        })?
        .key_bytes()
        .map_err(|e| CsiProviderError::UnextractableObject {
            uid: uid.to_owned(),
            cause: format!("key_bytes(): {e}"),
        })?;

    Ok(Zeroizing::new(bytes.to_vec()))
}

/// Fail when `spec` pins an `objectVersion` that differs from the `actual` version of
/// the object fetched from the KMS. An empty `objectVersion` means "latest".
fn check_pinned_version(spec: &ObjectSpec, actual: &str) -> Result<(), CsiProviderError> {
    if spec.object_version.is_empty() || spec.object_version == actual {
        Ok(())
    } else {
        Err(CsiProviderError::VersionMismatch {
            uid: spec.kms_uid.clone(),
            expected: spec.object_version.clone(),
            actual: actual.to_owned(),
        })
    }
}

/// Compute a deterministic version string for `bytes` as the lower-hex SHA-256
/// digest of the content.  A change in content → different version → rotation.
fn content_version(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attributes_valid() {
        // Simulate what the CSI driver sends: attributes is a JSON object
        // whose `objects` value is a YAML-encoded list.
        let objects_yaml = "- objectName: my-api-key\n  objectType: secret\n  kmsUID: 550e8400-e29b-41d4-a716-446655440000\n  objectVersion: \"\"\n";
        let attributes = serde_json::json!({ "objects": objects_yaml }).to_string();
        let specs = parse_attributes(&attributes).unwrap_or_else(|e| panic!("should parse: {e}"));
        assert_eq!(specs.len(), 1);
        let first = specs.first().expect("at least one spec");
        assert_eq!(first.object_name, "my-api-key");
        assert_eq!(first.kms_uid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(first.object_version, "");
    }

    #[test]
    fn parse_attributes_reads_object_version_pin() {
        let objects_yaml = "- objectName: a\n  kmsUID: uid-a\n  objectVersion: abc123\n- objectName: b\n  kmsUid: uid-b\n";
        let attributes = serde_json::json!({ "objects": objects_yaml }).to_string();
        let specs = parse_attributes(&attributes).unwrap_or_else(|e| panic!("should parse: {e}"));
        assert_eq!(specs.len(), 2);
        assert_eq!(specs.first().expect("first").object_version, "abc123");
        assert_eq!(specs.get(1).expect("second").object_version, "");
    }

    fn spec_with_version(object_version: &str) -> ObjectSpec {
        ObjectSpec {
            object_name: "secret".to_owned(),
            kms_uid: "uid-1".to_owned(),
            object_version: object_version.to_owned(),
        }
    }

    #[test]
    fn unpinned_spec_accepts_any_version() {
        assert!(
            check_pinned_version(&spec_with_version(""), &content_version(b"x"))
                .err()
                .is_none()
        );
    }

    #[test]
    fn pinned_version_matching_content_digest_is_accepted() {
        let pinned = content_version(b"secret-bytes");
        assert!(
            check_pinned_version(
                &spec_with_version(&pinned),
                &content_version(b"secret-bytes")
            )
            .err()
            .is_none()
        );
    }

    #[test]
    fn pinned_version_mismatch_is_a_failed_precondition() {
        let pinned = content_version(b"old");
        let actual = content_version(b"rotated");
        let err = check_pinned_version(&spec_with_version(&pinned), &actual)
            .expect_err("mismatching pinned version must be rejected");
        assert!(
            matches!(
                &err,
                CsiProviderError::VersionMismatch { uid, expected, actual: got }
                    if uid == "uid-1" && *expected == pinned && *got == actual
            ),
            "{err}"
        );
        assert_eq!(
            tonic::Status::from(err).code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[test]
    fn parse_attributes_empty_objects_list() {
        let attributes = r#"{"objects":""}"#;
        assert!(
            matches!(
                parse_attributes(attributes),
                Err(CsiProviderError::NoObjects)
            ),
            "expected NoObjects error"
        );
    }

    #[test]
    fn parse_attributes_invalid_json() {
        assert!(
            matches!(
                parse_attributes("not json"),
                Err(CsiProviderError::InvalidAttributes(_))
            ),
            "expected InvalidAttributes error"
        );
    }

    #[test]
    fn content_version_deterministic() {
        let v1 = content_version(b"hello");
        let v2 = content_version(b"hello");
        assert_eq!(v1, v2);
        let v3 = content_version(b"world");
        assert_ne!(v1, v3);
    }
}

#[cfg(test)]
#[path = "service_characterization_tests.rs"]
mod characterization_tests;

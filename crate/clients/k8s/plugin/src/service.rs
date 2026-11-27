use std::collections::{BTreeSet, HashMap};

use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::UniqueIdentifier,
    },
};
use tonic::{Request, Response, Status};
use tracing::{debug, info};

use crate::{
    error::PluginError,
    kmsv2::{
        DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, StatusRequest,
        StatusResponse, key_management_service_server::KeyManagementService,
    },
};

/// Annotation keys used to store AES-GCM cryptographic material alongside the
/// wrapped DEK in etcd.
///
/// The KMS v2 spec requires annotation keys to be fully-qualified domain names
/// (validated by `validation.IsFullyQualifiedDomainName`), i.e. plain DNS
/// labels separated by dots — **no** `domain/name` slash syntax.
const ANNOTATION_IV: &str = "iv.k8s-kms.cosmian.com";
const ANNOTATION_AEAD_TAG: &str = "aead-tag.k8s-kms.cosmian.com";

/// gRPC service implementing the Kubernetes KMS Provider Plugin v2 API.
///
/// Each incoming `Encrypt`/`Decrypt` call is delegated to a [`KmsClient`]
/// pointing at a Cosmian KMS server.  The wrapping key (KEK) is fixed at
/// construction time via `wrapping_key_uid`.
pub struct KmsPluginService {
    client: KmsClient,
    decryption_key_policy: DecryptionKeyPolicy,
}

/// KEK UIDs that kube-apiserver is permitted to use for decrypting stored data.
pub struct DecryptionKeyPolicy {
    current_key_uid: String,
    allowed_decryption_key_ids: BTreeSet<String>,
}

impl DecryptionKeyPolicy {
    /// Create a policy that always permits the current KEK and explicitly listed older KEKs.
    #[must_use]
    pub const fn new(
        current_key_uid: String,
        allowed_decryption_key_ids: BTreeSet<String>,
    ) -> Self {
        Self {
            current_key_uid,
            allowed_decryption_key_ids,
        }
    }

    fn allows(&self, key_uid: &str) -> bool {
        key_uid == self.current_key_uid || self.allowed_decryption_key_ids.contains(key_uid)
    }
}

impl KmsPluginService {
    /// Create a service backed by `client` and the configured KEK decryption policy.
    // KmsClient wraps a reqwest::Client which is not const-constructible.
    #[must_use]
    pub const fn new(client: KmsClient, decryption_key_policy: DecryptionKeyPolicy) -> Self {
        Self {
            client,
            decryption_key_policy,
        }
    }
}

#[tonic::async_trait]
impl KeyManagementService for KmsPluginService {
    /// Health-check polled by kube-apiserver every ~60 s.
    ///
    /// Returns `version="v2"`, `healthz="ok"` and the current KEK UID as
    /// `key_id`.  A change in `key_id` signals kube-apiserver that the KEK
    /// has rotated and stored secrets should be re-encrypted.
    async fn status(
        &self,
        _request: Request<StatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let reply = StatusResponse {
            version: "v2".to_owned(),
            healthz: "ok".to_owned(),
            key_id: self.decryption_key_policy.current_key_uid.clone(),
        };
        info!(key_id = %self.decryption_key_policy.current_key_uid, "Status polled");
        Ok(Response::new(reply))
    }

    /// Wrap a Data Encryption Key (DEK) using the configured KEK.
    ///
    /// The KMIP `Encrypt` response may return the IV and AEAD tag as separate
    /// fields.  These are persisted in the `annotations` map so that
    /// [`KeyManagementService::decrypt`] can reconstruct the exact call needed
    /// to unwrap the DEK.
    async fn encrypt(
        &self,
        request: Request<EncryptRequest>,
    ) -> Result<Response<EncryptResponse>, Status> {
        let req = request.into_inner();
        debug!(uid = %req.uid, "Encrypt request received");

        let kmip_request = Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(
                self.decryption_key_policy.current_key_uid.clone(),
            )),
            data: Some(req.plaintext.into()),
            ..Default::default()
        };

        let kmip_resp = self
            .client
            .encrypt(kmip_request)
            .await
            .map_err(PluginError::KmsClient)?;

        let ciphertext = kmip_resp.data.ok_or(PluginError::MissingCiphertext)?;

        // Persist optional IV and AEAD tag in annotations so we can reconstruct
        // the exact Decrypt call later.  Both fields are binary-safe bytes.
        let mut annotations: HashMap<String, Vec<u8>> = HashMap::new();
        if let Some(iv) = kmip_resp.i_v_counter_nonce {
            annotations.insert(ANNOTATION_IV.to_owned(), iv.to_vec());
        }
        if let Some(tag) = kmip_resp.authenticated_encryption_tag {
            annotations.insert(ANNOTATION_AEAD_TAG.to_owned(), tag.to_vec());
        }

        info!(
            uid = %req.uid,
            key_id = %self.decryption_key_policy.current_key_uid,
            "DEK wrapped successfully"
        );

        Ok(Response::new(EncryptResponse {
            ciphertext: ciphertext.to_vec(),
            key_id: self.decryption_key_policy.current_key_uid.clone(),
            annotations,
        }))
    }

    /// Unwrap a previously wrapped Data Encryption Key (DEK).
    ///
    /// Uses the `key_id` provided by kube-apiserver (persisted in etcd at encrypt time)
    /// to select the KEK for the KMIP Decrypt call, which allows key rotation.
    async fn decrypt(
        &self,
        request: Request<DecryptRequest>,
    ) -> Result<Response<DecryptResponse>, Status> {
        let req = request.into_inner();
        debug!(uid = %req.uid, key_id = %req.key_id, "Decrypt request received");
        if !self.decryption_key_policy.allows(&req.key_id) {
            return Err(Status::permission_denied(
                "key_id is not an allowed current or retained KEK",
            ));
        }

        let iv = req.annotations.get(ANNOTATION_IV).cloned();
        let tag = req.annotations.get(ANNOTATION_AEAD_TAG).cloned();

        // Use the key_id stored in etcd (the KEK that was used at encrypt time),
        // NOT the current wrapping_key_uid.  After a KEK rotation the current
        // wrapping_key_uid is the new key, but etcd still holds secrets wrapped
        // with the old key — identified by req.key_id.  Refusing to decrypt them
        // would make those secrets permanently unreadable.
        let kmip_request = Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(req.key_id.clone())),
            data: Some(req.ciphertext),
            i_v_counter_nonce: iv.map(Into::into),
            authenticated_encryption_tag: tag.map(Into::into),
            ..Default::default()
        };

        let kmip_resp = self
            .client
            .decrypt(kmip_request)
            .await
            .map_err(PluginError::KmsClient)?;

        let plaintext = kmip_resp
            .data
            .map(|z| z.to_vec())
            .ok_or(PluginError::MissingPlaintext)?;

        info!(uid = %req.uid, key_id = %req.key_id, "DEK unwrapped successfully");

        Ok(Response::new(DecryptResponse { plaintext }))
    }
}

#[cfg(test)]
mod tests {
    use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};

    use super::*;

    fn make_test_client() -> KmsClient {
        KmsClient::new_with_config(KmsClientConfig {
            http_config: HttpClientConfig {
                server_url: "http://127.0.0.1:19998".to_owned(),
                ..HttpClientConfig::default()
            },
            ..KmsClientConfig::default()
        })
        .expect("client should build")
    }

    fn key_policy(current: &str, previous: &[&str]) -> DecryptionKeyPolicy {
        DecryptionKeyPolicy::new(
            current.to_owned(),
            previous.iter().map(|uid| (*uid).to_owned()).collect(),
        )
    }

    /// Verify that Decrypt uses `req.key_id` (not `wrapping_key_uid`) so that
    /// secrets encrypted with an old KEK remain decryptable after key rotation.
    /// When `req.key_id` differs from `wrapping_key_uid` the call must still
    /// reach the KMS (we get a network / KMS error, not an `InvalidArgument`).
    #[tokio::test]
    async fn test_decrypt_uses_request_key_id() {
        // Simulate post-rotation: plugin is configured with a new key …
        let svc = KmsPluginService::new(
            make_test_client(),
            key_policy("new-key-uid", &["old-key-uid"]),
        );

        // … but the secret in etcd was encrypted with the old key.
        let req = Request::new(DecryptRequest {
            ciphertext: b"some-ciphertext".to_vec(),
            uid: "test-uid".to_owned(),
            key_id: "old-key-uid".to_owned(),
            annotations: HashMap::new(),
        });

        let result = svc.decrypt(req).await;
        // Must NOT be InvalidArgument (key_id mismatch rejected locally).
        // It should be Internal (KMS unreachable) — the request reached the network layer.
        assert!(result.is_err());
        let status = result.unwrap_err();
        assert_ne!(
            status.code(),
            tonic::Code::InvalidArgument,
            "decrypt must not reject old key_ids — got: {status:?}"
        );
    }

    /// Verify that Status always returns version="v2", healthz="ok" and the
    /// configured wrapping key UID.
    #[tokio::test]
    async fn test_status_returns_correct_fields() {
        let uid = "my-wrapping-key-uid".to_owned();
        let svc = KmsPluginService::new(make_test_client(), key_policy(&uid, &[]));

        let resp = svc
            .status(Request::new(StatusRequest {}))
            .await
            .expect("status should succeed");
        let inner = resp.into_inner();

        assert_eq!(inner.version, "v2");
        assert_eq!(inner.healthz, "ok");
        assert_eq!(inner.key_id, uid);
    }

    #[test]
    fn decryption_policy_allows_current_and_retained_keys_only() {
        let policy = key_policy("current-key", &["old-key"]);

        assert!(policy.allows("current-key"));
        assert!(policy.allows("old-key"));
        assert!(!policy.allows("unconfigured-key"));
    }
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests for `KmsPluginService::new` and the Encrypt entry point.

    use std::collections::{BTreeSet, HashMap};

    use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
    use tonic::{Code, Request};

    use super::{DecryptionKeyPolicy, KmsPluginService};
    use crate::kmsv2::{
        DecryptRequest, EncryptRequest, StatusRequest,
        key_management_service_server::KeyManagementService,
    };

    fn service(wrapping_key_uid: &str) -> KmsPluginService {
        let client = KmsClient::new_with_config(KmsClientConfig {
            http_config: HttpClientConfig {
                server_url: "http://127.0.0.1:1".to_owned(),
                ..HttpClientConfig::default()
            },
            ..KmsClientConfig::default()
        })
        .unwrap();
        KmsPluginService::new(
            client,
            DecryptionKeyPolicy::new(wrapping_key_uid.to_owned(), BTreeSet::new()),
        )
    }

    #[tokio::test]
    async fn characterization_plugin_service_new_status_reports_wrapping_key() {
        let response = service("kek-1")
            .status(Request::new(StatusRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.version, "v2");
        assert_eq!(response.healthz, "ok");
        assert_eq!(response.key_id, "kek-1");
    }

    #[tokio::test]
    async fn characterization_plugin_service_new_encrypt_unreachable_kms() {
        let status = service("kek-1")
            .encrypt(Request::new(EncryptRequest {
                plaintext: vec![0_u8; 32],
                uid: "uid".to_owned(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn characterization_plugin_service_new_decrypt_unreachable_kms() {
        let status = service("kek-1")
            .decrypt(Request::new(DecryptRequest {
                ciphertext: vec![1, 2, 3],
                uid: "uid".to_owned(),
                key_id: "kek-1".to_owned(),
                annotations: HashMap::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn characterization_plugin_service_rejects_unconfigured_decryption_key() {
        let status = service("kek-1")
            .decrypt(Request::new(DecryptRequest {
                ciphertext: vec![1, 2, 3],
                uid: "uid".to_owned(),
                key_id: "unconfigured-key".to_owned(),
                annotations: HashMap::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
    }
}

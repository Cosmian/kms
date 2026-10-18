//! Characterization tests for `KmsPluginService::new` and the Encrypt entry point.

use std::collections::HashMap;

use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
use tonic::{Code, Request};

use super::KmsPluginService;
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
    KmsPluginService::new(client, wrapping_key_uid.to_owned())
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
            key_id: "kek-0".to_owned(),
            annotations: HashMap::new(),
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal);
}

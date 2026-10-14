//! Characterization tests for `CsiProviderService::new` and its gRPC entry points.

use cosmian_kms_client::{KmsClient, KmsClientConfig, http_client::HttpClientConfig};
use tonic::{Code, Request};

use super::CsiProviderService;
use crate::v1alpha1::{
    MountRequest, VersionRequest, csi_driver_provider_server::CsiDriverProvider,
};

fn service() -> CsiProviderService {
    let client = KmsClient::new_with_config(KmsClientConfig {
        http_config: HttpClientConfig {
            server_url: "http://127.0.0.1:1".to_owned(),
            ..HttpClientConfig::default()
        },
        ..KmsClientConfig::default()
    })
    .unwrap();
    CsiProviderService::new(client)
}

#[tokio::test]
async fn characterization_csi_service_new_version_reports_runtime() {
    let response = service()
        .version(Request::new(VersionRequest {
            version: "v1alpha1".to_owned(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.version, "v1alpha1");
    assert_eq!(response.runtime_name, "cosmian-kms");
    assert_eq!(response.runtime_version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn characterization_csi_service_new_mount_rejects_invalid_attributes() {
    let status = service()
        .mount(Request::new(MountRequest {
            attributes: "not json".to_owned(),
            ..MountRequest::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(
        status.message(),
        "invalid SecretProviderClass attributes: attributes is not valid JSON: expected ident at line 1 column 2 — raw: not json"
    );
}

#[tokio::test]
async fn characterization_csi_service_new_mount_rejects_empty_objects() {
    let status = service()
        .mount(Request::new(MountRequest {
            attributes: r#"{"objects":""}"#.to_owned(),
            ..MountRequest::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert_eq!(
        status.message(),
        "no objects declared in SecretProviderClass parameters"
    );
}

#[tokio::test]
async fn characterization_csi_service_new_mount_unreachable_kms_is_internal() {
    let objects = "- objectName: a\n  kmsUID: uid-a\n";
    let attributes = serde_json::json!({ "objects": objects }).to_string();
    let status = service()
        .mount(Request::new(MountRequest {
            attributes,
            ..MountRequest::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal);
}

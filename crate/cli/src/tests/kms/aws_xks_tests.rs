use crate::{
    actions::kms::{access::GrantAccess, shared::ImportSecretDataOrKeyAction},
    error::result::KmsCliResult,
};
use cosmian_aws_structs::health_status::{self, GetHealthStatusResponse};
use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::ImportKeyFormat;
use cosmian_logger::{info, log_init};
use std::{fs, path::PathBuf};
use tempfile::TempDir;
use test_kms_server::{
    MainDBConfig,
    reexport::cosmian_kms_server::{
        config::{ClapConfig, SocketServerConfig, TlsConfig},
        routes::aws_xks::AwsXksConfig,
    },
    start_test_kms_server_with_config,
};

const KEK_USER: &str = "KEK_USER";
const ACCESS_KEY_ID: &str = "AKIAIOSFODNN7EXAMPLE";
const ACCESS_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

#[tokio::test]
pub(super) async fn test_aws_xks() -> KmsCliResult<()> {
    log_init(Some(
        "info,cosmian_kms_server=debug,cosmian_kms_server_database=info",
    ));

    // plaintext no auth
    info!("==> Testing AWS XKS");
    let ctx = start_test_kms_server_with_config(ClapConfig {
        socket_server: SocketServerConfig {
            socket_server_start: true,
            ..Default::default()
        },
        tls: TlsConfig {
            tls_p12_file: Some(PathBuf::from(
                "../../test_data/certificates/client_server/server/kmserver.acme.com.p12",
            )),
            tls_p12_password: Some("password".to_owned()),
            clients_ca_cert_file: Some(PathBuf::from(
                "../../test_data/certificates/client_server/ca/ca.crt",
            )),
            tls_cipher_suites: None,
        },
        db: MainDBConfig {
            database_type: Some("sqlite".to_owned()),
            ..Default::default()
        },
        kms_public_url: None,
        aws_xks_config: AwsXksConfig {
            aws_xks_enable: true,
            aws_xks_region: Some("us-east-1".to_owned()),
            aws_xks_service: Some("xks-kms".to_owned()),
            aws_xks_sigv4_access_key_id: Some(ACCESS_KEY_ID.to_owned()),
            aws_xks_sigv4_secret_access_key: Some(ACCESS_KEY.to_owned()),
            aws_xks_kek_user: Some(KEK_USER.to_owned()),
        },
        ..Default::default()
    })
    .await;

    // Create a temporary file to hold the access key
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let tmp_file = tmp_path.join("access_key.key");
    fs::write(&tmp_file, ACCESS_KEY.as_bytes())?;

    // Import the AWS Key
    ImportSecretDataOrKeyAction {
        key_file: tmp_file,
        key_id: Some(ACCESS_KEY_ID.to_owned()),
        key_format: ImportKeyFormat::Aes,
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    GrantAccess {
        object_uid: Some(ACCESS_KEY_ID.to_owned()),
        user: KEK_USER.to_owned(),
        operations: vec![KmipOperation::Get],
    }
    .run(ctx.get_owner_client())
    .await?;

    let health_status_req = health_status::GetHealthStatusRequest {
        requestMetadata: health_status::RequestMetadata {
            kmsRequestId: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
            kmsOperation: "KmsHealthCheck".to_owned(),
        },
    };

    let health_status_response: GetHealthStatusResponse = ctx
        .get_owner_client()
        .post_no_ttlv("/aws/kms/xks/v1/health", Some(&health_status_req))
        .await?;
    info!(
        "AWS XKS GetHealthStatus response: fleet size {} model {}",
        health_status_response.xksProxyFleetSize, health_status_response.xksProxyModel
    );

    Ok(())
}

use std::path::PathBuf;

use cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::CertificateInputFormat;
use test_kms_server::start_default_test_kms_server;
use uuid::Uuid;

use crate::{
    actions::kms::certificates::import_certificate::ImportCertificateAction,
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_certificate_import_different_format() -> KmsCliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // import as TTLV JSON
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/exported_certificate_ttlv.json",
            )),
            input_format: CertificateInputFormat::JsonTtlv,
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // import as PEM
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from("../../test_data/certificates/ca.crt")),
            input_format: CertificateInputFormat::Pem,
            certificate_id: None,
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // import a chain
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/mozilla_IncludedRootsPEM.txt",
            )),
            input_format: CertificateInputFormat::Chain,
            certificate_id: None,
            replace_existing: true,
            tags: vec!["import_chain".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // import a PKCS12 - not supported in FIPS mode (PKCS12KDF is not FIPS-approved)
    #[cfg(feature = "non-fips")]
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from("../../test_data/certificates/p12/output.p12")),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: None,
            replace_existing: true,
            tags: vec!["import_pkcs12".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    Ok(())
}

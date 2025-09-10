use std::path::PathBuf;

use cosmian_kms_client::{
    kmip_2_1::kmip_types::ValidityIndicator,
    reexport::cosmian_kms_client_utils::import_utils::CertificateInputFormat,
};
use cosmian_logger::{debug, info};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::certificates::{
        import_certificate::ImportCertificateAction,
        validate_certificate::ValidateCertificatesAction,
    },
    error::result::KmsCliResult,
};

async fn import_revoked_certificate_encrypt(curve_name: &str) -> KmsCliResult<()> {
    use crate::actions::kms::certificates::encrypt_certificate::EncryptCertificateAction;

    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let _recovered_file = tmp_path.join("plain.txt");

    std::fs::remove_file(&output_file).ok();
    // assert!(!output_file.exists());

    debug!("\n\nImport Certificate");
    let root_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(format!(
                "../../test_data/certificates/openssl/{curve_name}-cert.pem"
            ))),
            input_format: CertificateInputFormat::Pem,
            replace_existing: true,
            tags: vec![curve_name.to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    debug!("\n\nImport Certificate");
    let certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(format!(
                "../../test_data/certificates/openssl/{curve_name}-revoked.crt"
            ))),
            input_format: CertificateInputFormat::Pem,
            issuer_certificate_id: Some(root_certificate_id.unwrap()),
            replace_existing: true,
            tags: vec![curve_name.to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    debug!("\n\nEncrypt with certificate");
    assert!(
        EncryptCertificateAction {
            input_file,
            certificate_id,
            output_file: Some(output_file),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_import_revoked_certificate_encrypt_prime256() -> KmsCliResult<()> {
    Box::pin(import_revoked_certificate_encrypt("prime256v1")).await
}

#[tokio::test]
async fn test_validate_cli() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    info!("importing root cert");
    let root_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/chain/ca.cert.pem",
            )),
            input_format: CertificateInputFormat::Pem,
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    info!("importing intermediate cert");
    let intermediate_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/chain/intermediate.cert.pem",
            )),
            input_format: CertificateInputFormat::Pem,
            issuer_certificate_id: root_certificate_id.clone(),
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let leaf1_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/chain/leaf1.cert.pem",
            )),
            input_format: CertificateInputFormat::Pem,
            issuer_certificate_id: intermediate_certificate_id.clone(),
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;
    info!("leaf1 cert imported: {leaf1_certificate_id:?}");

    let root_certificate_id = root_certificate_id.unwrap();
    let intermediate_certificate_id = intermediate_certificate_id.unwrap();

    let test1_res = ValidateCertificatesAction {
        certificate_id: vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf1_certificate_id.unwrap(),
        ],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await;
    info!(
        "Validate chain with leaf1: result supposed to be invalid, as leaf1 was revoked. \
         test1_res: {test1_res:?}"
    );
    test1_res.unwrap_err();

    let test2_res = ValidateCertificatesAction {
        certificate_id: vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
        ],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;
    info!(
        "validate chain with leaf2: result supposed to be valid, as leaf2 was never revoked. \
         test2_res: {test2_res:?}"
    );
    assert_eq!(test2_res, ValidityIndicator::Valid);

    let test3_res = ValidateCertificatesAction {
        certificate_id: vec![intermediate_certificate_id, root_certificate_id.clone()],
        validity_time: Some("4804152030Z".to_owned()),
    }
    .run(ctx.get_owner_client())
    .await;
    info!(
        "validate chain with leaf2: result supposed to be invalid, as date is posthumous to \
         leaf2's expiration date. test3_res: {test3_res:?}"
    );
    test3_res.unwrap_err();

    let test4_res = ValidateCertificatesAction {
        certificate_id: vec![root_certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    info!("validate chain only. Must be valid.");
    assert_eq!(test4_res, ValidityIndicator::Valid);

    info!("validate tests successfully passed");
    Ok(())
}

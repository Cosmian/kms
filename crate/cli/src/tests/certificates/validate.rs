use std::path::PathBuf;

use kms_test_server::{start_default_test_kms_server, ONCE};
use tempfile::TempDir;
use tracing::debug;

use crate::{
    actions::certificates::CertificateInputFormat,
    error::CliError,
    tests::certificates::{encrypt::encrypt, import::import_certificate},
};

async fn import_revoked_certificate_encrypt(curve_name: &str) -> Result<(), CliError> {
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let tmp_path = std::path::Path::new("./");

    let input_file = PathBuf::from("test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let _recovered_file = tmp_path.join("plain.txt");

    let tags = &[curve_name];

    std::fs::remove_file(&output_file).ok();
    // assert!(!output_file.exists());

    debug!("\n\nImport Certificate");
    let root_certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-cert.pem"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        None,
        Some(tags),
        None,
        false,
        true,
    )?;

    debug!("\n\nImport Certificate");
    let certificate_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        &format!("test_data/certificates/openssl/{curve_name}-revoked.crt"),
        CertificateInputFormat::Pem,
        None,
        None,
        None,
        Some(root_certificate_id),
        Some(tags),
        None,
        false,
        true,
    )?;

    debug!("\n\nEncrypt with certificate");
    assert!(
        encrypt(
            &ctx.owner_client_conf_path,
            input_file.to_str().unwrap(),
            &certificate_id,
            Some(output_file.to_str().unwrap()),
            None,
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_import_revoked_certificate_encrypt_prime256() -> Result<(), CliError> {
    import_revoked_certificate_encrypt("prime256v1").await
}

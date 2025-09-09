use std::{fs, path::PathBuf};

use cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        import_utils::{CertificateInputFormat, ImportKeyFormat, KeyUsage},
        rsa_utils::RsaEncryptionAlgorithm,
    },
};
use cosmian_logger::debug;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

#[cfg(feature = "non-fips")]
async fn test_certificate_import_encrypt(
    ca_path: &str,
    subca_path: &str,
    cert_path: &str,
    key_path: &str,
    tags: &[&str],
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> KmsCliResult<()> {
    use crate::actions::kms::{
        certificates::{
            decrypt_certificate::DecryptCertificateAction,
            encrypt_certificate::EncryptCertificateAction,
            import_certificate::ImportCertificateAction,
        },
        shared::ImportSecretDataOrKeyAction,
    };

    let ctx = start_default_test_kms_server().await;
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let tags = tags.iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    debug!("\n\nImport Key");
    let private_key_id = ImportSecretDataOrKeyAction {
        key_file: format!("../../test_data/certificates/{key_path}").into(),
        key_format: ImportKeyFormat::Pem,
        tags: tags.clone(),
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let root_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(format!("../../test_data/certificates/{ca_path}").into()),
            input_format: CertificateInputFormat::Pem,
            replace_existing: true,
            tags: tags.clone(),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let subca_certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(format!("../../test_data/certificates/{subca_path}").into()),
            input_format: CertificateInputFormat::Pem,
            replace_existing: true,
            issuer_certificate_id: root_certificate_id,
            tags: tags.clone(),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(format!("../../test_data/certificates/{cert_path}").into()),
            input_format: CertificateInputFormat::Pem,
            private_key_id: Some(private_key_id.to_string()),
            issuer_certificate_id: subca_certificate_id,
            replace_existing: true,
            tags: tags.clone(),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    debug!("\n\nEncrypt With Certificate");

    EncryptCertificateAction {
        input_file: input_file.clone(),
        certificate_id,
        tags: None,
        output_file: Some(output_file.clone()),
        authentication_data: None,
        encryption_algorithm,
    }
    .run(ctx.get_owner_client())
    .await?;

    debug!("\n\nDecrypt");
    // the user key should be able to decrypt the file
    DecryptCertificateAction {
        input_file: output_file,
        private_key_id: Some(private_key_id.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: None,
        encryption_algorithm,
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_import_ca_and_encrypt_using_x25519() -> KmsCliResult<()> {
    Box::pin(test_certificate_import_encrypt(
        "p12/root.pem",
        "p12/subca.pem",
        "p12/cert.pem",
        "p12/cert.key",
        &["external_certificate"],
        None,
    ))
    .await
}

async fn import_encrypt_decrypt(
    filename: &str,
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
) -> KmsCliResult<()> {
    use crate::actions::kms::{
        certificates::{
            decrypt_certificate::DecryptCertificateAction,
            encrypt_certificate::EncryptCertificateAction,
            import_certificate::ImportCertificateAction,
        },
        shared::ImportSecretDataOrKeyAction,
    };

    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let tags = vec![filename.to_owned()];

    debug!("\n\nImport Private key");
    let private_key_id = ImportSecretDataOrKeyAction {
        key_file: format!("../../test_data/certificates/openssl/{filename}-private-key.pem").into(),
        key_format: ImportKeyFormat::Pem,
        tags: tags.clone(),
        key_usage: Some(vec![KeyUsage::Decrypt, KeyUsage::UnwrapKey]),
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    debug!("\n\nImport Certificate");
    let certificate_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(
                format!("../../test_data/certificates/openssl/{filename}-cert.pem").into(),
            ),
            input_format: CertificateInputFormat::Pem,
            private_key_id: Some(private_key_id.to_string()),
            replace_existing: true,
            tags: tags.clone(),
            key_usage: Some(vec![KeyUsage::Encrypt]),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    debug!("\n\nEncrypt With Certificate");
    EncryptCertificateAction {
        input_file: input_file.clone(),
        certificate_id,
        tags: None,
        output_file: Some(output_file.clone()),
        authentication_data: None,
        encryption_algorithm,
    }
    .run(ctx.get_owner_client())
    .await?;

    debug!("\n\nDecrypt");
    DecryptCertificateAction {
        input_file: output_file,
        private_key_id: Some(private_key_id.to_string()),
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: None,
        encryption_algorithm,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(recovered_file.exists());
    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[tokio::test]
#[cfg(feature = "non-fips")]
// P-192 should not be used in FIPS mode. See NIST.SP.800-186 - Section 3.2.1.1.
async fn test_certificate_encrypt_using_prime192() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("prime192v1", None)).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_prime224() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("secp224r1", None)).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
// Edwards curve shall be used **for digital signature only**.
// See NIST.SP.800-186 - Section 3.1.2 table 2 and NIST.FIPS.186-5.
async fn test_certificate_encrypt_using_ed25519() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("ED25519", None)).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_prime256() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("prime256v1", None)).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_secp384r1() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("secp384r1", None)).await
}

#[tokio::test]
#[cfg(feature = "non-fips")]
async fn test_certificate_encrypt_using_secp521r1() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt("secp521r1", None)).await
}

#[tokio::test]
async fn test_certificate_encrypt_using_rsa() -> KmsCliResult<()> {
    Box::pin(import_encrypt_decrypt(
        "rsa-2048",
        Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap),
    ))
    .await?;
    Box::pin(import_encrypt_decrypt(
        "rsa-3072",
        Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap),
    ))
    .await?;
    Box::pin(import_encrypt_decrypt(
        "rsa-4096",
        Some(RsaEncryptionAlgorithm::CkmRsaAesKeyWrap),
    ))
    .await
}

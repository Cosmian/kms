use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::Sign,
    kmip_types::{UniqueIdentifier, ValidityIndicator},
};
use cosmian_logger::log_init;
// Curve no longer used since EcSignAction was removed
use sha2::Digest as Sha2Digest;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        elliptic_curves::{
            keys::create_key_pair::CreateKeyPairAction as EcCreateKeyPairAction,
            signature_verify::SignatureVerifyAction as EcVerifyAction,
        },
        rsa::{
            keys::create_key_pair::CreateKeyPairAction as RsaCreateKeyPairAction,
            sign::SignAction as RsaSignAction,
            signature_verify::SignatureVerifyAction as RsaVerifyAction,
        },
    },
    error::result::KmsCliResult,
};

// RSA digested sign/verify in FIPS mode
#[tokio::test]
async fn rsa_digested_sign_verify() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.sig");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = openssl::sha::sha256(&data);
    std::fs::write(&digest_file, digest)?;

    let (private_key_id, public_key_id) = RsaCreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    RsaSignAction {
        input_file: digest_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        output_file: Some(sig_file.clone()),
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    let validity = RsaVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);
    Ok(())
}

// ECDSA digested sign/verify in FIPS mode
#[tokio::test]
async fn ecdsa_digested_sign_verify() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let digest_file = tmp_path.join("plain.sha256");
    let sig_file = tmp_path.join("plain.sha256.ec.sig");

    // compute SHA-256 digest of input and write to digest_file
    let data = std::fs::read(&input_file)?;
    let digest = sha2::Sha256::digest(&data);
    std::fs::write(&digest_file, digest)?;
    let (private_key_id, public_key_id) = EcCreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Build and send Sign operation directly
    let cryptographic_parameters = None;
    let sign_request = Sign {
        unique_identifier: Some(UniqueIdentifier::TextString(private_key_id.to_string())),
        cryptographic_parameters,
        data: None,
        digested_data: Some(std::fs::read(&digest_file)?),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    let sign_response = ctx.get_owner_client().sign(sign_request).await?;
    let signature = sign_response.signature_data.expect("signature_data");
    std::fs::write(&sig_file, &signature)?;

    let validity = EcVerifyAction {
        data_file: digest_file.clone(),
        signature_file: sig_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        output_file: None,
        digested: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validity, ValidityIndicator::Valid);
    Ok(())
}

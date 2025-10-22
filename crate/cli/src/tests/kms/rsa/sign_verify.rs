use std::{fs, path::PathBuf};

use cosmian_logger::{log_init, trace};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::error::result::KmsCliResult;

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_rsa_sign() -> KmsCliResult<()> {
    // to enable this, add cosmian_logger = { workspace = true } to dev-dependencies in Cargo.toml
    log_init(None);

    use cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator;
    use cosmian_logger::trace;

    use crate::actions::kms::rsa::{
        keys::create_key_pair::CreateKeyPairAction,
        sign::{CDigitalSignatureAlgorithm, SignAction},
        signature_verify::SignatureVerifyAction,
    };
    let ctx = start_default_test_kms_server().await;

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.sign");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");

    SignAction {
        input_file: input_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        signature_algorithm: CDigitalSignatureAlgorithm::RSASSAPSS,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    let signature_result = SignatureVerifyAction {
        data_file: input_file.clone(),
        signature_file: output_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        signature_algorithm: CDigitalSignatureAlgorithm::RSASSAPSS,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(signature_result, ValidityIndicator::Valid);

    // // the user key should NOT be able to decrypt with another algorithm
    // assert!(
    //     DecryptAction {
    //         input_file: output_file.clone(),
    //         key_id: Some(private_key_id.to_string()),
    //         tags: None,
    //         encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
    //         hash_fn: HashFn::Sha256,
    //         output_file: Some(recovered_file.clone()),
    //     }
    //     .run(ctx.get_owner_client())
    //     .await
    //     .is_err()
    // );

    // let original_content = read_bytes_from_file(&input_file)?;
    // let recovered_content = read_bytes_from_file(&recovered_file)?;
    // assert_eq!(original_content, recovered_content);

    Ok(())
}

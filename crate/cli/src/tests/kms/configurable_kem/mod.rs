use cosmian_logger::debug;
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::configurable_kem::{
        decaps::DecapsAction, encaps::EncapsAction, keygen::CreateKemKeyPairAction,
    },
    error::result::KmsCliResult,
};

async fn test_kem(ctx: &TestsContext, name: &str, tag: usize) -> KmsCliResult<()> {
    debug!("Key generation ({name})");

    let (dk_id, ek_id) = Box::pin(
        CreateKemKeyPairAction {
            access_structure: None,
            tags: vec![name.to_owned()],
            sensitive: false,
            kem_tag: tag,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let encapsulation_file = tmp_path.join("encapsulation.enc");
    let session_key_file = tmp_path.join("session_key.plain");

    debug!("Encapsulation");

    EncapsAction {
        key_id: Some(ek_id.to_string()),
        encryption_policy: None,
        tags: None,
        output_file: Some(encapsulation_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    debug!("Decapsulation");

    DecapsAction {
        input_file: encapsulation_file,
        key_id: Some(dk_id.to_string()),
        tags: None,
        output_file: Some(session_key_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the session key was written to the output file
    assert!(session_key_file.exists());
    let session_key = std::fs::read(&session_key_file)?;
    assert!(!session_key.is_empty());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_create_configurable_kem_key_pair() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    test_kem(ctx, "ML-KEM512 KEM", 0).await?;
    test_kem(ctx, "ML-KEM768 KEM", 1).await?;
    test_kem(ctx, "P256 KEM", 10).await?;
    test_kem(ctx, "CURVE25519 KEM", 11).await?;
    test_kem(ctx, "ML-KEM512/P256 KEM", 100).await?;
    test_kem(ctx, "ML-KEM768/P256 KEM", 101).await?;
    test_kem(ctx, "ML-KEM512/CURVE25519 KEM", 110).await?;
    test_kem(ctx, "ML-KEM768/CURVE25519 KEM", 111).await?;

    Ok(())
}

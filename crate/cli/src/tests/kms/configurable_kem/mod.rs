use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::configurable_kem::{
        decaps::DecapsAction, encaps::EncapsAction, keygen::CreateKemKeyPairAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_create_configurable_kem_key_pair() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    async fn test_kem(ctx: &TestsContext, name: &str, tag: usize) -> KmsCliResult<()> {
        println!("Key generation ({name})");

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

        println!("Encapsulation");

        let (key, enc) = EncapsAction {
            key_id: Some(ek_id.to_string()),
            encryption_policy: None,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        println!("Decapsulation");

        let key_ = DecapsAction {
            key_id: Some(dk_id.to_string()),
            encapsulation: enc.to_vec(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_eq!(key, key_);

        Ok(())
    }

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

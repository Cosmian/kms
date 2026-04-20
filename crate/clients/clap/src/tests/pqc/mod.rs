use cosmian_kms_logger::log_init;
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::pqc::{
        decapsulate::DecapsulateAction,
        encapsulate::EncapsulateAction,
        keys::create_key_pair::{CreatePqcKeyPairAction, PqcAlgorithm},
        sign::SignAction,
        signature_verify::SignatureVerifyAction,
    },
    error::result::KmsCliResult,
};

async fn test_kem(ctx: &TestsContext, name: &str, algorithm: PqcAlgorithm) -> KmsCliResult<()> {
    let (sk_id, pk_id) = Box::pin(
        CreatePqcKeyPairAction {
            algorithm,
            tags: vec![name.to_owned()],
            sensitive: false,
            rotate_interval: None,
            rotate_name: None,
            rotate_offset: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let encapsulation_file = tmp_path.join("encapsulation.enc");

    EncapsulateAction {
        key_id: Some(pk_id.to_string()),
        tags: None,
        output_file: Some(encapsulation_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(encapsulation_file.exists());
    // The shared secret file is at encapsulation_file.key
    let shared_secret_encaps = encapsulation_file.with_extension("key");
    assert!(shared_secret_encaps.exists());
    let ss1 = std::fs::read(&shared_secret_encaps)?;
    assert!(!ss1.is_empty());

    let session_key_file = tmp_path.join("session_key.plain");
    DecapsulateAction {
        input_file: encapsulation_file,
        key_id: Some(sk_id.to_string()),
        tags: None,
        output_file: Some(session_key_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(session_key_file.exists());
    let ss2 = std::fs::read(&session_key_file)?;
    assert_eq!(ss1, ss2, "Shared secrets must match after encaps/decaps");

    Ok(())
}

async fn test_sign_verify(
    ctx: &TestsContext,
    name: &str,
    algorithm: PqcAlgorithm,
) -> KmsCliResult<()> {
    let (sk_id, pk_id) = Box::pin(
        CreatePqcKeyPairAction {
            algorithm,
            tags: vec![name.to_owned()],
            sensitive: false,
            rotate_interval: None,
            rotate_name: None,
            rotate_offset: None,
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = std::path::PathBuf::from("../../../test_data/plain.txt");
    let sig_file = tmp_path.join("signature.sig");

    SignAction {
        input_file: input_file.clone(),
        key_id: Some(sk_id.to_string()),
        tags: None,
        output_file: Some(sig_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(sig_file.exists());

    let validity = SignatureVerifyAction {
        data_file: input_file,
        signature_file: sig_file,
        key_id: Some(pk_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(
        validity,
        cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
        "Signature must be valid"
    );

    Ok(())
}

#[tokio::test]
async fn test_pqc_ml_kem() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    test_kem(ctx, "PQC ML-KEM-512", PqcAlgorithm::MlKem512).await?;
    test_kem(ctx, "PQC ML-KEM-768", PqcAlgorithm::MlKem768).await?;
    test_kem(ctx, "PQC ML-KEM-1024", PqcAlgorithm::MlKem1024).await?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_ml_dsa() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    test_sign_verify(ctx, "PQC ML-DSA-44", PqcAlgorithm::MlDsa44).await?;
    test_sign_verify(ctx, "PQC ML-DSA-65", PqcAlgorithm::MlDsa65).await?;
    test_sign_verify(ctx, "PQC ML-DSA-87", PqcAlgorithm::MlDsa87).await?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_hybrid_kem() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    test_kem(ctx, "PQC X25519MLKEM768", PqcAlgorithm::X25519MlKem768).await?;
    test_kem(ctx, "PQC X448MLKEM1024", PqcAlgorithm::X448MlKem1024).await?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_slh_dsa() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-128s", PqcAlgorithm::SlhDsaSha2_128s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-128f", PqcAlgorithm::SlhDsaSha2_128f).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-192s", PqcAlgorithm::SlhDsaSha2_192s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-192f", PqcAlgorithm::SlhDsaSha2_192f).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-256s", PqcAlgorithm::SlhDsaSha2_256s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHA2-256f", PqcAlgorithm::SlhDsaSha2_256f).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-128s", PqcAlgorithm::SlhDsaShake128s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-128f", PqcAlgorithm::SlhDsaShake128f).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-192s", PqcAlgorithm::SlhDsaShake192s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-192f", PqcAlgorithm::SlhDsaShake192f).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-256s", PqcAlgorithm::SlhDsaShake256s).await?;
    test_sign_verify(ctx, "PQC SLH-DSA-SHAKE-256f", PqcAlgorithm::SlhDsaShake256f).await?;

    Ok(())
}

#[tokio::test]
async fn test_pqc_configurable_hybrid_kem() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    test_kem(ctx, "PQC ML-KEM-512-P256", PqcAlgorithm::MlKem512P256).await?;
    test_kem(ctx, "PQC ML-KEM-768-P256", PqcAlgorithm::MlKem768P256).await?;
    test_kem(
        ctx,
        "PQC ML-KEM-512-Curve25519",
        PqcAlgorithm::MlKem512Curve25519,
    )
    .await?;
    test_kem(
        ctx,
        "PQC ML-KEM-768-Curve25519",
        PqcAlgorithm::MlKem768Curve25519,
    )
    .await?;

    Ok(())
}

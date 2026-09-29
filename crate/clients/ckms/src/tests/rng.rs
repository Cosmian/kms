use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

#[tokio::test]
async fn test_rng_retrieve() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["rng", "retrieve", "--length", "32"])?;
    assert!(
        !stdout.is_empty(),
        "Expected random bytes output, got empty"
    );

    Ok(())
}

#[tokio::test]
async fn test_rng_seed() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let seed_hex = "00".repeat(16);

    run_ckms(&conf, &["rng", "seed", "--data", &seed_hex])?;

    Ok(())
}

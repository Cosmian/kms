use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

#[tokio::test]
async fn test_discover_versions() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["server", "discover-versions"])?;
    assert!(
        stdout.contains("1.") || stdout.contains("2."),
        "Expected version numbers in output, got: {stdout}"
    );

    Ok(())
}

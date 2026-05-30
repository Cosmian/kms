use test_kms_server::start_default_test_kms_server;

use crate::{
    error::result::CosmianResult,
    tests::utils::{owner_config, run_ckms},
};

#[tokio::test]
async fn test_query() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);

    let stdout = run_ckms(&conf, &["server", "query"])?;
    assert!(
        !stdout.is_empty(),
        "Expected query response, got empty output"
    );

    Ok(())
}

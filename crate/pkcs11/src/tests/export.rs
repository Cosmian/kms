use kms_test_server::{start_default_test_kms_server, ONCE};

use crate::error::Pkcs11Error;

#[tokio::test]
async fn integration_tests_use_ids_no_tags() -> Result<(), Pkcs11Error> {
    let ctx = ONCE
        .get_or_try_init(start_default_test_kms_server)
        .await
        .unwrap();

    let kms_client = ctx.owner_client_conf.initialize_kms_client()?;

    let version = kms_client.version().await?;
    println!("Version: {:?}", version);

    Ok(())
}

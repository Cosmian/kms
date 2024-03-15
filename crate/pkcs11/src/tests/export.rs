use cosmian_kms_client::KmsClient;

use crate::error::Pkcs11Error;

#[tokio::test]
async fn integration_tests_use_ids_no_tags() -> Result<(), Pkcs11Error> {
    // log_init("cosmian_kms_server=info");
    let app = test_utils::test_app().await;

    let client = KmsClient::instantiate(
        "https://localhost:9998",
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )?;

    let version = client.version().await?;
    println!("Version: {:?}", version);

    Ok(())
}

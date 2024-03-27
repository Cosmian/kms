use cosmian_kms_client::ClientError;

use crate::start_default_test_kms_server;

#[tokio::test]
async fn test_start_server() -> Result<(), ClientError> {
    let context = start_default_test_kms_server().await?;
    context.stop_server().await
}

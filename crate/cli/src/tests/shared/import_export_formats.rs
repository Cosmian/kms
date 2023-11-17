use crate::{
    error::CliError,
    tests::{
        shared::import_key,
        utils::{start_default_test_kms_server, ONCE},
    },
};

#[tokio::test]
async fn test_import_export_PKCS8() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    let key_file_path = "test_data/pkcs8_private_key.pem";

    // import the wrapping key
    // let key_uid = import_key(
    //     &ctx.owner_cli_conf_path,
    //     "ec",
    //     wrap_key_path.to_str().unwrap(),
    //     None,
    //     &[],
    //     false,
    //     false,
    // )?;

    Ok(())
}

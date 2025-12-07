#![allow(clippy::unwrap_in_result)]

use std::sync::Arc;

use cosmian_logger::log_init;
use uuid::Uuid;

use crate::{
    config::ServerParams, core::KMS, result::KResult, routes::aws_xks::AwsXksConfig,
    tests::test_utils::https_clap_config,
};

#[tokio::test]
async fn test_xks() -> KResult<()> {
    log_init(Some("debug"));

    let mut clap_config = https_clap_config();
    clap_config.aws_xks_config = AwsXksConfig {
        aws_xks_enable: true,
        aws_xks_region: Some("us-west-2".to_owned()),
        aws_xks_service: Some("kms".to_owned()),
        aws_xks_uri_path_prefix: Some("/kms/v1".to_owned()),
        aws_xks_sigv4_access_key_id: Some("test_access_key_id".to_owned()),
        aws_xks_sigv4_secret_access_key: Some("test_secret_access_key".to_owned()),
        aws_xks_partition: Some("aws".to_owned()),
        aws_xks_account_id: Some("123456789012".to_owned()),
        aws_xks_user_path: Some("?".to_owned()),
        aws_xks_user_name: Some("kms_xks_user".to_owned()),
    };

    let _kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);
    let _owner = Uuid::new_v4().to_string();

    // // request key pair creation
    // let request =
    //     create_ec_key_pair_request(None, EMPTY_TAGS, RecommendedCurve::CURVE25519, false, None)?;
    // let response = kms.create_key_pair(request, owner, None, None).await?;
    // // check that the private and public keys exist
    // // check secret key
    // let sk_response = kms
    //     .get(
    //         get_ec_private_key_request(
    //             response
    //                 .private_key_unique_identifier
    //                 .as_str()
    //                 .context("no string for the private_key_unique_identifier")?,
    //         ),
    //         owner,
    //         None,
    //     )
    //     .await?;
    // let sk_uid = sk_response
    //     .unique_identifier
    //     .as_str()
    //     .context("no string for the unique_identifier")?;
    // let sk = &sk_response.object;
    // let sk_key_block = match sk {
    //     Object::PrivateKey(PrivateKey { key_block }) => key_block.clone(),
    //     _ => {
    //         return Err(KmsError::ServerError(
    //             "Expected a KMIP Private Key".to_owned(),
    //         ));
    //     }
    // };
    // assert_eq!(
    //     sk_key_block.cryptographic_algorithm,
    //     Some(CryptographicAlgorithm::ECDH),
    // );

    Ok(())
}

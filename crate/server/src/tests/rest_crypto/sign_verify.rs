//! RS256 and ES256 sign/verify round-trip tests.

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
    kmip_operations::CreateKeyPairResponse,
    kmip_types::RecommendedCurve,
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::log_init;

use crate::{result::KResult, tests::test_utils};

#[tokio::test]
async fn test_rs256_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req =
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "RS256", &private_kid, &public_kid).await
}

#[tokio::test]
async fn test_es256_round_trip() -> KResult<()> {
    log_init(None);
    let app = test_utils::test_app(None, None).await;

    let kp_req = create_ec_key_pair_request(
        VENDOR_ID_COSMIAN,
        None,
        EMPTY_TAGS,
        RecommendedCurve::P256,
        false,
        None,
    )?;
    let kp_resp: CreateKeyPairResponse = test_utils::post_2_1(&app, kp_req).await?;
    let private_kid = kp_resp.private_key_unique_identifier.to_string();
    let public_kid = kp_resp.public_key_unique_identifier.to_string();

    super::common::sign_verify_round_trip(&app, "ES256", &private_kid, &public_kid).await
}

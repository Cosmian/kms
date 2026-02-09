use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        kmip_operations::{CreateKeyPairResponse, Operation, SignResponse},
        kmip_types::{
            CryptographicParameters, DigitalSignatureAlgorithm, RecommendedCurve, UniqueIdentifier,
        },
        requests::create_ec_key_pair_request,
    },
};
use zeroize::Zeroizing;

use crate::{
    error::KmsError,
    tests::test_utils::{https_clap_config_opts, post_2_1, test_app_with_clap_config},
};

#[actix_web::test]
async fn e2e_signature_algorithm_allowlist_is_enforced_on_sign() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.policy_id = "CUSTOM".to_owned();
    conf.kmip_policy.allowlists.signature_algorithms =
        Some(vec![DigitalSignatureAlgorithm::SHA256WithRSAEncryption]);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-signature-alg-allow"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await.unwrap();
    let sk_uid = create_resp
        .private_key_unique_identifier
        .as_str()
        .expect("private key uid should be a string")
        .to_owned();

    let sign = Operation::Sign(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(sk_uid)),
            cryptographic_parameters: Some(CryptographicParameters {
                digital_signature_algorithm: Some(
                    DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                ),
                ..Default::default()
            }),
            data: Some(Zeroizing::new(b"hello".to_vec())),
            ..Default::default()
        },
    );

    let err = post_2_1::<_, _, SignResponse, _>(&app, &sign)
        .await
        .unwrap_err();
    assert!(
        !matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
        ),
        "should not fail at KMIP policy layer"
    );
}

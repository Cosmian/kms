use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::{CreateKeyPairResponse, DecryptResponse, EncryptResponse},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters, RecommendedCurve},
    requests::{create_ec_key_pair_request, decrypt_request, encrypt_request},
};

use super::helpers::{assert_constraint_violation, https_clap_config_opts};
use crate::{
    error::KmsError,
    tests::test_utils::{post_2_1, test_app_with_clap_config},
};

fn ecies_policy_conf(
    curve: RecommendedCurve,
    allowed_shake: CryptographicAlgorithm,
) -> crate::config::ClapConfig {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.curves = Some(vec![curve]);
    conf.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        allowed_shake,
    ]);
    conf
}

async fn e2e_ecies_roundtrip_with_policy(
    curve: RecommendedCurve,
    allowed_shake: CryptographicAlgorithm,
) -> Result<(), KmsError> {
    let conf = ecies_policy_conf(curve, allowed_shake);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(None, ["e2e-ecies-matrix"], curve, false, None)
        .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await?;

    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid
    } else {
        format!("{pk_uid}_pk")
    };
    let sk_uid = create_resp
        .private_key_unique_identifier
        .as_str()
        .expect("private key uid should be a string")
        .to_owned();

    let plaintext = b"ecies-matrix".to_vec();

    let shake_hash = None;

    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext.clone(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            hashing_algorithm: shake_hash,
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");
    let enc_resp: EncryptResponse = post_2_1(&app, &enc_req).await?;

    let ciphertext = enc_resp.data.expect("encrypt response should include data");

    let dec_req = decrypt_request(
        &sk_uid,
        None,
        ciphertext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            hashing_algorithm: shake_hash,
            ..Default::default()
        }),
    );
    let dec_resp: DecryptResponse = post_2_1(&app, &dec_req).await?;

    assert_eq!(
        dec_resp
            .data
            .expect("decrypt response should include data")
            .to_vec(),
        plaintext
    );

    Ok(())
}

#[actix_web::test]
async fn e2e_ecies_matrix_p256_shake128_passes_shake256_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P256,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .expect("P-256 should work with SHAKE128 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P256,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[actix_web::test]
async fn e2e_ecies_matrix_p384_shake256_passes_shake128_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P384,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .expect("P-384 should work with SHAKE256 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P384,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[actix_web::test]
async fn e2e_ecies_matrix_p521_shake256_passes_shake128_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P521,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .expect("P-521 should work with SHAKE256 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P521,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[actix_web::test]
async fn e2e_ecies_is_allowed_when_curves_allowlist_is_unset() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.curves = None;
    conf.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        CryptographicAlgorithm::SHAKE128,
        CryptographicAlgorithm::SHAKE256,
    ]);

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-ecies-curve-unset"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp)
        .await
        .expect("create keypair should succeed");

    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid
    } else {
        format!("{pk_uid}_pk")
    };

    let plaintext = b"ecies-curve-unset".to_vec();
    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            hashing_algorithm: None,
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");

    let res: Result<EncryptResponse, KmsError> = post_2_1(&app, &enc_req).await;
    res.expect("policy should not block ECIES when curves allowlist is unset");
}

#[actix_web::test]
async fn e2e_ecies_is_denied_when_curves_allowlist_is_empty() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.curves = Some(vec![]);
    conf.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        CryptographicAlgorithm::SHAKE256,
    ]);

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-ecies-curve-empty"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");

    let res: Result<CreateKeyPairResponse, KmsError> = post_2_1(&app, &create_kp).await;

    let err = res.unwrap_err();
    assert_constraint_violation(err);
}

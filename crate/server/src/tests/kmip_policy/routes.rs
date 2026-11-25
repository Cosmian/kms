//! F-038 (#1492): the JOSE `/v1/crypto/*` and SPIRE transit routes call the KMS directly,
//! so they must enforce `kmip_policy` themselves, with the same error as the KMIP endpoints.

use std::sync::Arc;

use actix_http::Request;
use actix_web::{
    App,
    body::MessageBody,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test,
    web::{self, Data},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm},
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_operations::{
            CreateKeyPairResponse, CreateResponse, Encrypt, MAC, Operation, Sign, SignatureVerify,
        },
        kmip_types::{CryptographicAlgorithm, DigitalSignatureAlgorithm, RecommendedCurve},
        requests::{
            create_ec_key_pair_request, create_rsa_key_pair_request, symmetric_key_create_request,
        },
    },
};
use serde_json::{Value, json};

use crate::{
    config::{AesKeySize, RsaKeySize},
    core::{KMS, operations::algorithm_policy::enforce_kmip_algorithm_policy_for_request},
    error::KmsError,
    middlewares::UserId,
    routes::{
        self,
        jose::{JoseAlgorithm, JoseEncAlgorithm, jose_to_kmip_params},
    },
    tests::test_utils::{https_clap_config, post_2_1, post_json_with_uri, test_kms_with_config},
};

const JOSE_KEYS: &str = "/v1/crypto/keys";

/// Policy allowing only P-384, RSA 3072/4096 and AES-256: P-256, RSA-2048 and AES-128 are
/// denied, in FIPS and non-FIPS builds alike.
async fn restrictive_policy_kms() -> Arc<KMS> {
    let mut conf = https_clap_config();
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.curves = Some(vec![RecommendedCurve::P384]);
    conf.kmip_policy.allowlists.rsa_key_sizes =
        Some(vec![RsaKeySize::Rsa3072, RsaKeySize::Rsa4096]);
    conf.kmip_policy.allowlists.aes_key_sizes = Some(vec![AesKeySize::Aes256]);
    test_kms_with_config(conf).await.unwrap()
}

/// The KMIP endpoint, the JOSE key route and the SPIRE transit key route on one KMS.
async fn policy_app(
    kms: Arc<KMS>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    test::init_service(
        App::new()
            .app_data(Data::new(kms))
            .service(routes::kmip::kmip_2_1_json)
            .service(web::scope("/v1/crypto").service(routes::jose::create_key_handler))
            .service(web::scope("/v1/transit").service(routes::spire::transit::create_transit_key)),
    )
    .await
}

/// The policy message the KMIP path returns for `op`.
fn kmip_policy_message(kms: &KMS, op: &Operation) -> String {
    match enforce_kmip_algorithm_policy_for_request(&kms.params, op) {
        Err(KmsError::Kmip21Error(_, msg)) => msg,
        other => panic!(
            "the KMIP path must deny {} with a policy error, got {other:?}",
            op.operation_enum()
        ),
    }
}

fn ec_create(curve: RecommendedCurve) -> Operation {
    Operation::CreateKeyPair(Box::new(
        create_ec_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, curve, false, None)
            .unwrap(),
    ))
}

fn rsa_create(bits: usize) -> Operation {
    Operation::CreateKeyPair(Box::new(
        create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, bits, false, None)
            .unwrap(),
    ))
}

fn aes_create(bits: usize) -> Operation {
    Operation::Create(Box::new(
        symmetric_key_create_request(
            VENDOR_ID_COSMIAN,
            None,
            bits,
            CryptographicAlgorithm::AES,
            EMPTY_TAGS,
            false,
            None,
        )
        .unwrap(),
    ))
}

async fn assert_route_denied<S, B>(app: &S, uri: &str, body: &Value, expected: &str)
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let Err(err) = post_json_with_uri::<_, _, Value, _>(app, body, uri).await else {
        panic!("{uri} {body} must be denied by the KMIP policy");
    };
    assert!(
        err.to_string().contains(expected),
        "{uri} {body} must fail with the KMIP policy error `{expected}`, got: {err}"
    );
}

#[actix_web::test]
async fn jose_key_creation_honours_kmip_policy() {
    let kms = restrictive_policy_kms().await;
    let ec_msg = kmip_policy_message(&kms, &ec_create(RecommendedCurve::P256));
    let rsa_msg = kmip_policy_message(&kms, &rsa_create(2048));
    let aes_msg = kmip_policy_message(&kms, &aes_create(128));
    let app = policy_app(kms).await;

    // The KMIP endpoint returns these messages.
    let err = post_2_1::<_, _, CreateKeyPairResponse, _>(&app, &ec_create(RecommendedCurve::P256))
        .await
        .unwrap_err();
    assert!(err.to_string().contains(&ec_msg), "KMIP P-256: {err}");
    let err = post_2_1::<_, _, CreateKeyPairResponse, _>(&app, &rsa_create(2048))
        .await
        .unwrap_err();
    assert!(err.to_string().contains(&rsa_msg), "KMIP RSA-2048: {err}");
    let err = post_2_1::<_, _, CreateResponse, _>(&app, &aes_create(128))
        .await
        .unwrap_err();
    assert!(err.to_string().contains(&aes_msg), "KMIP AES-128: {err}");

    // CreateKeyPair (EC, RSA)
    assert_route_denied(
        &app,
        JOSE_KEYS,
        &json!({"kty": "EC", "crv": "P-256", "alg": "ES256"}),
        &ec_msg,
    )
    .await;
    assert_route_denied(
        &app,
        JOSE_KEYS,
        &json!({"kty": "RSA", "bits": 2048, "alg": "RS256"}),
        &rsa_msg,
    )
    .await;
    // Create (symmetric generation)
    assert_route_denied(
        &app,
        JOSE_KEYS,
        &json!({"kty": "oct", "alg": "A128GCM"}),
        &aes_msg,
    )
    .await;
    // Import (symmetric key material)
    assert_route_denied(
        &app,
        JOSE_KEYS,
        &json!({"kty": "oct", "alg": "A128GCM", "k": URL_SAFE_NO_PAD.encode([0x5a_u8; 16])}),
        &aes_msg,
    )
    .await;
}

#[actix_web::test]
async fn spire_transit_key_creation_honours_kmip_policy() {
    let kms = restrictive_policy_kms().await;
    let ec_msg = kmip_policy_message(&kms, &ec_create(RecommendedCurve::P256));
    let rsa_msg = kmip_policy_message(&kms, &rsa_create(2048));
    let app = policy_app(kms).await;

    assert_route_denied(
        &app,
        "/v1/transit/keys/policy-p256",
        &json!({"type": "ecdsa-p256"}),
        &ec_msg,
    )
    .await;
    assert_route_denied(
        &app,
        "/v1/transit/keys/policy-rsa2048",
        &json!({"type": "rsa-2048"}),
        &rsa_msg,
    )
    .await;

    // A policy denial is a client error, not a 500.
    let res = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/v1/transit/keys/policy-p256-status")
            .set_json(json!({"type": "ecdsa-p256"}))
            .to_request(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = String::from_utf8(test::read_body(res).await.to_vec()).unwrap();
    assert!(body.contains(&ec_msg), "transit P-256 body: {body}");
}

/// Policy denying SHA-256 hashes, RSA-SHA256 signatures and GCM: HS256, RS256 and `dir`/A256GCM
/// are denied, in FIPS and non-FIPS builds alike.
async fn restrictive_crypto_policy_kms() -> Arc<KMS> {
    let mut conf = https_clap_config();
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
    conf.kmip_policy.allowlists.hashes = Some(vec![HashingAlgorithm::SHA384]);
    conf.kmip_policy.allowlists.signature_algorithms =
        Some(vec![DigitalSignatureAlgorithm::SHA384WithRSAEncryption]);
    conf.kmip_policy.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::CBC]);
    test_kms_with_config(conf).await.unwrap()
}

#[actix_web::test]
async fn jose_crypto_operations_honour_kmip_policy() {
    let kms = restrictive_crypto_policy_kms().await;
    let rs256 = || Some(jose_to_kmip_params(JoseAlgorithm::RS256, None).unwrap());
    let sign_msg = kmip_policy_message(
        &kms,
        &Operation::Sign(Sign {
            cryptographic_parameters: rs256(),
            ..Default::default()
        }),
    );
    let verify_msg = kmip_policy_message(
        &kms,
        &Operation::SignatureVerify(SignatureVerify {
            cryptographic_parameters: rs256(),
            ..Default::default()
        }),
    );
    let mac_msg = kmip_policy_message(
        &kms,
        &Operation::MAC(MAC {
            cryptographic_parameters: Some(
                jose_to_kmip_params(JoseAlgorithm::HS256, None).unwrap(),
            ),
            ..Default::default()
        }),
    );
    let encrypt_msg = kmip_policy_message(
        &kms,
        &Operation::Encrypt(Box::new(Encrypt {
            cryptographic_parameters: Some(
                jose_to_kmip_params(JoseAlgorithm::Dir, Some(JoseEncAlgorithm::A256GCM)).unwrap(),
            ),
            ..Default::default()
        })),
    );
    // The sign route looks the key up first; the KMS API itself does not apply the policy.
    let signing_kid = kms
        .create_key_pair(
            create_rsa_key_pair_request(VENDOR_ID_COSMIAN, None, EMPTY_TAGS, 2048, false, None)
                .unwrap(),
            &UserId::from(kms.params.default_username.as_str()),
        )
        .await
        .unwrap()
        .private_key_unique_identifier
        .to_string();
    let app = test::init_service(
        App::new().app_data(Data::new(kms)).service(
            web::scope("/v1/crypto")
                .service(routes::jose::sign_handler)
                .service(routes::jose::verify_handler)
                .service(routes::jose::mac_handler)
                .service(routes::jose::encrypt_handler),
        ),
    )
    .await;
    let data = URL_SAFE_NO_PAD.encode(b"payload");
    let sig = URL_SAFE_NO_PAD.encode([0x5a_u8; 32]);

    assert_route_denied(
        &app,
        "/v1/crypto/sign",
        &json!({"kid": signing_kid, "alg": "RS256", "data": data}),
        &sign_msg,
    )
    .await;
    assert_route_denied(
        &app,
        "/v1/crypto/verify",
        &json!({
            "protected": URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"any"}"#),
            "data": data,
            "signature": sig,
        }),
        &verify_msg,
    )
    .await;
    assert_route_denied(
        &app,
        "/v1/crypto/mac",
        &json!({"kid": "any", "alg": "HS256", "data": data}),
        &mac_msg,
    )
    .await;
    // MACVerify carries the same parameters, so the policy denies it with the same message.
    assert_route_denied(
        &app,
        "/v1/crypto/mac",
        &json!({"kid": "any", "alg": "HS256", "data": data, "mac": sig}),
        &mac_msg,
    )
    .await;
    assert_route_denied(
        &app,
        "/v1/crypto/encrypt",
        &json!({"kid": "any", "alg": "dir", "enc": "A256GCM", "data": data}),
        &encrypt_msg,
    )
    .await;
}

#[actix_web::test]
async fn routes_still_create_policy_compliant_keys() {
    let app = policy_app(restrictive_policy_kms().await).await;

    let _ec: Value = post_json_with_uri(
        &app,
        json!({"kty": "EC", "crv": "P-384", "alg": "ES384"}),
        JOSE_KEYS,
    )
    .await
    .expect("JOSE P-384 key creation is allowed by the policy");
    let _aes: Value = post_json_with_uri(&app, json!({"kty": "oct", "alg": "A256GCM"}), JOSE_KEYS)
        .await
        .expect("JOSE AES-256 key creation is allowed by the policy");
    let _transit: Value = post_json_with_uri(
        &app,
        json!({"type": "ecdsa-p384"}),
        "/v1/transit/keys/policy-p384",
    )
    .await
    .expect("SPIRE transit P-384 key creation is allowed by the policy");
}

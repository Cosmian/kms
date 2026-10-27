//! Google CSE endpoints with token validation **enabled**, against a local identity
//! provider (a single RSA key published through an in-memory JWKS): no Google credentials,
//! no Google network access.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, RwLock},
};

use actix_http::{Request, body::MessageBody};
use actix_web::{
    ResponseError,
    dev::{Service, ServiceResponse},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::{Encrypt, EncryptResponse},
    kmip_types::UniqueIdentifier,
};
use jsonwebtoken::jwk::JwkSet;
use openssl::{
    hash::{MessageDigest, hash},
    pkey::{PKey, Private},
    rsa::Rsa,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{
    import_google_cse_key_file_with_access, import_google_cse_symmetric_key_with_access,
    rsa_encrypt,
    utils::{
        DRIVE_RESOURCE, LOCAL_AUTHN_ISSUER, LOCAL_KACLS_URL, LOCAL_KID, LOCAL_KMS_PUBLIC_URL,
        authn_token, authn_token_with_aud, authz_token, build_jwks_manager_with_key,
        gmail_authz_token, local_google_cse_config, migration_authz_token,
    },
};
use crate::{
    core::KMS,
    error::KmsError,
    middlewares::{JwksManager, JwtConfig},
    routes::google_cse::{
        GoogleCseConfig,
        operations::{
            DigestRequest, GOOGLE_CSE_ID, PrivateKeyDecryptRequest, PrivateKeySignRequest,
            PrivilegedUnwrapRequest, PrivilegedWrapRequest, RewrapRequest, UnwrapRequest,
            WrapRequest, compute_resource_key_hash, rewrap_with_client,
        },
    },
    tests::test_utils::{
        self, get_json_with_uri, https_clap_config_opts, post_json_raw, test_app_with_google_cse,
    },
};

const DEK: &str = "wHrlNOTI9mU6PBdqiq7EQA==";
const USER: &str = "user@example.com";

fn unauthorized() -> StatusCode {
    KmsError::Unauthorized(String::new()).status_code()
}

fn invalid_request() -> StatusCode {
    KmsError::InvalidRequest(String::new()).status_code()
}

/// Assert a structured CSE error reply: expected status, exact body shape, `details` content.
fn assert_error(reply: &(StatusCode, Value), expected: StatusCode, details_contain: &str) {
    let (status, body) = reply;
    assert_eq!(*status, expected, "{body}");
    let obj = body
        .as_object()
        .unwrap_or_else(|| panic!("error reply is not a JSON object: {body}"));
    assert_eq!(
        obj.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["code", "message", "details"])
    );
    assert_eq!(
        obj.get("message"),
        Some(&json!("A CSE request to the Cosmian KMS failed"))
    );
    assert_eq!(obj.get("code"), Some(&json!(expected.as_u16())));
    let details = obj
        .get("details")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        details.contains(details_contain),
        "`{details}` does not contain `{details_contain}`"
    );
}

async fn validating_app_with_config(
    google_cse_config: GoogleCseConfig,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    let mut clap_config = https_clap_config_opts(Some(LOCAL_KMS_PUBLIC_URL.to_owned()));
    clap_config
        .google_cse_config
        .google_cse_disable_tokens_validation = false;
    let app = Box::pin(test_app_with_google_cse(
        clap_config,
        Some(google_cse_config),
    ))
    .await;
    import_google_cse_symmetric_key_with_access(&app)
        .await
        .unwrap();
    app
}

async fn validating_app(
    rsa: &Rsa<Private>,
) -> impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error> {
    validating_app_with_config(local_google_cse_config(rsa)).await
}

/// An authorization token for the Drive test resource and an empty perimeter.
fn authz(rsa: &Rsa<Private>, email: Option<&str>, role: &str) -> String {
    authz_token(rsa, email, role, DRIVE_RESOURCE, "")
}

fn wrap_request(authentication: String, authorization: String) -> WrapRequest {
    WrapRequest {
        authentication,
        authorization,
        key: DEK.to_owned(),
        reason: String::new(),
    }
}

fn unwrap_request(
    authentication: String,
    authorization: String,
    wrapped_key: String,
) -> UnwrapRequest {
    UnwrapRequest {
        authentication,
        authorization,
        wrapped_key,
        reason: String::new(),
    }
}

fn field(body: &Value, name: &str) -> String {
    body.get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no string field `{name}` in {body}"))
        .to_owned()
}

/// Wrap [`DEK`] for [`USER`] on the Drive test resource and return the wrapped key.
async fn wrap_dek<B, S>(app: &S, rsa: &Rsa<Private>, perimeter_id: &str) -> String
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let (status, body) = post_json_raw(
        app,
        wrap_request(
            authn_token(rsa, Some(USER), None),
            authz_token(rsa, Some(USER), "writer", DRIVE_RESOURCE, perimeter_id),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    field(&body, "wrapped_key")
}

#[tokio::test]
async fn wrap_unwrap_roundtrip() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;
    let authn = authn_token(&rsa, Some(USER), None);

    let wrapped_key = wrap_dek(&app, &rsa, "").await;
    let (status, body) = post_json_raw(
        &app,
        unwrap_request(authn, authz(&rsa, Some(USER), "reader"), wrapped_key),
        "/google_cse/unwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), DEK);
}

#[tokio::test]
async fn wrap_uses_google_email_over_email() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    // `google_email` wins over `email`: it matches the authorization email
    let (status, body) = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some("other@example.com"), Some(USER)),
            authz(&rsa, Some(USER), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // and the other way round: `email` matches but `google_email` does not
    let reply = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some(USER), Some("other@example.com")),
            authz(&rsa, Some(USER), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authentication and authorization emails in tokens do not match",
    );
}

#[tokio::test]
async fn wrap_rejects_email_mismatch() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let reply = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some("a@example.com"), None),
            authz(&rsa, Some("b@example.com"), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authentication and authorization emails in tokens do not match",
    );
}

#[tokio::test]
async fn email_match_is_case_insensitive() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let (status, body) = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some("User@Example.com"), None),
            authz(&rsa, Some("user@example.com"), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn wrap_rejects_authn_without_email() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let reply = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, None, None),
            authz(&rsa, Some(USER), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authentication token should contain a google_email or an email",
    );
}

#[tokio::test]
async fn wrap_rejects_authz_without_email() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let reply = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&rsa, None, "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authorization token should contain an email",
    );
}

#[tokio::test]
async fn wrap_rejects_authz_signed_by_unknown_key() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;
    // same `kid`, different key: only the signature check can reject it
    let other = Rsa::generate(2048).unwrap();

    let reply = post_json_raw(
        &app,
        wrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&other, Some(USER), "writer"),
        ),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Failed to decode authorization token with any configured JWT authorization config",
    );
}

#[tokio::test]
async fn wrap_rejects_garbage_authn() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let reply = post_json_raw(
        &app,
        wrap_request("not-a-jwt".to_owned(), authz(&rsa, Some(USER), "writer")),
        "/google_cse/wrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Fail to decode authentication token with the given config",
    );
}

#[tokio::test]
async fn unwrap_rejects_wrong_resource_name() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;
    let wrapped_key = wrap_dek(&app, &rsa, "").await;

    // the resource name is bound to the wrapped key as additional authenticated data
    let (status, _body) = post_json_raw(
        &app,
        unwrap_request(
            authn_token(&rsa, Some(USER), None),
            authz_token(
                &rsa,
                Some(USER),
                "reader",
                "//googleapis.com/drive/files/other",
                "",
            ),
            wrapped_key,
        ),
        "/google_cse/unwrap",
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}

/// Wrap a private key the way `ckms google key-pairs create` does: AES-GCM under the
/// `google_cse` key with no additional authenticated data, laid out as `nonce || ciphertext || tag`.
async fn wrap_private_key_out_of_band<B, S>(app: &S, der: &[u8]) -> String
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let response: EncryptResponse = test_utils::post_2_1(
        app,
        Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(GOOGLE_CSE_ID.to_owned())),
            cryptographic_parameters: None,
            data: Some(der.to_vec().into()),
            i_v_counter_nonce: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
            authenticated_encryption_additional_data: None,
        },
    )
    .await
    .unwrap();
    let mut wrapped = response.i_v_counter_nonce.unwrap();
    wrapped.extend_from_slice(&response.data.unwrap());
    wrapped.extend_from_slice(&response.authenticated_encryption_tag.unwrap());
    general_purpose::STANDARD.encode(wrapped)
}

/// Gmail flow with spec-shaped Gmail authorization tokens: issuer
/// `gsuitecse-tokenissuer-gmail@...`, roles `signer` / `decrypter`, and the `spki_hash` of the
/// private key being accessed.
#[tokio::test]
async fn private_key_sign_and_decrypt_with_tokens() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;
    let authn = authn_token(&rsa, Some(USER), None);

    let user_key = Rsa::generate(2048).unwrap();
    let spki_hash = general_purpose::STANDARD.encode(
        hash(
            MessageDigest::sha256(),
            &PKey::from_rsa(user_key.clone())
                .unwrap()
                .public_key_to_der()
                .unwrap(),
        )
        .unwrap(),
    );
    let wrapped_private_key =
        wrap_private_key_out_of_band(&app, &user_key.private_key_to_der().unwrap()).await;

    let digest = hash(MessageDigest::sha256(), b"message").unwrap();
    let (status, body) = post_json_raw(
        &app,
        PrivateKeySignRequest {
            authentication: authn.clone(),
            authorization: gmail_authz_token(&rsa, USER, "signer", &spki_hash),
            algorithm: "SHA256withRSA".to_owned(),
            digest: general_purpose::STANDARD.encode(digest),
            rsa_pss_salt_length: None,
            reason: String::new(),
            wrapped_private_key: wrapped_private_key.clone(),
        },
        "/google_cse/privatekeysign",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!field(&body, "signature").is_empty());

    let dek = [7_u8; 32];
    let encrypted = rsa_encrypt(
        Rsa::public_key_from_der_pkcs1(&user_key.public_key_to_der_pkcs1().unwrap()).unwrap(),
        &dek,
    )
    .unwrap();
    let (status, body) = post_json_raw(
        &app,
        PrivateKeyDecryptRequest {
            authentication: authn,
            authorization: gmail_authz_token(&rsa, USER, "decrypter", &spki_hash),
            algorithm: "RSA/ECB/PKCS1Padding".to_owned(),
            encrypted_data_encryption_key: encrypted,
            rsa_oaep_label: None,
            reason: String::new(),
            wrapped_private_key,
        },
        "/google_cse/privatekeydecrypt",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        field(&body, "data_encryption_key"),
        general_purpose::STANDARD.encode(dek)
    );
}

fn expected_hash(perimeter_id: &str) -> String {
    let dek = Zeroizing::new(general_purpose::STANDARD.decode(DEK).unwrap());
    compute_resource_key_hash(DRIVE_RESOURCE, perimeter_id, &dek).unwrap()
}

async fn digest_of_wrapped_dek<B, S>(app: &S, rsa: &Rsa<Private>) -> String
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let wrapped_key = wrap_dek(app, rsa, "").await;
    let (status, body) = post_json_raw(
        app,
        DigestRequest {
            authorization: migration_authz_token(rsa, Some(USER), "verifier", DRIVE_RESOURCE),
            wrapped_key,
            reason: String::new(),
        },
        "/google_cse/digest",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    field(&body, "resource_key_hash")
}

#[tokio::test]
async fn digest_matches_resource_key_hash() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    assert_eq!(digest_of_wrapped_dek(&app, &rsa).await, expected_hash(""));
}

#[tokio::test]
async fn digest_rejects_authz_without_email() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    let reply = post_json_raw(
        &app,
        DigestRequest {
            authorization: migration_authz_token(&rsa, None, "verifier", DRIVE_RESOURCE),
            wrapped_key: "AAAA".to_owned(),
            reason: String::new(),
        },
        "/google_cse/digest",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authorization token should contain an email",
    );
}

#[tokio::test]
async fn privileged_wrap_unwrap_roundtrip() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;
    let authn = authn_token(&rsa, Some(USER), None);

    let (status, body) = post_json_raw(
        &app,
        PrivilegedWrapRequest {
            authentication: authn.clone(),
            key: DEK.to_owned(),
            perimeter_id: String::new(),
            resource_name: "resource_name_test".to_owned(),
            reason: String::new(),
        },
        "/google_cse/privilegedwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = post_json_raw(
        &app,
        PrivilegedUnwrapRequest {
            authentication: authn,
            reason: String::new(),
            resource_name: "resource_name_test".to_owned(),
            wrapped_key: field(&body, "wrapped_key"),
        },
        "/google_cse/privilegedunwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), DEK);
}

#[tokio::test]
async fn privileged_unwrap_drive_resource_checks_audience() {
    let rsa = Rsa::generate(2048).unwrap();
    let mut config = local_google_cse_config(&rsa);
    config.authentication = Arc::new(vec![JwtConfig {
        jwt_issuer_uri: LOCAL_AUTHN_ISSUER.to_owned(),
        jwks: build_jwks_manager_with_key(LOCAL_KID, &rsa),
        jwt_audience: Some(vec!["kacls-migration".to_owned()]),
        accept_spiffe_subject: false,
    }]);
    let app = validating_app_with_config(config).await;

    let reply = post_json_raw(
        &app,
        PrivilegedUnwrapRequest {
            authentication: authn_token_with_aud(&rsa, None, None, "wrong"),
            reason: String::new(),
            resource_name: DRIVE_RESOURCE.to_owned(),
            wrapped_key: "AAAA".to_owned(),
        },
        "/google_cse/privilegedunwrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authentication token audience not allowed",
    );
}

#[tokio::test]
async fn rewrap_rejects_bad_original_kacls() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    for (url, details) in [
        ("http://kacls.example.com", "must use HTTPS scheme"),
        (
            "https://127.0.0.1",
            "must not target private or loopback addresses",
        ),
        ("https://localhost", "must not target internal hostnames"),
        ("://bad", "is invalid"),
    ] {
        let reply = post_json_raw(
            &app,
            RewrapRequest {
                authorization: migration_authz_token(&rsa, Some(USER), "migrator", DRIVE_RESOURCE),
                original_kacls_url: url.to_owned(),
                reason: String::new(),
                wrapped_key: "AAAA".to_owned(),
            },
            "/google_cse/rewrap",
        )
        .await;
        assert_error(&reply, invalid_request(), details);
    }
}

#[tokio::test]
async fn rewrap_rejects_authz_without_email() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    // `validate_cse_authorization_token` rejects the missing email before `rewrap`'s own check
    let reply = post_json_raw(
        &app,
        RewrapRequest {
            authorization: migration_authz_token(&rsa, None, "migrator", DRIVE_RESOURCE),
            original_kacls_url: "https://kacls.example.com".to_owned(),
            reason: String::new(),
            wrapped_key: "AAAA".to_owned(),
        },
        "/google_cse/rewrap",
    )
    .await;
    assert_error(
        &reply,
        unauthorized(),
        "Authorization token should contain an email",
    );
}

#[tokio::test]
async fn error_reply_shape() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = validating_app(&rsa).await;

    // an authentication failure and a request failure share the same structured reply
    let unauthorized_reply = post_json_raw(
        &app,
        wrap_request("not-a-jwt".to_owned(), "not-a-jwt".to_owned()),
        "/google_cse/wrap",
    )
    .await;
    assert_error(&unauthorized_reply, unauthorized(), "");

    let invalid_reply = post_json_raw(
        &app,
        unwrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&rsa, Some(USER), "reader"),
            general_purpose::STANDARD.encode([0_u8; 27]),
        ),
        "/google_cse/unwrap",
    )
    .await;
    assert_error(
        &invalid_reply,
        invalid_request(),
        "Invalid wrapped key - insufficient length.",
    );
}

struct TwoKacls<AppA, AppB> {
    kms_a: Arc<KMS>,
    config_a: GoogleCseConfig,
    app_a: AppA,
    app_b: AppB,
    original_kacls_url: String,
    wrapped_on_b: String,
}

async fn two_kacls(
    rsa: &Rsa<Private>,
) -> TwoKacls<
    impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error>,
    impl Service<Request, Response = ServiceResponse<impl MessageBody>, Error = actix_web::Error>,
> {
    let mut clap_a = https_clap_config_opts(Some(LOCAL_KMS_PUBLIC_URL.to_owned()));
    clap_a
        .google_cse_config
        .google_cse_disable_tokens_validation = false;
    let kms_a = Box::pin(test_utils::test_kms_with_google_cse(clap_a)).await;
    let config_a = local_google_cse_config(rsa);
    let app_a = test_utils::test_app_with_kms(kms_a.clone(), Some(config_a.clone())).await;
    import_google_cse_symmetric_key_with_access(&app_a)
        .await
        .unwrap();
    let jwks_a: JwkSet = get_json_with_uri(&app_a, "/google_cse/certs")
        .await
        .unwrap();

    let mut clap_b = https_clap_config_opts(Some("https://kms-original.example.com".to_owned()));
    clap_b
        .google_cse_config
        .google_cse_disable_tokens_validation = false;
    clap_b.db.sqlite_path.set_extension("original.sqlite");
    let mut config_b = local_google_cse_config(rsa);
    config_b.authentication = Arc::new(vec![
        JwtConfig {
            jwt_issuer_uri: LOCAL_KACLS_URL.to_owned(),
            jwt_audience: Some(vec!["kacls-migration".to_owned()]),
            jwks: Arc::new(JwksManager {
                uris: vec![LOCAL_KACLS_URL.to_owned()],
                jwks: RwLock::new(HashMap::from([(LOCAL_KACLS_URL.to_owned(), jwks_a)])),
                last_update: RwLock::new(Some(chrono::Utc::now())),
                last_force_refresh: RwLock::new(None),
                proxy_params: None,
                accept_invalid_certs: false,
            }),
            accept_spiffe_subject: false,
        },
        JwtConfig {
            jwt_issuer_uri: LOCAL_AUTHN_ISSUER.to_owned(),
            jwt_audience: None,
            jwks: build_jwks_manager_with_key(LOCAL_KID, rsa),
            accept_spiffe_subject: false,
        },
    ]);
    let kms_b = Box::pin(test_utils::test_kms_with_google_cse(clap_b)).await;
    let app_b = test_utils::test_app_with_kms(kms_b.clone(), Some(config_b.clone())).await;
    import_google_cse_key_file_with_access(
        &app_b,
        "../../documentation/docs/google_cse/original_kms_cse_key.demo.key.json",
    )
    .await
    .unwrap();
    let wrapped_on_b = wrap_dek(&app_b, rsa, "").await;
    let original_kacls_url = test_utils::spawn_google_cse_http_server(kms_b, Some(config_b));

    TwoKacls {
        kms_a,
        config_a,
        app_a,
        app_b,
        original_kacls_url,
        wrapped_on_b,
    }
}

#[actix_web::test]
async fn rewrap_migrates_dek_between_two_kacls() {
    let rsa = Rsa::generate(2048).unwrap();
    let two_kacls = Box::pin(two_kacls(&rsa)).await;
    let cse_config_a = Arc::new(Some(two_kacls.config_a));
    let rewrapped = rewrap_with_client(
        RewrapRequest {
            authorization: migration_authz_token(&rsa, Some(USER), "migrator", DRIVE_RESOURCE),
            original_kacls_url: two_kacls.original_kacls_url,
            reason: String::new(),
            wrapped_key: two_kacls.wrapped_on_b.clone(),
        },
        LOCAL_KACLS_URL,
        &cse_config_a,
        &two_kacls.kms_a,
        async |_: &str| Ok(reqwest::Client::new()),
    )
    .await
    .unwrap();

    assert_eq!(rewrapped.resource_key_hash, expected_hash(""));
    assert_ne!(rewrapped.wrapped_key, two_kacls.wrapped_on_b);

    let (status, body) = post_json_raw(
        &two_kacls.app_a,
        unwrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&rsa, Some(USER), "reader"),
            rewrapped.wrapped_key.clone(),
        ),
        "/google_cse/unwrap",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(field(&body, "key"), DEK);

    let (status, _) = post_json_raw(
        &two_kacls.app_b,
        unwrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&rsa, Some(USER), "reader"),
            rewrapped.wrapped_key.clone(),
        ),
        "/google_cse/unwrap",
    )
    .await;
    assert_ne!(status, StatusCode::OK);

    let (status, _) = post_json_raw(
        &two_kacls.app_a,
        unwrap_request(
            authn_token(&rsa, Some(USER), None),
            authz(&rsa, Some(USER), "reader"),
            two_kacls.wrapped_on_b,
        ),
        "/google_cse/unwrap",
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}

#[actix_web::test]
async fn rewrap_fails_when_original_kacls_refuses() {
    let rsa = Rsa::generate(2048).unwrap();
    let two_kacls = Box::pin(two_kacls(&rsa)).await;
    let cse_config_a = Arc::new(Some(two_kacls.config_a));
    let result = rewrap_with_client(
        RewrapRequest {
            authorization: migration_authz_token(
                &rsa,
                Some(USER),
                "migrator",
                "//googleapis.com/drive/files/other",
            ),
            original_kacls_url: two_kacls.original_kacls_url,
            reason: String::new(),
            wrapped_key: two_kacls.wrapped_on_b,
        },
        LOCAL_KACLS_URL,
        &cse_config_a,
        &two_kacls.kms_a,
        async |_: &str| Ok(reqwest::Client::new()),
    )
    .await;

    let KmsError::ClientConnectionError(error) = result.unwrap_err() else {
        panic!("expected the original KACLS HTTP refusal");
    };
    assert!(
        error.contains("422 Unprocessable Entity"),
        "expected the original KACLS status: {error}"
    );
    assert!(
        error.contains("/google_cse/privilegedunwrap"),
        "expected a privilegedunwrap response from the original KACLS: {error}"
    );
}

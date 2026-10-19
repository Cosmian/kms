//! Google CSE server setup: status, certs, KACLS URL, RSA key-pair handling at startup and
//! the JWT configuration builders. No Google credentials or network access needed.

use std::{ffi::OsString, sync::Arc};

use actix_web::{ResponseError, http::StatusCode};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{KeyWrapType, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_operations::{Destroy, DestroyResponse, Get, Revoke, RevokeResponse},
        kmip_types::{KeyFormatType, UniqueIdentifier},
    },
};
use jsonwebtoken::{
    decode_header,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, PublicKeyUse},
};
use openssl::{pkey::PKey, rsa::Rsa};
use serde_json::json;

use super::utils::{
    LOCAL_KACLS_URL, LOCAL_KID, LOCAL_KMS_PUBLIC_URL, build_jwks_manager_with_key,
    google_cse_rsa_private_der, local_google_cse_config,
};
use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    routes::google_cse::{
        build_google_cse_url, jwt_authorization_config, list_jwks_uri, list_jwt_configurations,
        operations::{StatusResponse, create_jwt},
    },
    start_kms_server::handle_google_cse_rsa_keypair,
    tests::test_utils::{
        self, get_json_raw, get_json_with_uri, https_clap_config_opts, post_2_1, post_json_raw,
        test_app_with_google_cse,
    },
};

const OPERATIONS_SUPPORTED: [&str; 10] = [
    "digest",
    "privatekeydecrypt",
    "privatekeysign",
    "privilegedprivatekeydecrypt",
    "privilegedunwrap",
    "privilegedwrap",
    "rewrap",
    "status",
    "unwrap",
    "wrap",
];

#[tokio::test]
async fn status_fields() {
    let app = test_utils::test_app(Some(LOCAL_KMS_PUBLIC_URL.to_owned())).await;

    let status: StatusResponse = get_json_with_uri(&app, "/google_cse/status").await.unwrap();
    assert_eq!(status.server_type, "KACLS");
    assert_eq!(status.vendor_id, "Cosmian");
    assert_eq!(status.name, "Cosmian KMS");
    assert!(!status.version.is_empty());
    assert_eq!(status.kacls_url, LOCAL_KACLS_URL);
    assert_eq!(status.operations_supported, OPERATIONS_SUPPORTED);
}

#[test]
fn build_google_cse_url_cases() {
    let err = build_google_cse_url(None).unwrap_err();
    assert!(err.to_string().contains("missing KMS_PUBLIC_URL"), "{err}");
    assert_eq!(
        build_google_cse_url(Some("https://h/")).unwrap(),
        "https://h/google_cse"
    );
    assert_eq!(
        build_google_cse_url(Some("https://h")).unwrap(),
        "https://h/google_cse"
    );
}

#[tokio::test]
async fn missing_public_url() {
    let rsa = Rsa::generate(2048).unwrap();
    let app = Box::pin(test_app_with_google_cse(
        https_clap_config_opts(None),
        Some(local_google_cse_config(&rsa)),
    ))
    .await;

    let (status, _body) = get_json_raw(&app, "/google_cse/status").await;
    assert_ne!(status, StatusCode::OK);

    let (status, body) = post_json_raw(
        &app,
        json!({
            "authorization": "x",
            "original_kacls_url": "https://kacls.example.com",
            "reason": "",
            "wrapped_key": "AAAA"
        }),
        "/google_cse/rewrap",
    )
    .await;
    assert_eq!(
        status,
        KmsError::InvalidRequest(String::new()).status_code(),
        "{body}"
    );
    let details = body
        .get("details")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        details.contains("Google CSE KACLS URL can't be built: missing KMS_PUBLIC_URL"),
        "{details}"
    );
}

/// The `/certs` key id is the hash of the KACLS URL, the same one `create_jwt` puts in the
/// header of the tokens it signs.
#[tokio::test]
async fn certs_kid_matches_create_jwt() {
    let app = test_utils::test_app(Some(LOCAL_KMS_PUBLIC_URL.to_owned())).await;
    let der = google_cse_rsa_private_der(&app).await.unwrap();
    let jwt = create_jwt(&der, LOCAL_KACLS_URL, "x", "r").unwrap();
    let expected_kid = decode_header(&jwt).unwrap().kid.unwrap();

    let jwks: JwkSet = get_json_with_uri(&app, "/google_cse/certs").await.unwrap();
    assert_eq!(jwks.keys.len(), 1);
    let jwk = jwks.keys.first().unwrap();
    assert!(matches!(jwk.algorithm, AlgorithmParameters::RSA(_)));
    assert_eq!(jwk.common.key_algorithm, Some(KeyAlgorithm::RS256));
    assert_eq!(jwk.common.public_key_use, Some(PublicKeyUse::Signature));
    assert_eq!(jwk.common.key_id.as_deref(), Some(expected_kid.as_str()));
}

/// The production signature path (`validate_signed_token`) accepts a `create_jwt` token against
/// the key published at `/certs`, and rejects the same token signed by another key.
/// (Authentication-token validation skips signatures in test builds.)
#[cfg(not(feature = "insecure"))]
#[tokio::test]
async fn certs_signature_verifies_with_signed_validation() {
    use std::{collections::HashMap, sync::RwLock};

    use super::utils::{DRIVE_RESOURCE, sign_test_jwt};
    use crate::middlewares::{JwksManager, JwtConfig};

    let app = test_utils::test_app(Some(LOCAL_KMS_PUBLIC_URL.to_owned())).await;
    let der = google_cse_rsa_private_der(&app).await.unwrap();
    let jwt = create_jwt(&der, LOCAL_KACLS_URL, LOCAL_KACLS_URL, DRIVE_RESOURCE).unwrap();
    let kid = decode_header(&jwt).unwrap().kid.unwrap();
    let jwks: JwkSet = get_json_with_uri(&app, "/google_cse/certs").await.unwrap();

    let config = JwtConfig {
        jwt_issuer_uri: LOCAL_KACLS_URL.to_owned(),
        jwt_audience: Some(vec!["kacls-migration".to_owned()]),
        jwks: Arc::new(JwksManager {
            uris: vec![LOCAL_KACLS_URL.to_owned()],
            jwks: RwLock::new(HashMap::from([(LOCAL_KACLS_URL.to_owned(), jwks)])),
            last_update: RwLock::new(Some(chrono::Utc::now())),
            last_force_refresh: RwLock::new(None),
            proxy_params: None,
            accept_invalid_certs: false,
        }),
        accept_spiffe_subject: false,
    };

    let claims = config.validate_signed_token(&jwt, false).unwrap();
    assert_eq!(claims.resource_name.as_deref(), Some(DRIVE_RESOURCE));
    assert_eq!(claims.kacls_url.as_deref(), Some(LOCAL_KACLS_URL));

    // same `kid`, same claims, another signing key
    let now = chrono::Utc::now().timestamp();
    let forged = sign_test_jwt(
        &kid,
        &json!({
            "iss": LOCAL_KACLS_URL,
            "aud": "kacls-migration",
            "iat": now,
            "exp": now + 3600,
            "kacls_url": LOCAL_KACLS_URL,
            "resource_name": DRIVE_RESOURCE,
        }),
        &Rsa::generate(2048).unwrap(),
    );
    config.validate_signed_token(&forged, false).unwrap_err();
}

#[tokio::test]
async fn certs_fails_when_public_key_destroyed() {
    let app = test_utils::test_app(Some(LOCAL_KMS_PUBLIC_URL.to_owned())).await;
    let uid = UniqueIdentifier::TextString("google_cse_rsa_pk".to_owned());

    let (status, _body) = get_json_raw(&app, "/google_cse/certs").await;
    assert_eq!(status, StatusCode::OK);

    let _revoked: RevokeResponse = post_2_1(
        &app,
        Revoke {
            unique_identifier: Some(uid.clone()),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
    )
    .await
    .unwrap();
    let _destroyed: DestroyResponse = post_2_1(
        &app,
        Destroy {
            unique_identifier: Some(uid),
            remove: false,
            cascade: false,
            expected_object_type: None,
        },
    )
    .await
    .unwrap();

    let (status, _body) = get_json_raw(&app, "/google_cse/certs").await;
    assert_ne!(status, StatusCode::OK);
}

async fn kms_with_config(
    google_cse_migration_key: Option<String>,
) -> (Arc<ServerParams>, Arc<KMS>) {
    let mut clap_config = https_clap_config_opts(Some(LOCAL_KMS_PUBLIC_URL.to_owned()));
    clap_config.google_cse_config.google_cse_migration_key = google_cse_migration_key;
    let server_params = Arc::new(ServerParams::try_from(clap_config).unwrap());
    let kms = Arc::new(KMS::instantiate(server_params.clone()).await.unwrap());
    (server_params, kms)
}

/// The modulus of the stored `google_cse_rsa_pk` public key.
async fn rsa_pk_modulus(kms: &Arc<KMS>) -> Vec<u8> {
    let response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(
                    "google_cse_rsa_pk".to_owned(),
                )),
                key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
                key_wrap_type: Some(KeyWrapType::NotWrapped),
                key_compression_type: None,
                key_wrapping_specification: None,
            },
            &UserId::from(kms.params.default_username.as_str()),
        )
        .await
        .unwrap();
    match &response.object.key_block().unwrap().key_value {
        Some(KeyValue::Structure {
            key_material: KeyMaterial::TransparentRSAPublicKey { modulus, .. },
            ..
        }) => modulus.to_bytes_be().1,
        other => panic!("not an RSA public key: {other:?}"),
    }
}

#[tokio::test]
async fn rsa_keypair_generated_once() {
    let (server_params, kms) = kms_with_config(None).await;

    handle_google_cse_rsa_keypair(&kms, &server_params)
        .await
        .unwrap();
    let modulus = rsa_pk_modulus(&kms).await;

    // second call: pre-check finds the existing private key and leaves it untouched
    handle_google_cse_rsa_keypair(&kms, &server_params)
        .await
        .unwrap();
    assert_eq!(rsa_pk_modulus(&kms).await, modulus);
}

#[tokio::test]
async fn rsa_keypair_from_migration_key() {
    let migration_key = Rsa::generate(2048).unwrap();
    let pem = PKey::from_rsa(migration_key.clone())
        .unwrap()
        .private_key_to_pem_pkcs8()
        .unwrap();
    let (server_params, kms) = kms_with_config(Some(String::from_utf8(pem).unwrap())).await;

    handle_google_cse_rsa_keypair(&kms, &server_params)
        .await
        .unwrap();
    assert_eq!(rsa_pk_modulus(&kms).await, migration_key.n().to_vec());
}

#[tokio::test]
async fn rsa_keypair_rejects_bad_migration_pem() {
    let (server_params, kms) = kms_with_config(Some("not a pem".to_owned())).await;

    let err = handle_google_cse_rsa_keypair(&kms, &server_params)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Error parsing google_cse_migration PEM key"),
        "{err}"
    );
}

#[tokio::test]
async fn list_jwt_configurations_per_kacls() {
    // `.invalid` never resolves: the JWKS fetch fails (and is only logged), offline-safe
    let configs = list_jwt_configurations(&["https://kacls.invalid".to_owned()], None)
        .await
        .unwrap();
    assert_eq!(configs.len(), 1);
    let config = configs.first().unwrap();
    assert_eq!(config.jwt_issuer_uri, "https://kacls.invalid");
    assert_eq!(
        config.jwt_audience,
        Some(vec!["kacls-migration".to_owned()])
    );
    assert_eq!(config.jwks.uris, vec!["https://kacls.invalid/certs"]);
}

const DEFAULT_MEET_JWKS_URI: &str = "https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-meet@system.gserviceaccount.com";

#[test]
fn list_jwks_uri_with_whitelist() {
    let uris = list_jwks_uri(Some(vec!["https://k".to_owned()]));
    assert_eq!(uris.len(), 7);
    assert_eq!(uris.last().map(String::as_str), Some("https://k/certs"));
    // the `migration` application always uses Google's KACLS communication service account
    assert_eq!(
        uris.get(4).map(String::as_str),
        Some(
            "https://www.googleapis.com/service_accounts/v1/jwk/apps-security-cse-kaclscommunication@system.gserviceaccount.com"
        )
    );
}

/// Sets or removes an environment variable and restores the previous value on drop.
///
/// Tests using it MUST be `#[serial]`: the process environment is global.
struct EnvVar {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVar {
    #[expect(
        unsafe_code,
        reason = "process environment mutation in #[serial] tests"
    )]
    fn set(key: &'static str, value: Option<&str>) -> Self {
        let previous = std::env::var_os(key);
        // SAFETY: only called from `#[serial]` tests, so no other test thread of this module
        // reads or writes the environment concurrently.
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        Self { key, previous }
    }
}

impl Drop for EnvVar {
    #[expect(
        unsafe_code,
        reason = "process environment mutation in #[serial] tests"
    )]
    fn drop(&mut self) {
        // SAFETY: see `EnvVar::set`.
        unsafe {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

#[test]
#[serial_test::serial]
fn jwks_uri_env_override() {
    let _meet = EnvVar::set("KMS_GOOGLE_CSE_MEET_JWKS_URI", Some("https://custom/jwks"));
    let uris = list_jwks_uri(None);
    assert!(uris.iter().any(|uri| uri == "https://custom/jwks"));
    assert!(!uris.iter().any(|uri| uri == DEFAULT_MEET_JWKS_URI));
}

#[test]
#[serial_test::serial]
fn authz_config_env_and_defaults() {
    let rsa = Rsa::generate(2048).unwrap();
    let jwks = build_jwks_manager_with_key(LOCAL_KID, &rsa);

    {
        let _issuer = EnvVar::set("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", None);
        let _audience = EnvVar::set("KMS_GOOGLE_CSE_AUDIENCE", None);
        let config = jwt_authorization_config(&jwks);
        assert_eq!(config.len(), 6);
        let drive = &config["drive"];
        assert_eq!(
            drive.jwt_issuer_uri,
            "gsuitecse-tokenissuer-drive@system.gserviceaccount.com"
        );
        assert_eq!(
            drive.jwt_audience,
            Some(vec!["cse-authorization".to_owned()])
        );
        assert_eq!(
            config["migration"].jwt_issuer_uri,
            "apps-security-cse-kaclscommunication@system.gserviceaccount.com"
        );
    }

    let _issuer = EnvVar::set("KMS_GOOGLE_CSE_DRIVE_JWT_ISSUER", Some("iss-x"));
    let _audience = EnvVar::set("KMS_GOOGLE_CSE_AUDIENCE", Some("aud-x"));
    let config = jwt_authorization_config(&jwks);
    let drive = &config["drive"];
    assert_eq!(drive.jwt_issuer_uri, "iss-x");
    assert_eq!(drive.jwt_audience, Some(vec!["aud-x".to_owned()]));
}

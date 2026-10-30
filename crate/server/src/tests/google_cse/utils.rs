use std::{collections::HashMap, sync::Arc};

use actix_http::{Request, body::MessageBody};
use actix_web::dev::{Service, ServiceResponse};
use base64::{Engine, engine::general_purpose};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_2_1::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_operations::{Get, GetResponse},
        kmip_types::{KeyFormatType, UniqueIdentifier},
    },
};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{
        AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
        RSAKeyParameters, RSAKeyType,
    },
};
use openssl::{pkey::Private, rsa::Rsa};
use serde::{Deserialize, Serialize};

use crate::{
    config::{IdpAuthConfig, ProxyParams},
    error::KmsError,
    middlewares::{JwksManager, JwtConfig},
    result::KResult,
    routes::google_cse::{self, GoogleCseConfig, operations::GOOGLE_CSE_ID},
    tests::test_utils::post_2_1,
};

/// `kid` of the key published by the local test identity provider
pub(crate) const LOCAL_KID: &str = "local-test-kid";
/// Issuer of the authentication tokens minted by the local test identity provider
pub(crate) const LOCAL_AUTHN_ISSUER: &str = "https://idp.local.test";
/// Issuer of the authorization tokens minted by the local test identity provider
pub(crate) const LOCAL_AUTHZ_ISSUER: &str =
    "gsuitecse-tokenissuer-drive@system.gserviceaccount.com";
/// Issuer of the Gmail authorization tokens (spec: `gsuitecse-tokenissuer-gmail@...`)
pub(crate) const LOCAL_GMAIL_AUTHZ_ISSUER: &str =
    "gsuitecse-tokenissuer-gmail@system.gserviceaccount.com";
/// Issuer of the KACLS migration authorization tokens
pub(crate) const LOCAL_MIGRATION_AUTHZ_ISSUER: &str =
    "apps-security-cse-kaclscommunication@system.gserviceaccount.com";
/// A Gmail CSE key pair resource name (spec: up to 512 bytes)
pub(crate) const GMAIL_RESOURCE: &str =
    "//gmail.googleapis.com/gmail/users/user%40example.com/settings/cse/keypairs/abc123";
/// `KMS_PUBLIC_URL` of the validation-enabled test servers
pub(crate) const LOCAL_KMS_PUBLIC_URL: &str = "https://127.0.0.1:9998";
/// KACLS URL derived from [`LOCAL_KMS_PUBLIC_URL`]
pub(crate) const LOCAL_KACLS_URL: &str = "https://127.0.0.1:9998/google_cse";
/// A Google Drive resource name used by the tests
pub(crate) const DRIVE_RESOURCE: &str = "//googleapis.com/drive/files/test";
/// Audience of the authorization tokens
pub(crate) const AUTHZ_AUDIENCE: &str = "cse-authorization";

/// Build a `JwksManager` pre-loaded with a single RSA public key (no HTTP fetch).
pub(crate) fn build_jwks_manager_with_key(kid: &str, rsa: &Rsa<Private>) -> Arc<JwksManager> {
    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_owned()),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: general_purpose::URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
            e: general_purpose::URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
        }),
    };

    let mut map = HashMap::new();
    map.insert("test".to_owned(), JwkSet { keys: vec![jwk] });

    Arc::new(JwksManager {
        uris: vec![],
        jwks: std::sync::RwLock::new(map),
        last_update: std::sync::RwLock::new(Some(chrono::Utc::now())),
        last_force_refresh: std::sync::RwLock::new(None),
        proxy_params: None,
        accept_invalid_certs: false,
    })
}

/// Sign `claims` as an RS256 JWT carrying `kid`.
pub(crate) fn sign_test_jwt<T: Serialize>(kid: &str, claims: &T, rsa: &Rsa<Private>) -> String {
    let encoding_key = EncodingKey::from_rsa_der(&rsa.private_key_to_der().unwrap());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    encode(&header, claims, &encoding_key).unwrap()
}

/// A [`GoogleCseConfig`] backed by a single local key: no Google network access needed.
pub(crate) fn local_google_cse_config(rsa: &Rsa<Private>) -> GoogleCseConfig {
    let jwks = build_jwks_manager_with_key(LOCAL_KID, rsa);
    GoogleCseConfig {
        authentication: Arc::new(vec![JwtConfig {
            jwt_issuer_uri: LOCAL_AUTHN_ISSUER.to_owned(),
            jwks: jwks.clone(),
            jwt_audience: None,
            accept_spiffe_subject: false,
        }]),
        authorization: HashMap::from([
            (
                "drive".to_owned(),
                Arc::new(JwtConfig {
                    jwt_issuer_uri: LOCAL_AUTHZ_ISSUER.to_owned(),
                    jwks: jwks.clone(),
                    jwt_audience: Some(vec![AUTHZ_AUDIENCE.to_owned()]),
                    accept_spiffe_subject: false,
                }),
            ),
            (
                "gmail".to_owned(),
                Arc::new(JwtConfig {
                    jwt_issuer_uri: LOCAL_GMAIL_AUTHZ_ISSUER.to_owned(),
                    jwks: jwks.clone(),
                    jwt_audience: Some(vec![AUTHZ_AUDIENCE.to_owned()]),
                    accept_spiffe_subject: false,
                }),
            ),
            (
                "migration".to_owned(),
                Arc::new(JwtConfig {
                    jwt_issuer_uri: LOCAL_MIGRATION_AUTHZ_ISSUER.to_owned(),
                    jwks,
                    jwt_audience: Some(vec![AUTHZ_AUDIENCE.to_owned()]),
                    accept_spiffe_subject: false,
                }),
            ),
        ]),
    }
}

fn now_and_expiry() -> (usize, usize) {
    let now = usize::try_from(chrono::Utc::now().timestamp()).unwrap();
    (now, now + 3600)
}

#[derive(Serialize)]
struct AuthnClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    google_email: Option<&'a str>,
    iat: usize,
    exp: usize,
}

/// An authentication token (`aud` is mandatory for the server's claim parser).
pub(crate) fn authn_token_with_aud(
    rsa: &Rsa<Private>,
    email: Option<&str>,
    google_email: Option<&str>,
    aud: &str,
) -> String {
    let (iat, exp) = now_and_expiry();
    sign_test_jwt(
        LOCAL_KID,
        &AuthnClaims {
            iss: LOCAL_AUTHN_ISSUER,
            aud,
            email,
            google_email,
            iat,
            exp,
        },
        rsa,
    )
}

/// An authentication token issued by the local identity provider.
pub(crate) fn authn_token(
    rsa: &Rsa<Private>,
    email: Option<&str>,
    google_email: Option<&str>,
) -> String {
    authn_token_with_aud(rsa, email, google_email, "authn-audience")
}

#[derive(Serialize)]
struct AuthzClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    role: &'a str,
    resource_name: &'a str,
    perimeter_id: &'a str,
    kacls_url: &'a str,
    iat: usize,
    exp: usize,
}

/// An authorization token issued by the local identity provider.
pub(crate) fn authz_token(
    rsa: &Rsa<Private>,
    email: Option<&str>,
    role: &str,
    resource_name: &str,
    perimeter_id: &str,
) -> String {
    let (iat, exp) = now_and_expiry();
    sign_test_jwt(
        LOCAL_KID,
        &AuthzClaims {
            iss: LOCAL_AUTHZ_ISSUER,
            aud: AUTHZ_AUDIENCE,
            email,
            role,
            resource_name,
            perimeter_id,
            kacls_url: LOCAL_KACLS_URL,
            iat,
            exp,
        },
        rsa,
    )
}

/// Claims of a Gmail CSE authorization token, exactly as listed by Google's
/// "Authorization token for Gmail CSE" reference.
#[derive(Serialize)]
struct GmailAuthzClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    email: &'a str,
    role: &'a str,
    message_id: &'a str,
    resource_name: &'a str,
    perimeter_id: &'a str,
    spki_hash: &'a str,
    spki_hash_algorithm: &'a str,
    kacls_url: &'a str,
    iat: usize,
    exp: usize,
}

/// A Gmail authorization token (`role` is `signer` or `decrypter`) for the private key whose
/// DER `SubjectPublicKeyInfo` digest is `spki_hash` (standard base64, SHA-256).
pub(crate) fn gmail_authz_token(
    rsa: &Rsa<Private>,
    email: &str,
    role: &str,
    spki_hash: &str,
) -> String {
    let (iat, exp) = now_and_expiry();
    sign_test_jwt(
        LOCAL_KID,
        &GmailAuthzClaims {
            iss: LOCAL_GMAIL_AUTHZ_ISSUER,
            aud: AUTHZ_AUDIENCE,
            email,
            role,
            message_id: "msg-id-12345",
            resource_name: GMAIL_RESOURCE,
            perimeter_id: "",
            spki_hash,
            spki_hash_algorithm: "SHA-256",
            kacls_url: LOCAL_KACLS_URL,
            iat,
            exp,
        },
        rsa,
    )
}

/// Claims of an authorization token of the KACLS migration service, exactly as listed by
/// Google's "Authorization token for KACLS migration service" reference (no `perimeter_id`).
#[derive(Serialize)]
struct MigrationAuthzClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    role: &'a str,
    resource_name: &'a str,
    kacls_url: &'a str,
    iat: usize,
    exp: usize,
}

/// A KACLS migration authorization token: `role` is `migrator` (rewrap) or `verifier` (digest).
pub(crate) fn migration_authz_token(
    rsa: &Rsa<Private>,
    email: Option<&str>,
    role: &str,
    resource_name: &str,
) -> String {
    let (iat, exp) = now_and_expiry();
    sign_test_jwt(
        LOCAL_KID,
        &MigrationAuthzClaims {
            iss: LOCAL_MIGRATION_AUTHZ_ISSUER,
            aud: AUTHZ_AUDIENCE,
            email,
            role,
            resource_name,
            kacls_url: LOCAL_KACLS_URL,
            iat,
            exp,
        },
        rsa,
    )
}

// Default Google JWT issuer URI
pub(crate) const GOOGLE_JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default Google JWT Set URI
pub(crate) const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub(crate) async fn generate_google_jwt() -> KResult<String> {
    #[derive(Deserialize)]
    struct RefreshToken {
        pub id_token: String,
    }

    let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").map_err(|e| {
        KmsError::ServerError(format!("Failed to get TEST_GOOGLE_OAUTH_CLIENT_ID: {e}"))
    })?;
    let client_secret = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_SECRET").map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_CLIENT_SECRET: {e}"
        ))
    })?;
    let refresh_token = std::env::var("TEST_GOOGLE_OAUTH_REFRESH_TOKEN").map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_REFRESH_TOKEN: {e}"
        ))
    })?;

    assert!(!client_id.is_empty());
    assert!(!client_secret.is_empty());
    assert!(!refresh_token.is_empty());

    let res = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await?;

    let id_token = res.json::<RefreshToken>().await?.id_token;

    tracing::debug!("ID token: {id_token:?}");

    Ok(id_token)
}

pub(crate) async fn google_cse_auth(
    proxy_params: Option<&ProxyParams>,
) -> KResult<GoogleCseConfig> {
    let mut uris = google_cse::list_jwks_uri(None);

    uris.push(IdpAuthConfig::uri(
        GOOGLE_JWT_ISSUER_URI,
        Some(GOOGLE_JWKS_URI),
    ));
    let jwks_manager = Arc::new(JwksManager::new(uris, proxy_params).await?);
    let jwt_config = JwtConfig {
        jwt_issuer_uri: GOOGLE_JWT_ISSUER_URI.to_owned(),
        jwks: jwks_manager.clone(),
        jwt_audience: None,
        accept_spiffe_subject: false,
    };

    Ok(GoogleCseConfig {
        authentication: vec![jwt_config].into(),
        authorization: google_cse::jwt_authorization_config(&jwks_manager),
    })
}

/// The PKCS#1 DER of the server's `google_cse_rsa` private key (the KACLS migration key).
pub(crate) async fn google_cse_rsa_private_der<B, S>(app: &S) -> KResult<Vec<u8>>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{GOOGLE_CSE_ID}_rsa"))),
        key_format_type: Some(KeyFormatType::PKCS1),
        key_wrap_type: Some(KeyWrapType::NotWrapped),
        key_compression_type: None,
        key_wrapping_specification: None,
    };
    let response: GetResponse = post_2_1(app, get_request).await?;
    match &response.object.key_block()?.key_value {
        Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(bytes),
            ..
        }) => Ok(bytes.to_vec()),
        _ => Err(KmsError::InvalidRequest(
            "Expected ByteString key material for RSA private key.".to_owned(),
        )),
    }
}

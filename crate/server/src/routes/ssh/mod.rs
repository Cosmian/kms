mod certificate;
mod storage;
mod types;

use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::OperationEnumeration;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use self::{
    certificate::{
        CertificateTbs, build_certificate_tbs, ca_public_key, finish_certificate,
        sign_certificate_payload, validate_subject_algorithm,
    },
    storage::{
        CaConfiguration, RolePolicy, get_ca_configuration, get_role, save_ca_configuration,
        save_role,
    },
    types::{
        ConfigureCaRequest, DataWrapper, PasswordData, PasswordRequest, PutRoleRequest,
        SignRequest, SignedKeyData, parse_duration_secs, validate_principals,
    },
};
use crate::{
    core::{KMS, operations::check_role_permission},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

const PASSWORD_LENGTH: usize = 32;
const PASSWORD_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[put("/v1/ssh/config/ca")]
pub(crate) async fn configure_ca(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<ConfigureCaRequest>,
) -> KResult<HttpResponse> {
    let user = kms.get_user(&request);
    require_crypto_officer(&kms, &user).await?;
    check_role_permission(
        &kms,
        user.as_str(),
        OperationEnumeration::Sign,
        &kms.params.crypto_officer,
    )
    .await?;
    let body = body.into_inner();
    let key_uid = body.ca_key_uid.trim();
    if key_uid.is_empty() || key_uid.len() > 512 {
        return Err(KmsError::InvalidRequest(
            "ca_key_uid must contain between 1 and 512 characters".to_owned(),
        ));
    }
    let (_, public_key, _) = Box::pin(ca_public_key(&kms, key_uid, &user)).await?;
    let fingerprint = Sha256::digest(public_key.as_bytes());
    save_ca_configuration(
        &kms,
        &CaConfiguration {
            key_uid: key_uid.to_owned(),
            public_key,
            public_key_sha256: hex::encode(fingerprint),
        },
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/v1/ssh/public_key")]
pub(crate) async fn get_public_key(kms: Data<Arc<KMS>>) -> KResult<HttpResponse> {
    let configuration = get_ca_configuration(&kms).await?;
    Ok(HttpResponse::Ok()
        .content_type("text/plain; charset=utf-8")
        .body(configuration.public_key))
}

#[put("/v1/ssh/roles/{name}")]
pub(crate) async fn put_role(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    name: Path<String>,
    body: Json<PutRoleRequest>,
) -> KResult<HttpResponse> {
    let user = kms.get_user(&request);
    require_crypto_officer(&kms, &user).await?;
    let name = name.into_inner();
    validate_role_name(&name)?;
    let body = body.into_inner();
    validate_principals(&body.allowed_principals).map_err(KmsError::InvalidRequest)?;
    let default_ttl_secs = parse_duration_secs(&body.default_ttl)
        .ok_or_else(|| KmsError::InvalidRequest("default_ttl is invalid".to_owned()))?;
    let max_ttl_secs = parse_duration_secs(&body.max_ttl)
        .ok_or_else(|| KmsError::InvalidRequest("max_ttl is invalid".to_owned()))?;
    if default_ttl_secs > max_ttl_secs {
        return Err(KmsError::InvalidRequest(
            "default_ttl must not exceed max_ttl".to_owned(),
        ));
    }
    save_role(
        &kms,
        &RolePolicy {
            name,
            allowed_principals: body.allowed_principals,
            default_ttl_secs,
            max_ttl_secs,
        },
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[post("/v1/ssh/sign/{role}")]
pub(crate) async fn sign(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    role: Path<String>,
    body: Json<SignRequest>,
) -> KResult<Json<DataWrapper<SignedKeyData>>> {
    let user = kms.get_user(&request);
    check_role_permission(
        &kms,
        user.as_str(),
        OperationEnumeration::Sign,
        &kms.params.crypto_officer,
    )
    .await?;
    let role = role.into_inner();
    validate_role_name(&role)?;
    let policy = get_role(&kms, &role).await?;
    let body = body.into_inner();
    let ttl = validate_sign_request(&body, &policy)?;
    let configuration = get_ca_configuration(&kms).await?;
    let (ca_pkey, ca_public_text, is_hsm) =
        Box::pin(ca_public_key(&kms, &configuration.key_uid, &user)).await?;
    let fingerprint = hex::encode(Sha256::digest(ca_public_text.as_bytes()));
    if fingerprint != configuration.public_key_sha256 || ca_public_text != configuration.public_key
    {
        return Err(KmsError::InvalidRequest(
            "configured SSH CA key generation has changed".to_owned(),
        ));
    }
    let ca_public = ssh_key::PublicKey::from_openssh(&configuration.public_key)
        .map_err(|e| KmsError::ServerError(format!("decoding configured SSH CA key: {e}")))?;
    let subject = ssh_key::PublicKey::from_openssh(&body.public_key)
        .map_err(|e| KmsError::InvalidRequest(format!("invalid SSH public key: {e}")))?;
    validate_subject_algorithm(&subject)?;
    let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|e| {
        KmsError::ServerError(format!("system clock is before the Unix epoch: {e}"))
    })?;
    let valid_before = now.checked_add(ttl).ok_or_else(|| {
        KmsError::InvalidRequest("requested ttl overflows certificate time".to_owned())
    })?;
    let mut nonce = Zeroizing::new([0_u8; 32]);
    kms.rng.fill_public_bytes(&mut nonce[..])?;
    let mut serial_bytes = [0_u8; 8];
    kms.rng.fill_public_bytes(&mut serial_bytes)?;
    let serial = u64::from_be_bytes(serial_bytes);
    let tbs = build_certificate_tbs(&CertificateTbs {
        subject: &subject,
        ca: &ca_public,
        role: &role,
        principals: &body.valid_principals,
        valid_after: now,
        valid_before,
        serial,
        nonce: &nonce[..],
    })?;
    let (algorithm, signature) =
        sign_certificate_payload(&kms, &configuration.key_uid, &user, &tbs, &ca_pkey, is_hsm)
            .await?;
    let signed_key = finish_certificate(&tbs, &ca_public, algorithm, &signature)?;
    Ok(Json(DataWrapper {
        data: SignedKeyData {
            signed_key,
            serial_number: serial.to_string(),
        },
    }))
}

#[post("/v1/secrets/password")]
pub(crate) async fn generate_password(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    _body: Json<PasswordRequest>,
) -> KResult<Json<DataWrapper<PasswordData>>> {
    let user = kms.get_user(&request);
    kms.enforce_create_permission(&user).await?;
    let mut password = Zeroizing::new(Vec::with_capacity(PASSWORD_LENGTH));
    while password.len() < PASSWORD_LENGTH {
        let mut random = Zeroizing::new([0_u8; 64]);
        kms.rng.fill_bytes(&mut random[..])?;
        for byte in random.iter().copied().filter(|byte| *byte < 248) {
            let index = usize::from(byte % 62);
            let character = PASSWORD_ALPHABET.get(index).copied().ok_or_else(|| {
                KmsError::ServerError("password alphabet index is out of range".to_owned())
            })?;
            password.push(character);
            if password.len() == PASSWORD_LENGTH {
                break;
            }
        }
    }
    password.truncate(PASSWORD_LENGTH);
    let password = String::from_utf8(password.to_vec())
        .map_err(|e| KmsError::ServerError(format!("encoding generated password: {e}")))?;
    Ok(Json(DataWrapper {
        data: PasswordData { password },
    }))
}

async fn require_crypto_officer(kms: &KMS, user: &UserId) -> KResult<()> {
    if kms.is_crypto_officer(user).await? {
        Ok(())
    } else {
        Err(KmsError::Unauthorized(
            "an active Crypto Officer is required to manage SSH configuration".to_owned(),
        ))
    }
}

fn validate_role_name(name: &str) -> KResult<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
    {
        return Err(KmsError::InvalidRequest(
            "role name contains unsupported characters or length".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sign_request(body: &SignRequest, policy: &RolePolicy) -> KResult<u64> {
    if body.public_key.len() > 16 * 1024 {
        return Err(KmsError::InvalidRequest(
            "SSH public key exceeds the maximum length".to_owned(),
        ));
    }
    validate_principals(&body.valid_principals).map_err(KmsError::InvalidRequest)?;
    if body
        .valid_principals
        .iter()
        .any(|principal| !policy.allowed_principals.contains(principal))
    {
        return Err(KmsError::Unauthorized(
            "requested principal is not allowed by the SSH role".to_owned(),
        ));
    }
    let ttl = match &body.ttl {
        Some(ttl) => {
            let requested = parse_duration_secs(ttl)
                .ok_or_else(|| KmsError::InvalidRequest("ttl is invalid".to_owned()))?;
            if requested > policy.max_ttl_secs {
                return Err(KmsError::InvalidRequest(
                    "requested ttl exceeds the role's max_ttl".to_owned(),
                ));
            }
            requested
        }
        None => policy.default_ttl_secs,
    };
    Ok(ttl)
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)] // Test assertions are the failure signal; fallible setup still propagates.
mod tests {
    use actix_web::{App, test as actix_test};
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN, requests::create_rsa_key_pair_request,
    };
    use openssl::{pkey::PKey, rsa::Rsa};
    use ssh_key::Certificate;

    use super::*;

    fn policy() -> RolePolicy {
        RolePolicy {
            name: "developers".to_owned(),
            allowed_principals: vec!["alice".to_owned(), "db-admin".to_owned()],
            default_ttl_secs: 900,
            max_ttl_secs: 3_600,
        }
    }

    #[test]
    fn role_policy_enforces_principals_and_maximum_ttl() -> KResult<()> {
        let body = SignRequest {
            public_key: "ssh-ed25519 AAAA".to_owned(),
            valid_principals: vec!["alice".to_owned()],
            ttl: Some("30m".to_owned()),
        };
        assert_eq!(validate_sign_request(&body, &policy())?, 1_800);

        let disallowed = SignRequest {
            valid_principals: vec!["root".to_owned()],
            ..body
        };
        assert!(matches!(
            validate_sign_request(&disallowed, &policy()),
            Err(KmsError::Unauthorized(_))
        ));
        Ok(())
    }

    #[test]
    fn role_policy_defaults_ttl_and_rejects_excessive_ttl() -> KResult<()> {
        let body = SignRequest {
            public_key: "ssh-ed25519 AAAA".to_owned(),
            valid_principals: vec!["alice".to_owned()],
            ttl: None,
        };
        assert_eq!(validate_sign_request(&body, &policy())?, 900);
        let excessive = SignRequest {
            ttl: Some("2h".to_owned()),
            ..body
        };
        assert!(matches!(
            validate_sign_request(&excessive, &policy()),
            Err(KmsError::InvalidRequest(_))
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_role_names() {
        assert!(matches!(validate_role_name("developers"), Ok(())));
        assert!(matches!(
            validate_role_name("admin/other"),
            Err(KmsError::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_role_name(""),
            Err(KmsError::InvalidRequest(_))
        ));
    }

    #[actix_web::test]
    async fn public_key_endpoint_returns_plain_openssh_text() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample";
        save_ca_configuration(
            &kms,
            &CaConfiguration {
                key_uid: "test-ca".to_owned(),
                public_key: public_key.to_owned(),
                public_key_sha256: "unused-by-this-handler".to_owned(),
            },
        )
        .await?;

        let app =
            actix_test::init_service(App::new().app_data(Data::new(kms)).service(get_public_key))
                .await;
        let request = actix_test::TestRequest::get()
            .uri("/v1/ssh/public_key")
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(actix_web::http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            actix_test::read_body(response).await.as_ref(),
            public_key.as_bytes()
        );
        Ok(())
    }

    #[actix_web::test]
    async fn password_endpoint_returns_32_alphanumeric_characters() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .service(generate_password),
        )
        .await;
        let request = actix_test::TestRequest::post()
            .uri("/v1/secrets/password")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload("{}")
            .to_request();
        let response = actix_test::call_service(&app, request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&actix_test::read_body(response).await)?;
        let password = response
            .get("data")
            .and_then(|data| data.get("password"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KmsError::ServerError("password response is not a string".to_owned()))?;
        assert_eq!(password.len(), PASSWORD_LENGTH);
        assert!(
            password
                .bytes()
                .all(|byte| PASSWORD_ALPHABET.contains(&byte))
        );
        Ok(())
    }

    #[actix_web::test]
    async fn software_ca_issues_an_openssh_certificate() -> KResult<()> {
        let mut config = crate::tests::test_utils::https_clap_config();
        config.roles.crypto_officer_users = Some(vec![config.default_username.clone()]);
        let kms = crate::tests::test_utils::test_kms_with_config(config).await?;
        let user = UserId::from(kms.params.default_username.as_str());
        let key_pair = kms
            .create_key_pair(
                create_rsa_key_pair_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    Vec::<String>::new(),
                    2048,
                    false,
                    None,
                )?,
                &user,
            )
            .await?;

        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .service(configure_ca)
                .service(put_role)
                .service(sign),
        )
        .await;
        let ca_uid = key_pair.private_key_unique_identifier.to_string();
        let configure_request = actix_test::TestRequest::put()
            .uri("/v1/ssh/config/ca")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(serde_json::json!({"ca_key_uid": ca_uid}).to_string())
            .to_request();
        let response = actix_test::call_service(&app, configure_request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::NO_CONTENT);

        let role_request = actix_test::TestRequest::put()
            .uri("/v1/ssh/roles/developers")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(
                serde_json::json!({
                    "allowed_principals": ["alice"],
                    "default_ttl": "15m",
                    "max_ttl": "1h"
                })
                .to_string(),
            )
            .to_request();
        let response = actix_test::call_service(&app, role_request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::NO_CONTENT);

        let subject_private = PKey::from_rsa(Rsa::generate(2048)?)?;
        let subject_public = PKey::public_key_from_der(&subject_private.public_key_to_der()?)?;
        let subject_public = certificate::open_ssh_public_key(&subject_public)?;
        let sign_request = actix_test::TestRequest::post()
            .uri("/v1/ssh/sign/developers")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(
                serde_json::json!({
                    "public_key": subject_public,
                    "valid_principals": ["alice"],
                    "ttl": "15m"
                })
                .to_string(),
            )
            .to_request();
        let response = actix_test::call_service(&app, sign_request).await;
        assert_eq!(response.status(), actix_web::http::StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&actix_test::read_body(response).await)?;
        let signed_key = response
            .get("data")
            .and_then(|data| data.get("signed_key"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KmsError::ServerError("signed_key is not a string".to_owned()))?;
        let parsed = Certificate::from_openssh(signed_key)
            .map_err(|e| KmsError::ServerError(format!("parsing issued certificate: {e}")))?;
        let round_trip = parsed
            .to_openssh()
            .map_err(|e| KmsError::ServerError(format!("serializing issued certificate: {e}")))?;
        assert_eq!(round_trip, signed_key);
        Ok(())
    }
}

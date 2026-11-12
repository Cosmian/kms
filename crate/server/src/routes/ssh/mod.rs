pub(crate) mod certificate;
mod storage;
mod types;

use std::{collections::HashSet, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse, get, post, put,
    web::{Data, Json, Path},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    KmipOperation, kmip_types::OperationEnumeration,
};
use time::OffsetDateTime;
use zeroize::Zeroizing;

pub(crate) use self::storage::SSH_RECORD_OWNER;
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
        SignRequest, SignedKeyData, validate_allowed_users, validate_principals,
    },
};
use crate::{
    core::{KMS, operations::check_role_permission},
    error::KmsError,
    middlewares::{AuthMethod, UserId, reject_reserved_service_identity},
    result::KResult,
    routes::parse_duration_secs,
};

const PASSWORD_LENGTH: usize = 32;
const PASSWORD_ALPHABET: &[u8; 62] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Configure the CA key. The caller must be able to grant the key (its owner, or an HSM admin
/// for an HSM key): the key's `Sign` right is then delegated to the internal SSH authority,
/// which signs the certificates of every role user without giving them raw `Sign` on the key.
#[put("/v1/ssh/config/ca")]
pub(crate) async fn configure_ca(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    body: Json<ConfigureCaRequest>,
) -> KResult<HttpResponse> {
    let user = authenticated_user(&kms, &request)?;
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
    // Same rule as GrantAccess: only who may grant the key may delegate it.
    if !kms.database.is_object_owned_by(key_uid, &user).await? {
        return Err(KmsError::Unauthorized(
            "the caller cannot delegate the selected SSH CA key".to_owned(),
        ));
    }
    let (_, public_key, _) = Box::pin(ca_public_key(&kms, key_uid, &user)).await?;
    let authority = UserId::from(SSH_RECORD_OWNER);
    kms.database
        .grant_operations(key_uid, &authority, HashSet::from([KmipOperation::Sign]))
        .await?;
    let (_, authority_view, _) = Box::pin(ca_public_key(&kms, key_uid, &authority)).await?;
    if authority_view != public_key {
        return Err(KmsError::ServerError(
            "the SSH signing authority resolves a different CA key".to_owned(),
        ));
    }
    let public_key_sha256 = hex::encode(openssl::sha::sha256(public_key.as_bytes()));
    save_ca_configuration(
        &kms,
        &CaConfiguration {
            key_uid: key_uid.to_owned(),
            public_key,
            public_key_sha256,
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
    let user = authenticated_user(&kms, &request)?;
    require_crypto_officer(&kms, &user).await?;
    let name = name.into_inner();
    validate_role_name(&name)?;
    let body = body.into_inner();
    validate_principals(&body.allowed_principals).map_err(KmsError::InvalidRequest)?;
    validate_allowed_users(&body.allowed_users).map_err(KmsError::InvalidRequest)?;
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
            allowed_users: body.allowed_users,
            default_ttl_secs,
            max_ttl_secs,
        },
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// Issue a certificate for an authorized role user. The CA key signs under the internal SSH
/// authority: the caller needs no right on the CA key, so the role limits cannot be bypassed
/// with a raw KMIP `Sign`.
#[post("/v1/ssh/sign/{role}")]
pub(crate) async fn sign(
    request: HttpRequest,
    kms: Data<Arc<KMS>>,
    role: Path<String>,
    body: Json<SignRequest>,
) -> KResult<Json<DataWrapper<SignedKeyData>>> {
    let user = authenticated_user(&kms, &request)?;
    check_role_permission(
        &kms,
        user.as_str(),
        OperationEnumeration::Sign,
        &kms.params.crypto_officer,
    )
    .await?;
    let role = role.into_inner();
    validate_role_name(&role)?;
    let (policy, configuration) = tokio::join!(get_role(&kms, &role), get_ca_configuration(&kms));
    // The role is authorized before any CA state is disclosed.
    let policy = authorize_role(&kms, &user, &role, policy?).await?;
    let body = body.into_inner();
    let ttl = validate_sign_request(&body, &policy)?;
    let configuration = configuration?;
    let authority = UserId::from(SSH_RECORD_OWNER);
    let (ca_pkey, ca_public_text, is_hsm) =
        Box::pin(ca_public_key(&kms, &configuration.key_uid, &authority)).await?;
    let fingerprint = hex::encode(openssl::sha::sha256(ca_public_text.as_bytes()));
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
    let key_id = certificate_key_id(&user, &role, serial);
    let tbs = build_certificate_tbs(&CertificateTbs {
        subject: &subject,
        ca: &ca_public,
        key_id: &key_id,
        principals: &body.valid_principals,
        valid_after: now,
        valid_before,
        serial,
        nonce: &nonce[..],
    })?;
    let (algorithm, signature) = sign_certificate_payload(
        &kms,
        &configuration.key_uid,
        &authority,
        &tbs,
        &ca_pkey,
        is_hsm,
    )
    .await?;
    let signed_key = finish_certificate(&tbs, &ca_public, algorithm, &signature)?;
    // error! like the other audit events, so that it survives any RUST_LOG filter.
    tracing::error!(
        target: "audit",
        user = ?user.as_str(),
        role = %role,
        serial,
        principals = ?body.valid_principals,
        ttl_secs = ttl,
        valid_after = now,
        valid_before,
        "SSH_CERTIFICATE_ISSUED: SSH certificate signed by the KMS CA",
    );
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
    let user = authenticated_user(&kms, &request)?;
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
    // Move the bytes into the zeroized `String` instead of copying them.
    let password = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *password))
            .map_err(|e| KmsError::ServerError(format!("encoding generated password: {e}")))?,
    );
    Ok(Json(DataWrapper {
        data: PasswordData { password },
    }))
}

/// The caller's identity; never anonymous while authentication is configured, never a
/// reserved service identity.
fn authenticated_user(kms: &KMS, request: &HttpRequest) -> KResult<UserId> {
    require_authenticated_caller(kms, request)?;
    let user = kms.get_user(request);
    reject_reserved_service_identity(&user)?;
    Ok(user)
}

/// Reject a request that carries no real identity while authentication is configured.
///
/// The default scope only enforces native authentication (JWT, mTLS, API token, Auth Verifier):
/// when `X-Vault-Token` is the sole configured method its extractor is optional, so a request
/// without a token would otherwise run as `default_username`.
fn require_authenticated_caller(kms: &KMS, request: &HttpRequest) -> KResult<()> {
    let vault_token_auth =
        kms.params.vault.api_enabled && kms.params.vault.auth_verifier_url.is_some();
    let anonymous = matches!(
        kms.get_auth_method(request),
        None | Some(AuthMethod::DefaultUser)
    );
    if vault_token_auth && anonymous && !kms.params.force_default_username {
        return Err(KmsError::Unauthorized(
            "authentication is required for this endpoint".to_owned(),
        ));
    }
    Ok(())
}

/// A role can be used by the users it lists and by active Crypto Officers, which manage roles.
/// A missing role and a denied role get the same answer, so roles cannot be enumerated.
async fn authorize_role(
    kms: &KMS,
    user: &UserId,
    role: &str,
    policy: Option<RolePolicy>,
) -> KResult<RolePolicy> {
    if let Some(policy) = policy
        && (policy
            .allowed_users
            .iter()
            .any(|allowed| allowed == user.as_str())
            || kms.is_crypto_officer(user).await?)
    {
        return Ok(policy);
    }
    Err(KmsError::Unauthorized(format!(
        "user is not allowed to use the SSH role '{role}'"
    )))
}

/// Certificate Key ID, logged by sshd at login: who requested it, under which role, and its
/// serial. The user name is escaped so that it cannot inject characters into sshd logs.
fn certificate_key_id(user: &UserId, role: &str, serial: u64) -> String {
    format!("{}/{role}/{serial}", user.as_str().escape_default())
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
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use actix_web::{
        App, HttpMessage,
        body::{BoxBody, MessageBody},
        dev::{ServiceRequest, ServiceResponse},
        http::StatusCode,
        middleware::{Next, from_fn},
        test as actix_test,
    };
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            extra::tagging::VENDOR_ID_COSMIAN,
            kmip_operations::Sign,
            kmip_types::{RecommendedCurve, UniqueIdentifier},
            requests::create_ec_key_pair_request,
        },
    };
    use openssl::{
        ec::{EcGroup, EcKey},
        nid::Nid,
        pkey::PKey,
    };
    use ssh_key::Certificate;

    use super::*;
    use crate::middlewares::AuthenticatedUser;

    const TEST_USER_HEADER: &str = "x-test-user";

    fn policy() -> RolePolicy {
        RolePolicy {
            name: "developers".to_owned(),
            allowed_principals: vec!["alice".to_owned(), "db-admin".to_owned()],
            allowed_users: vec!["alice".to_owned()],
            default_ttl_secs: 900,
            max_ttl_secs: 3_600,
        }
    }

    /// Stand-in for the production Vault-token extractor: `x-test-user` becomes the same
    /// `AuthenticatedUser` extension (`AuthMethod::SpireToken`) the runtime inserts; without
    /// the header the request stays anonymous.
    async fn inject_test_user<B: MessageBody + 'static>(
        req: ServiceRequest,
        next: Next<B>,
    ) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
        if let Some(user) = req
            .headers()
            .get(TEST_USER_HEADER)
            .and_then(|value| value.to_str().ok())
        {
            req.extensions_mut().insert(AuthenticatedUser {
                username: UserId::from(user),
                auth_method: AuthMethod::SpireToken,
            });
        }
        next.call(req)
            .await
            .map(ServiceResponse::map_into_boxed_body)
    }

    /// A JSON request authenticated as `user` by [`inject_test_user`].
    fn json_request(
        method: actix_test::TestRequest,
        uri: &str,
        user: &str,
        body: &serde_json::Value,
    ) -> actix_test::TestRequest {
        method
            .uri(uri)
            .insert_header((TEST_USER_HEADER, user))
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload(body.to_string())
    }

    fn sign_body() -> serde_json::Value {
        serde_json::json!({"public_key": "ssh-ed25519 AAAA", "valid_principals": ["alice"]})
    }

    fn ec_subject_public_key() -> KResult<String> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let subject = PKey::from_ec_key(EcKey::generate(&group)?)?;
        certificate::open_ssh_public_key(&PKey::public_key_from_der(&subject.public_key_to_der()?)?)
    }

    async fn kms_with_officers(officers: &[&str]) -> KResult<Arc<KMS>> {
        let mut config = crate::tests::test_utils::https_clap_config();
        config.roles.crypto_officer_users = Some(
            officers
                .iter()
                .map(|officer| (*officer).to_owned())
                .collect(),
        );
        crate::tests::test_utils::test_kms_with_config(config).await
    }

    async fn create_ec_ca(kms: &KMS, owner: &str) -> KResult<String> {
        Ok(kms
            .create_key_pair(
                create_ec_key_pair_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    Vec::<String>::new(),
                    RecommendedCurve::P256,
                    false,
                    None,
                )?,
                &UserId::from(owner),
            )
            .await?
            .private_key_unique_identifier
            .to_string())
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
    fn sign_ttl_accepts_bare_positive_seconds() -> KResult<()> {
        let body = |ttl: &str| SignRequest {
            public_key: "ssh-ed25519 AAAA".to_owned(),
            valid_principals: vec!["alice".to_owned()],
            ttl: Some(ttl.to_owned()),
        };
        assert_eq!(validate_sign_request(&body("45"), &policy())?, 45);
        for rejected in ["0", "-5", "0s", "1é"] {
            assert!(
                matches!(
                    validate_sign_request(&body(rejected), &policy()),
                    Err(KmsError::InvalidRequest(_))
                ),
                "{rejected}"
            );
        }
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

    #[test]
    fn certificate_key_id_names_the_escaped_requester_role_and_serial() {
        assert_eq!(
            certificate_key_id(&UserId::from("alice@example.com"), "developers", 42),
            "alice@example.com/developers/42"
        );
        assert_eq!(
            certificate_key_id(&UserId::from("eve\nforged"), "developers", 7),
            "eve\\nforged/developers/7"
        );
    }

    #[test]
    fn stored_role_record_requires_allowed_users() {
        let record = r#"{"name":"old","allowed_principals":["alice"],"default_ttl_secs":900,"max_ttl_secs":3600}"#;
        let error = serde_json::from_str::<RolePolicy>(record)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(error.contains("missing field `allowed_users`"), "{error}");
    }

    #[actix_web::test]
    async fn reserved_internal_identity_is_refused_as_a_caller() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let request = actix_test::TestRequest::default().to_http_request();
        request.extensions_mut().insert(AuthenticatedUser {
            username: UserId::from(SSH_RECORD_OWNER),
            auth_method: AuthMethod::SpireToken,
        });
        assert!(matches!(
            authenticated_user(&kms, &request),
            Err(KmsError::Unauthorized(_))
        ));
        Ok(())
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
        assert_eq!(response.status(), StatusCode::OK);
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
        assert_eq!(response.status(), StatusCode::OK);
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
    async fn password_endpoint_accepts_only_the_empty_object() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .service(generate_password),
        )
        .await;
        for (body, expected) in [
            ("{}", StatusCode::OK),
            (r#"{"length":64}"#, StatusCode::BAD_REQUEST),
            ("null", StatusCode::BAD_REQUEST),
            ("[]", StatusCode::BAD_REQUEST),
        ] {
            let request = actix_test::TestRequest::post()
                .uri("/v1/secrets/password")
                .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
                .set_payload(body)
                .to_request();
            assert_eq!(
                actix_test::call_service(&app, request).await.status(),
                expected,
                "{body}"
            );
        }
        Ok(())
    }

    /// A role user without any right on the CA key gets a certificate naming them, while a raw
    /// KMIP `Sign` with the CA key stays denied to them.
    #[actix_web::test]
    async fn role_user_signs_without_a_raw_sign_right_on_the_ca_key() -> KResult<()> {
        let kms = kms_with_officers(&["admin"]).await?;
        let ca_uid = create_ec_ca(&kms, "admin").await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms.clone()))
                .wrap(from_fn(inject_test_user))
                .service(configure_ca)
                .service(put_role)
                .service(sign),
        )
        .await;
        let response = actix_test::call_service(
            &app,
            json_request(
                actix_test::TestRequest::put(),
                "/v1/ssh/config/ca",
                "admin",
                &serde_json::json!({"ca_key_uid": ca_uid}),
            )
            .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = actix_test::call_service(
            &app,
            json_request(
                actix_test::TestRequest::put(),
                "/v1/ssh/roles/developers",
                "admin",
                &serde_json::json!({
                    "allowed_principals": ["alice"],
                    "allowed_users": ["alice"],
                    "default_ttl": "15m",
                    "max_ttl": "1h"
                }),
            )
            .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = actix_test::call_service(
            &app,
            json_request(
                actix_test::TestRequest::post(),
                "/v1/ssh/sign/developers",
                "alice",
                &serde_json::json!({
                    "public_key": ec_subject_public_key()?,
                    "valid_principals": ["alice"],
                    "ttl": "900"
                }),
            )
            .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value =
            serde_json::from_slice(&actix_test::read_body(response).await)?;
        let data = response
            .get("data")
            .ok_or_else(|| KmsError::ServerError("no data in the response".to_owned()))?;
        let signed_key = data
            .get("signed_key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KmsError::ServerError("signed_key is not a string".to_owned()))?;
        let serial = data
            .get("serial_number")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| KmsError::ServerError("serial_number is not a string".to_owned()))?;
        let certificate = Certificate::from_openssh(signed_key)
            .map_err(|e| KmsError::ServerError(format!("parsing issued certificate: {e}")))?;
        assert_eq!(certificate.serial().to_string(), serial);
        assert_eq!(certificate.key_id(), format!("alice/developers/{serial}"));
        assert_eq!(
            certificate
                .valid_before()
                .checked_sub(certificate.valid_after()),
            Some(900)
        );
        assert_eq!(
            certificate
                .to_openssh()
                .map_err(|e| KmsError::ServerError(format!("serializing certificate: {e}")))?,
            signed_key
        );

        let raw_sign = kms
            .sign(
                Sign {
                    unique_identifier: Some(UniqueIdentifier::TextString(ca_uid)),
                    data: Some(Zeroizing::new(b"forged certificate".to_vec())),
                    ..Default::default()
                },
                &UserId::from("alice"),
            )
            .await;
        assert!(
            matches!(
                raw_sign,
                Err(KmsError::Kmip21Error(
                    ErrorReason::Item_Not_Found | ErrorReason::Object_Not_Found,
                    _
                ) | KmsError::Unauthorized(_))
            ),
            "a role user must not sign with the CA key directly"
        );
        Ok(())
    }

    /// A Crypto Officer cannot delegate a key it does not own to the internal SSH authority.
    #[actix_web::test]
    async fn ca_configuration_requires_the_right_to_delegate_the_key() -> KResult<()> {
        let kms = kms_with_officers(&["admin", "carol"]).await?;
        let ca_uid = create_ec_ca(&kms, "admin").await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms.clone()))
                .wrap(from_fn(inject_test_user))
                .service(configure_ca),
        )
        .await;
        let response = actix_test::call_service(
            &app,
            json_request(
                actix_test::TestRequest::put(),
                "/v1/ssh/config/ca",
                "carol",
                &serde_json::json!({"ca_key_uid": ca_uid}),
            )
            .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            kms.database
                .list_user_operations_on_object(&ca_uid, &UserId::from(SSH_RECORD_OWNER), true)
                .await?
                .is_empty(),
            "no right may be delegated on a key the caller does not own"
        );
        Ok(())
    }

    #[actix_web::test]
    async fn role_use_is_limited_to_listed_users() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        save_role(&kms, &policy()).await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(sign),
        )
        .await;
        for (user, expected) in [
            // Authorized: past the role check, stopped by the missing CA configuration.
            ("alice", StatusCode::UNPROCESSABLE_ENTITY),
            ("bob", StatusCode::UNAUTHORIZED),
        ] {
            let request = json_request(
                actix_test::TestRequest::post(),
                "/v1/ssh/sign/developers",
                user,
                &sign_body(),
            )
            .to_request();
            assert_eq!(
                actix_test::call_service(&app, request).await.status(),
                expected,
                "{user}"
            );
        }
        Ok(())
    }

    /// A missing role answers like a denied one, and neither discloses the CA state.
    #[actix_web::test]
    async fn missing_and_denied_roles_get_the_same_answer() -> KResult<()> {
        let kms = crate::tests::test_utils::test_kms().await?;
        save_role(&kms, &policy()).await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(sign),
        )
        .await;
        for role in ["developers", "ghost"] {
            let response = actix_test::call_service(
                &app,
                json_request(
                    actix_test::TestRequest::post(),
                    &format!("/v1/ssh/sign/{role}"),
                    "bob",
                    &sign_body(),
                )
                .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{role}");
            let body = String::from_utf8(actix_test::read_body(response).await.to_vec())
                .map_err(|e| KmsError::ServerError(e.to_string()))?;
            assert!(
                body.contains(&format!("user is not allowed to use the SSH role '{role}'")),
                "{role}: {body}"
            );
        }
        Ok(())
    }

    #[actix_web::test]
    async fn crypto_officer_can_use_a_role_that_does_not_list_them() -> KResult<()> {
        let kms = kms_with_officers(&["carol"]).await?;
        save_role(&kms, &policy()).await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(sign),
        )
        .await;
        let request = json_request(
            actix_test::TestRequest::post(),
            "/v1/ssh/sign/developers",
            "carol",
            &sign_body(),
        )
        .to_request();
        // Past the role check, stopped by the missing CA configuration.
        assert_eq!(
            actix_test::call_service(&app, request).await.status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        Ok(())
    }

    #[actix_web::test]
    async fn put_role_persists_allowed_users_and_rejects_wildcards() -> KResult<()> {
        let kms = kms_with_officers(&["admin"]).await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms.clone()))
                .wrap(from_fn(inject_test_user))
                .service(put_role),
        )
        .await;
        for (users, expected) in [
            (serde_json::json!(["alice", "bob"]), StatusCode::NO_CONTENT),
            (serde_json::json!(["*"]), StatusCode::UNPROCESSABLE_ENTITY),
            (
                serde_json::json!(["bob", "bob"]),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let request = json_request(
                actix_test::TestRequest::put(),
                "/v1/ssh/roles/developers",
                "admin",
                &serde_json::json!({
                    "allowed_principals": ["alice"],
                    "allowed_users": users,
                    "default_ttl": "15m",
                    "max_ttl": "1h"
                }),
            )
            .to_request();
            assert_eq!(
                actix_test::call_service(&app, request).await.status(),
                expected
            );
        }
        let stored = get_role(&kms, "developers")
            .await?
            .ok_or_else(|| KmsError::ServerError("role was not stored".to_owned()))?;
        assert_eq!(
            stored.allowed_users,
            vec!["alice".to_owned(), "bob".to_owned()]
        );
        Ok(())
    }

    async fn vault_token_kms() -> KResult<Arc<KMS>> {
        let mut config = crate::tests::test_utils::https_clap_config();
        config.vault.api_enabled = true;
        config.vault.auth_verifier_url = Some("http://127.0.0.1:9".to_owned());
        crate::tests::test_utils::test_kms_with_config(config).await
    }

    #[actix_web::test]
    async fn vault_token_deployment_rejects_anonymous_callers() -> KResult<()> {
        let kms = vault_token_kms().await?;
        let anonymous = actix_test::TestRequest::default().to_http_request();
        assert!(matches!(
            require_authenticated_caller(&kms, &anonymous),
            Err(KmsError::Unauthorized(_))
        ));
        let default_user = actix_test::TestRequest::default().to_http_request();
        default_user.extensions_mut().insert(AuthenticatedUser {
            username: UserId::from(kms.params.default_username.as_str()),
            auth_method: AuthMethod::DefaultUser,
        });
        assert!(matches!(
            require_authenticated_caller(&kms, &default_user),
            Err(KmsError::Unauthorized(_))
        ));
        let authenticated = actix_test::TestRequest::default().to_http_request();
        authenticated.extensions_mut().insert(AuthenticatedUser {
            username: UserId::from("rotator"),
            auth_method: AuthMethod::SpireToken,
        });
        assert!(matches!(
            require_authenticated_caller(&kms, &authenticated),
            Ok(())
        ));
        Ok(())
    }

    #[actix_web::test]
    async fn password_endpoint_requires_a_token_when_vault_auth_is_configured() -> KResult<()> {
        let kms = vault_token_kms().await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(generate_password),
        )
        .await;
        let anonymous = actix_test::TestRequest::post()
            .uri("/v1/secrets/password")
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .set_payload("{}")
            .to_request();
        assert_eq!(
            actix_test::call_service(&app, anonymous).await.status(),
            StatusCode::UNAUTHORIZED
        );
        let authenticated = json_request(
            actix_test::TestRequest::post(),
            "/v1/secrets/password",
            "rotator",
            &serde_json::json!({}),
        )
        .to_request();
        assert_eq!(
            actix_test::call_service(&app, authenticated).await.status(),
            StatusCode::OK
        );
        Ok(())
    }

    #[actix_web::test]
    async fn password_endpoint_rejects_users_without_create_access_when_officers_are_configured()
    -> KResult<()> {
        let kms = kms_with_officers(&["carol"]).await?;
        let app = actix_test::init_service(
            App::new()
                .app_data(Data::new(kms))
                .wrap(from_fn(inject_test_user))
                .service(generate_password),
        )
        .await;
        for (user, expected) in [
            ("mallory", StatusCode::UNAUTHORIZED),
            ("carol", StatusCode::OK),
        ] {
            let request = json_request(
                actix_test::TestRequest::post(),
                "/v1/secrets/password",
                user,
                &serde_json::json!({}),
            )
            .to_request();
            assert_eq!(
                actix_test::call_service(&app, request).await.status(),
                expected,
                "{user}"
            );
        }
        Ok(())
    }
}

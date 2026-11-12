//! SSH certificates signed by a non-extractable, HSM-resident CA key (issue #864).
//!
//! The CA private key never leaves the HSM: the certificate payload is signed by the HSM oracle
//! under the internal SSH authority, and the KMS verifies the signature against the published
//! CA public key before returning it. Role users hold no right on the CA key.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use actix_web::{
    App, HttpMessage,
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::{StatusCode, header::CONTENT_TYPE},
    middleware::{Next, from_fn},
    test as actix_test,
    web::Data,
};
use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_operations::{Operation, Sign},
        kmip_types::{RecommendedCurve, UniqueIdentifier},
        requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
    },
};
use cosmian_logger::info;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use ssh_key::{Certificate, PublicKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    error::KmsError,
    middlewares::{AuthMethod, AuthenticatedUser, UserId},
    result::KResult,
    routes::ssh::{configure_ca, get_public_key, put_role, sign},
    tests::{
        hsm::{EMPTY_TAGS, hsm_clap_config, send_message, sshd::Sshd},
        test_utils::{get_tmp_sqlite_path, test_kms_with_config},
    },
};

/// HSM admin and Crypto Officer: configures the CA and the roles.
const ADMIN: &str = "owner.client@acme.com";
/// Role user: no right on the HSM CA key.
const ROLE_USER: &str = "user.client@acme.com";
const TEST_USER_HEADER: &str = "x-test-user";

/// Lifetime of the certificate checked against a real sshd: long enough for one login attempt,
/// short enough to wait for its expiry.
const SSHD_CERT_TTL_SECS: u64 = 10;

#[derive(Clone, Copy)]
enum CaKind {
    Rsa,
    EcP256,
}

async fn create_hsm_ca(
    kms: &Arc<KMS>,
    slot: usize,
    kind: CaKind,
    sensitive: bool,
) -> KResult<String> {
    let sk_uid = as_hsm_uid!(slot, Uuid::new_v4());
    let operation = match kind {
        CaKind::Rsa => Operation::CreateKeyPair(Box::new(create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(sk_uid.clone())),
            EMPTY_TAGS,
            3072,
            sensitive,
            None,
        )?)),
        CaKind::EcP256 => Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(sk_uid.clone())),
            EMPTY_TAGS,
            RecommendedCurve::P256,
            sensitive,
            None,
        )?)),
    };
    let response = send_message(kms.clone(), ADMIN, vec![operation]).await?;
    let Operation::CreateKeyPairResponse(_) = &response[0] else {
        return Err(KmsError::ServerError(
            "invalid CreateKeyPair response".to_owned(),
        ));
    };
    Ok(sk_uid)
}

/// Authenticates `x-test-user` with the extension the runtime Vault-token extractor inserts;
/// requests without it run as the default user, [`ADMIN`].
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

fn json_request(
    method: actix_test::TestRequest,
    uri: &str,
    body: &serde_json::Value,
) -> actix_test::TestRequest {
    method
        .uri(uri)
        .insert_header((CONTENT_TYPE, "application/json"))
        .set_payload(body.to_string())
}

/// The issued certificate and serial of a successful sign response.
async fn signed_certificate(response: ServiceResponse) -> KResult<(String, String)> {
    assert_eq!(response.status(), StatusCode::OK);
    let response: serde_json::Value =
        serde_json::from_slice(&actix_test::read_body(response).await)?;
    let field = |name: &str| {
        response
            .get("data")
            .and_then(|data| data.get(name))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| KmsError::ServerError(format!("{name} is not a string")))
    };
    Ok((field("signed_key")?, field("serial_number")?))
}

async fn issue_and_check(kms: &Arc<KMS>, slot: usize, kind: CaKind) -> KResult<()> {
    let ca_uid = create_hsm_ca(kms, slot, kind, true).await?;
    let app = actix_test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .wrap(from_fn(inject_test_user))
            .service(configure_ca)
            .service(get_public_key)
            .service(put_role)
            .service(sign),
    )
    .await;

    let response = actix_test::call_service(
        &app,
        json_request(
            actix_test::TestRequest::put(),
            "/v1/ssh/config/ca",
            &serde_json::json!({ "ca_key_uid": ca_uid }),
        )
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = actix_test::call_service(
        &app,
        json_request(
            actix_test::TestRequest::put(),
            "/v1/ssh/roles/hsm-users",
            &serde_json::json!({
                "allowed_principals": ["alice"],
                "allowed_users": [ROLE_USER],
                "default_ttl": "15m",
                "max_ttl": "1h"
            }),
        )
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let public_key_response = actix_test::call_service(
        &app,
        actix_test::TestRequest::get()
            .uri("/v1/ssh/public_key")
            .to_request(),
    )
    .await;
    let ca_public_text =
        String::from_utf8(actix_test::read_body(public_key_response).await.to_vec())
            .map_err(|e| KmsError::ServerError(format!("CA public key is not UTF-8: {e}")))?;
    let ca_public = PublicKey::from_openssh(&ca_public_text)
        .map_err(|e| KmsError::ServerError(format!("parsing the CA public key: {e}")))?;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let subject = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let subject_public = crate::routes::ssh::certificate::open_ssh_public_key(
        &PKey::public_key_from_der(&subject.public_key_to_der()?)?,
    )?;
    let response = actix_test::call_service(
        &app,
        json_request(
            actix_test::TestRequest::post(),
            "/v1/ssh/sign/hsm-users",
            &serde_json::json!({
                "public_key": subject_public,
                "valid_principals": ["alice"],
                "ttl": "15m"
            }),
        )
        .insert_header((TEST_USER_HEADER, ROLE_USER))
        .to_request(),
    )
    .await;
    let (signed_key, serial) = signed_certificate(response).await?;
    let certificate = Certificate::from_openssh(&signed_key)
        .map_err(|e| KmsError::ServerError(format!("parsing the issued certificate: {e}")))?;
    assert_eq!(
        certificate.signature_key(),
        ca_public.key_data(),
        "the certificate must be signed by the published HSM CA key"
    );
    assert_eq!(certificate.valid_principals(), ["alice"]);
    assert_eq!(
        certificate.key_id(),
        format!("{ROLE_USER}/hsm-users/{serial}")
    );

    // The role user cannot use the HSM CA key outside the role limits.
    let raw_sign = kms
        .sign(
            Sign {
                unique_identifier: Some(UniqueIdentifier::TextString(ca_uid)),
                data: Some(Zeroizing::new(b"forged certificate".to_vec())),
                ..Default::default()
            },
            &UserId::from(ROLE_USER),
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
        "a role user must not sign with the HSM CA key directly"
    );

    // Host lifecycle: a real sshd that trusts only the HSM CA public key accepts the short-lived
    // certificate before it expires and rejects it afterwards.
    let sshd = Sshd::start(&ca_public_text)?;
    let response = actix_test::call_service(
        &app,
        json_request(
            actix_test::TestRequest::put(),
            "/v1/ssh/roles/hsm-sshd",
            &serde_json::json!({
                "allowed_principals": [sshd.login],
                "allowed_users": [ROLE_USER],
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
            "/v1/ssh/sign/hsm-sshd",
            &serde_json::json!({
                "public_key": sshd.user_public_key()?,
                "valid_principals": [sshd.login],
                "ttl": SSHD_CERT_TTL_SECS.to_string()
            }),
        )
        .insert_header((TEST_USER_HEADER, ROLE_USER))
        .to_request(),
    )
    .await;
    let issued_at = Instant::now();
    let (signed_key, _) = signed_certificate(response).await?;
    assert!(
        sshd.accepts(&signed_key)?,
        "sshd rejected a valid HSM-signed certificate: {}",
        sshd.log()
    );
    // Real time must pass: sshd checks the certificate against its own clock.
    let remaining = Duration::from_secs(SSHD_CERT_TTL_SECS + 2).saturating_sub(issued_at.elapsed());
    tokio::time::sleep(remaining).await;
    assert!(
        !sshd.accepts(&signed_key)?,
        "sshd accepted the HSM-signed certificate after expiry"
    );
    Ok(())
}

/// An extractable HSM key cannot become the SSH CA.
async fn extractable_hsm_ca_is_rejected(kms: &Arc<KMS>, slot: usize) -> KResult<()> {
    let ca_uid = create_hsm_ca(kms, slot, CaKind::EcP256, false).await?;
    let app = actix_test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .service(configure_ca),
    )
    .await;
    let response = actix_test::call_service(
        &app,
        json_request(
            actix_test::TestRequest::put(),
            "/v1/ssh/config/ca",
            &serde_json::json!({ "ca_key_uid": ca_uid }),
        )
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = String::from_utf8(actix_test::read_body(response).await.to_vec())
        .map_err(|e| KmsError::ServerError(format!("error body is not UTF-8: {e}")))?;
    assert!(body.contains("is extractable"), "{body}");
    Ok(())
}

/// An RSA and an ECDSA P-256 sensitive CA key generated inside the HSM sign OpenSSH
/// certificates whose signing key is the published CA public key; an extractable one is refused.
pub(super) async fn test_hsm_ssh_ca() -> KResult<()> {
    let mut clap_config = hsm_clap_config(ADMIN, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    clap_config.default_username = ADMIN.to_owned();
    clap_config.roles.crypto_officer_users = Some(vec![ADMIN.to_owned()]);
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    info!("HSM SSH CA: extractable key rejected");
    Box::pin(extractable_hsm_ca_is_rejected(&kms, slot)).await?;
    info!("HSM SSH CA: ECDSA P-256");
    Box::pin(issue_and_check(&kms, slot, CaKind::EcP256)).await?;
    info!("HSM SSH CA: RSA-3072");
    Box::pin(issue_and_check(&kms, slot, CaKind::Rsa)).await?;
    Ok(())
}

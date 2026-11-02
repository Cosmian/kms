//! SSH certificates signed by a non-extractable, HSM-resident CA key (issue #864).
//!
//! The CA private key never leaves the HSM: the certificate payload is signed by the HSM oracle,
//! and the KMS verifies the signature against the published CA public key before returning it.
use std::sync::Arc;

use actix_web::{
    App,
    http::{StatusCode, header::CONTENT_TYPE},
    test as actix_test,
    web::Data,
};
use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_operations::Operation,
    kmip_types::{RecommendedCurve, UniqueIdentifier},
    requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
};
use cosmian_logger::info;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use ssh_key::{Certificate, PublicKey};
use uuid::Uuid;

use crate::{
    core::KMS,
    error::KmsError,
    result::KResult,
    routes::ssh::{configure_ca, get_public_key, put_role, sign},
    tests::{
        hsm::{EMPTY_TAGS, hsm_clap_config, send_message},
        test_utils::{get_tmp_sqlite_path, test_kms_with_config},
    },
};

const ADMIN: &str = "owner.client@acme.com";

#[derive(Clone, Copy)]
enum CaKind {
    Rsa,
    EcP256,
}

async fn create_hsm_ca(kms: &Arc<KMS>, slot: usize, kind: CaKind) -> KResult<String> {
    let sk_uid = as_hsm_uid!(slot, Uuid::new_v4());
    let operation = match kind {
        CaKind::Rsa => Operation::CreateKeyPair(Box::new(create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(sk_uid.clone())),
            EMPTY_TAGS,
            3072,
            false,
            None,
        )?)),
        CaKind::EcP256 => Operation::CreateKeyPair(Box::new(create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(sk_uid.clone())),
            EMPTY_TAGS,
            RecommendedCurve::P256,
            false,
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

async fn issue_and_check(kms: &Arc<KMS>, slot: usize, kind: CaKind) -> KResult<()> {
    let ca_uid = create_hsm_ca(kms, slot, kind).await?;
    let app = actix_test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
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
        .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response: serde_json::Value =
        serde_json::from_slice(&actix_test::read_body(response).await)?;
    let signed_key = response
        .get("data")
        .and_then(|data| data.get("signed_key"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| KmsError::ServerError("signed_key is not a string".to_owned()))?;
    let certificate = Certificate::from_openssh(signed_key)
        .map_err(|e| KmsError::ServerError(format!("parsing the issued certificate: {e}")))?;
    assert_eq!(
        certificate.signature_key(),
        ca_public.key_data(),
        "the certificate must be signed by the published HSM CA key"
    );
    assert_eq!(certificate.valid_principals(), ["alice"]);
    Ok(())
}

/// An RSA and an ECDSA P-256 CA key generated inside the HSM sign OpenSSH certificates whose
/// signing key is the published CA public key.
pub(super) async fn test_hsm_ssh_ca() -> KResult<()> {
    let mut clap_config = hsm_clap_config(ADMIN, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    clap_config.default_username = ADMIN.to_owned();
    clap_config.roles.crypto_officer_users = Some(vec![ADMIN.to_owned()]);
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    info!("HSM SSH CA: ECDSA P-256");
    Box::pin(issue_and_check(&kms, slot, CaKind::EcP256)).await?;
    info!("HSM SSH CA: RSA-3072");
    Box::pin(issue_and_check(&kms, slot, CaKind::Rsa)).await?;
    Ok(())
}

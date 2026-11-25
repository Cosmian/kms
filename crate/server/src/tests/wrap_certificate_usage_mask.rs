//! Wrapping with a Certificate enforces the `WrapKey` usage mask of the certificate, or of its
//! linked public key when the certificate carries no mask (issue #1457).

use std::sync::Arc;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_data_structures::KeyWrappingSpecification,
        kmip_types::{
            CryptographicAlgorithm, EncodingOption, EncryptionKeyInformation, LinkType,
            LinkedObjectIdentifier, UniqueIdentifier, WrappingMethod,
        },
        requests::symmetric_key_create_request,
    },
};

use crate::{
    core::{KMS, wrapping::wrap_object},
    middlewares::UserId,
    tests::{
        crl_tests::{CA_EXT, certify},
        test_utils::test_kms,
    },
};

/// Self-signed certificate; returns `(certificate_uid, public_key_uid)`.
async fn certificate(kms: &Arc<KMS>, user: &UserId) -> (String, String) {
    let (cert_id, _) = certify(kms, user, "wrap-usage-mask", None, None, CA_EXT)
        .await
        .unwrap();
    let pk_id = kms
        .database
        .retrieve_object(&cert_id)
        .await
        .unwrap()
        .unwrap()
        .attributes()
        .get_link(LinkType::PublicKeyLink)
        .unwrap()
        .to_string();
    (cert_id, pk_id)
}

async fn set_attributes(kms: &KMS, uid: &str, edit: impl FnOnce(&mut Attributes)) {
    let owm = kms.database.retrieve_object(uid).await.unwrap().unwrap();
    let mut attributes = owm.attributes().clone();
    edit(&mut attributes);
    kms.database
        .update_object(uid, owm.object(), &attributes, None)
        .await
        .unwrap();
}

async fn set_usage_mask(kms: &KMS, uid: &str, mask: CryptographicUsageMask) {
    set_attributes(kms, uid, |a| a.cryptographic_usage_mask = Some(mask)).await;
}

/// Point the certificate's `PublicKeyLink` at `target`, or remove it.
async fn set_public_key_link(kms: &KMS, cert_id: &str, target: Option<&str>) {
    set_attributes(kms, cert_id, |a| match target {
        Some(uid) => a.set_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(uid.to_owned()),
        ),
        None => a.remove_link(LinkType::PublicKeyLink),
    })
    .await;
}

/// Wrap a fresh AES key with `wrapping_key_uid`.
async fn wrap_with(kms: &KMS, user: &UserId, wrapping_key_uid: &str) -> Result<(), String> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )
    .unwrap();
    let uid = kms
        .create(request, user)
        .await
        .unwrap()
        .unique_identifier
        .to_string();
    let mut object = kms
        .database
        .retrieve_object(&uid)
        .await
        .unwrap()
        .unwrap()
        .object()
        .clone();
    let spec = KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_uid.to_owned()),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..KeyWrappingSpecification::default()
    };
    wrap_object(&mut object, &spec, kms, user)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn certificate_wrap_requires_wrap_key_on_linked_public_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("wrap_cert_usage_pk_denied");
    let (cert_id, pk_id) = certificate(&kms, &user).await;
    set_usage_mask(&kms, &pk_id, CryptographicUsageMask::Verify).await;
    let err = wrap_with(&kms, &user, &cert_id).await.unwrap_err();
    assert!(err.contains("is not meant to wrap keys"), "{err}");
}

#[tokio::test]
async fn certificate_wrap_succeeds_when_linked_public_key_allows_wrap_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("wrap_cert_usage_pk_allowed");
    let (cert_id, pk_id) = certificate(&kms, &user).await;
    set_usage_mask(
        &kms,
        &pk_id,
        CryptographicUsageMask::Verify | CryptographicUsageMask::WrapKey,
    )
    .await;
    wrap_with(&kms, &user, &cert_id).await.unwrap();
}

#[tokio::test]
async fn certificate_own_usage_mask_takes_precedence_over_linked_public_key() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("wrap_cert_usage_cert_mask");
    let (cert_id, pk_id) = certificate(&kms, &user).await;
    set_usage_mask(&kms, &pk_id, CryptographicUsageMask::WrapKey).await;
    set_usage_mask(&kms, &cert_id, CryptographicUsageMask::Verify).await;
    let err = wrap_with(&kms, &user, &cert_id).await.unwrap_err();
    assert!(err.contains("is not meant to wrap keys"), "{err}");
}

#[tokio::test]
async fn certificate_own_wrap_key_mask_allows_wrapping() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("wrap_cert_usage_cert_allows");
    let (cert_id, pk_id) = certificate(&kms, &user).await;
    set_usage_mask(&kms, &pk_id, CryptographicUsageMask::Verify).await;
    set_usage_mask(&kms, &cert_id, CryptographicUsageMask::WrapKey).await;
    wrap_with(&kms, &user, &cert_id).await.unwrap();
}

#[tokio::test]
async fn certificate_without_usable_public_key_link_cannot_wrap() {
    let kms = test_kms().await.unwrap();
    let user = UserId::from("wrap_cert_usage_bad_link");
    let other = UserId::from("wrap_cert_usage_bad_link_other");
    let (cert_id, _) = certificate(&kms, &user).await;
    let private_key_id = kms
        .database
        .retrieve_object(&cert_id)
        .await
        .unwrap()
        .unwrap()
        .attributes()
        .get_link(LinkType::PrivateKeyLink)
        .unwrap()
        .to_string();
    set_usage_mask(&kms, &private_key_id, CryptographicUsageMask::WrapKey).await;
    // A public key with WrapKey that belongs to another user.
    let (_, foreign_pk_id) = certificate(&kms, &other).await;
    set_usage_mask(&kms, &foreign_pk_id, CryptographicUsageMask::WrapKey).await;

    for target in [
        None,
        Some("does-not-exist"),
        Some(private_key_id.as_str()),
        Some(foreign_pk_id.as_str()),
    ] {
        set_public_key_link(&kms, &cert_id, target).await;
        let err = wrap_with(&kms, &user, &cert_id).await.unwrap_err();
        assert!(
            err.contains("is not meant to wrap keys"),
            "{target:?}: {err}"
        );
    }
}

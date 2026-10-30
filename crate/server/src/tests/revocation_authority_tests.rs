//! Only the certificates a CA really issued count for its CRL and OCSP answers.
//!
//! Any user allowed to `Import` can link a certificate to any CA through `CertificateLink`: a
//! forgery carrying a genuine serial (issuer name of the CA, signed by another key) or an exact
//! copy of a genuine certificate. Revoking such a certificate must not put the genuine serial on
//! the CA's CRL, and keeping one active must not make OCSP answer `good` for a revoked
//! certificate.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{collections::HashSet, sync::Arc};

use actix_web::{App, test, web::Data};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{CertificateType, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        KmipOperation,
        extra::{VENDOR_ATTR_X509_EXTENSION, tagging::VENDOR_ID_COSMIAN},
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, Object, ObjectType},
        kmip_operations::{Certify, Get, GetAttributes, Import, Revoke},
        kmip_types::{
            CertificateAttributes, CryptographicAlgorithm, LinkType, LinkedObjectIdentifier,
            UniqueIdentifier, VendorAttribute, VendorAttributeValue,
        },
    },
};
use openssl::{
    hash::MessageDigest,
    ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspRequest, OcspResponse},
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    x509::{X509, store::X509StoreBuilder},
};

use crate::{
    config::ClapConfig,
    core::{
        KMS,
        operations::generate_crl::{CrlRequester, generate_crl},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    routes::ocsp,
    tests::test_utils::{get_tmp_sqlite_path, https_clap_config, test_kms, test_kms_with_config},
};

const CA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign
";

fn user(name: &str) -> UserId {
    UserId::try_new(name).expect("valid test user")
}

/// Certify `subject`, self-signed when `issuer` is `None`; returns the certificate id.
async fn certify(
    kms: &KMS,
    owner: &UserId,
    subject: &str,
    issuer: Option<(&str, &str)>,
) -> KResult<String> {
    let mut attributes = Attributes {
        activation_date: Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
        cryptographic_length: Some(2048),
        certificate_attributes: Some(CertificateAttributes::parse_subject_line(subject)?),
        ..Attributes::default()
    };
    if let Some((ca_id, ca_sk_id)) = issuer {
        for (link_type, id) in [
            (LinkType::CertificateLink, ca_id),
            (LinkType::PrivateKeyLink, ca_sk_id),
        ] {
            attributes.set_link(link_type, LinkedObjectIdentifier::TextString(id.to_owned()));
        }
    } else {
        attributes.vendor_attributes = Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(CA_EXT.to_vec()),
        }]);
    }
    Ok(kms
        .certify(
            Certify {
                attributes: Some(attributes),
                ..Certify::default()
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string())
}

/// Self-signed CA; returns `(certificate id, private key id)`.
async fn make_ca(kms: &KMS, owner: &UserId) -> KResult<(String, String)> {
    let ca_id = certify(kms, owner, "C=FR, O=KMS Test, CN=Revocation CA", None).await?;
    let ca_sk_id = kms
        .get_attributes(GetAttributes::from(ca_id.clone()), owner)
        .await?
        .attributes
        .get_link(LinkType::PrivateKeyLink)
        .expect("CA certificate has a PrivateKeyLink")
        .to_string();
    Ok((ca_id, ca_sk_id))
}

async fn certificate(kms: &KMS, owner: &UserId, id: &str) -> KResult<X509> {
    let response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
                ..Get::default()
            },
            owner,
        )
        .await?;
    let Object::Certificate(certificate) = response.object else {
        panic!("not a certificate");
    };
    Ok(X509::from_der(&certificate.certificate_value)?)
}

/// A certificate with the serial and subject of `genuine` that names `ca` as issuer, but is
/// signed by another key.
fn forge(genuine: &X509, ca: &X509) -> KResult<X509> {
    let key = PKey::from_rsa(Rsa::generate(2048)?)?;
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_serial_number(genuine.serial_number())?;
    builder.set_subject_name(genuine.subject_name())?;
    builder.set_issuer_name(ca.subject_name())?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(genuine.not_before())?;
    builder.set_not_after(genuine.not_after())?;
    builder.sign(&key, MessageDigest::sha256())?;
    Ok(builder.build())
}

/// Import `certificate` as `owner`, linked to the CA `ca_id`; returns its id.
async fn import_linked(
    kms: &KMS,
    owner: &UserId,
    certificate: &X509,
    ca_id: &str,
) -> KResult<String> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };
    attributes.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(ca_id.to_owned()),
    );
    Ok(kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString(String::new()),
                object_type: ObjectType::Certificate,
                replace_existing: None,
                key_wrap_type: None,
                attributes,
                object: Object::Certificate(Certificate {
                    certificate_type: CertificateType::X509,
                    certificate_value: certificate.to_der()?,
                }),
            },
            owner,
        )
        .await?
        .unique_identifier
        .to_string())
}

/// Import a forgery and an exact copy of `genuine`, both linked to `ca_id`; returns their ids.
async fn import_forgery_and_copy(
    kms: &KMS,
    owner: &UserId,
    genuine: &X509,
    ca: &X509,
    ca_id: &str,
) -> KResult<[String; 2]> {
    Ok([
        import_linked(kms, owner, &forge(genuine, ca)?, ca_id).await?,
        import_linked(kms, owner, genuine, ca_id).await?,
    ])
}

async fn revoke(kms: &KMS, owner: &UserId, id: &str) -> KResult<()> {
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        owner,
    )
    .await?;
    Ok(())
}

fn serial_hex(certificate: &X509) -> KResult<String> {
    Ok(certificate
        .serial_number()
        .to_bn()?
        .to_hex_str()?
        .to_string())
}

/// Serials (hex) listed on the CRL of `ca_id`, as generated for its owner.
async fn crl_serials(kms: &KMS, owner: &UserId, ca_id: &str) -> KResult<Vec<String>> {
    let crl = Box::pin(generate_crl(kms, ca_id, None, CrlRequester::User(owner))).await?;
    crl.get_revoked().map_or_else(
        || Ok(Vec::new()),
        |revoked| {
            revoked
                .iter()
                .map(|entry| Ok(entry.serial_number().to_bn()?.to_hex_str()?.to_string()))
                .collect()
        },
    )
}

#[tokio::test]
async fn crl_lists_only_revocations_of_certificates_the_ca_issued() -> KResult<()> {
    let kms = test_kms().await?;
    let alice = user("alice@example.com");
    let bob = user("bob@example.com");
    let mallory = user("mallory@example.com");
    let (ca_id, ca_sk_id) = make_ca(&kms, &alice).await?;
    let ca = certificate(&kms, &alice, &ca_id).await?;
    let leaf_id = certify(
        &kms,
        &alice,
        "C=FR, O=KMS Test, CN=Alice Leaf",
        Some((&ca_id, &ca_sk_id)),
    )
    .await?;
    let leaf = certificate(&kms, &alice, &leaf_id).await?;

    // Attack: mallory links a forgery and a copy of alice's active leaf to the CA, then
    // revokes them.
    for id in import_forgery_and_copy(&kms, &mallory, &leaf, &ca, &ca_id).await? {
        revoke(&kms, &mallory, &id).await?;
    }
    assert!(
        crl_serials(&kms, &alice, &ca_id).await?.is_empty(),
        "a forged or copied certificate revoked by another user must not reach the CA CRL"
    );

    // The genuine revocation is listed, once.
    revoke(&kms, &alice, &leaf_id).await?;
    assert_eq!(
        crl_serials(&kms, &alice, &ca_id).await?,
        vec![serial_hex(&leaf)?]
    );

    // A delegated issuer's revocation is listed, and stays listed after its grant is removed.
    kms.database
        .grant_operations(&ca_id, &bob, HashSet::from([KmipOperation::Certify]))
        .await?;
    kms.database
        .grant_operations(&ca_sk_id, &bob, HashSet::from([KmipOperation::Get]))
        .await?;
    let bob_leaf_id = certify(
        &kms,
        &bob,
        "C=FR, O=KMS Test, CN=Bob Leaf",
        Some((&ca_id, &ca_sk_id)),
    )
    .await?;
    let bob_leaf = certificate(&kms, &bob, &bob_leaf_id).await?;
    for id in import_forgery_and_copy(&kms, &mallory, &bob_leaf, &ca, &ca_id).await? {
        revoke(&kms, &mallory, &id).await?;
    }
    assert_eq!(
        crl_serials(&kms, &alice, &ca_id).await?,
        vec![serial_hex(&leaf)?],
        "the authorized issuer's active record outweighs revoked copies"
    );
    revoke(&kms, &bob, &bob_leaf_id).await?;
    kms.database
        .remove_operations(&ca_sk_id, &bob, HashSet::from([KmipOperation::Get]))
        .await?;
    let mut serials = crl_serials(&kms, &alice, &ca_id).await?;
    serials.sort();
    let mut expected = vec![serial_hex(&leaf)?, serial_hex(&bob_leaf)?];
    expected.sort();
    assert_eq!(serials, expected);
    Ok(())
}

/// POST an OCSP request for `leaf` (issued by `ca`) and return the verified status.
async fn ocsp_status(kms: &Arc<KMS>, ca: &X509, leaf: &X509) -> KResult<OcspCertStatus> {
    let app = test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .service(ocsp::post_ocsp),
    )
    .await;
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(MessageDigest::sha1(), leaf, ca)?)?;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/ocsp/")
            .insert_header(("content-type", "application/ocsp-request"))
            .set_payload(request.to_der()?)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 200);
    let basic = OcspResponse::from_der(&test::read_body(response).await)?.basic()?;
    let mut trusted = X509StoreBuilder::new()?;
    trusted.add_cert(ca.clone())?;
    let untrusted: Stack<X509> = Stack::new()?;
    basic.verify(&untrusted, &trusted.build(), OcspFlag::empty())?;
    let id = OcspCertId::from_cert(MessageDigest::sha1(), leaf, ca)?;
    Ok(basic
        .find_status(&id)
        .ok_or_else(|| KmsError::ServerError("no OCSP status for the leaf".to_owned()))?
        .status)
}

fn config(sqlite_path: &std::path::Path, ocsp_ca_uid: Option<String>) -> ClapConfig {
    let mut config = https_clap_config();
    config.db.sqlite_path = sqlite_path.to_path_buf();
    config.ocsp.ocsp_enabled = ocsp_ca_uid.is_some();
    config.ocsp.ocsp_ca_uid = ocsp_ca_uid;
    config
}

#[tokio::test]
async fn ocsp_ignores_forged_and_copied_certificates_linked_to_the_ca() -> KResult<()> {
    let sqlite_path = get_tmp_sqlite_path();
    let kms = test_kms_with_config(config(&sqlite_path, None)).await?;
    let alice = user("alice@example.com");
    let mallory = user("mallory@example.com");
    let (ca_id, ca_sk_id) = make_ca(&kms, &alice).await?;
    let ca = certificate(&kms, &alice, &ca_id).await?;
    let leaf_subject = |cn: &str| format!("C=FR, O=KMS Test, CN={cn}");
    let issuer = Some((ca_id.as_str(), ca_sk_id.as_str()));
    let revoked_leaf_id = certify(&kms, &alice, &leaf_subject("Revoked Leaf"), issuer).await?;
    let revoked_leaf = certificate(&kms, &alice, &revoked_leaf_id).await?;
    let active_leaf_id = certify(&kms, &alice, &leaf_subject("Active Leaf"), issuer).await?;
    let active_leaf = certificate(&kms, &alice, &active_leaf_id).await?;
    revoke(&kms, &alice, &revoked_leaf_id).await?;
    // Active forgery and copy of the revoked leaf; revoked forgery and copy of the active leaf.
    import_forgery_and_copy(&kms, &mallory, &revoked_leaf, &ca, &ca_id).await?;
    for id in import_forgery_and_copy(&kms, &mallory, &active_leaf, &ca, &ca_id).await? {
        revoke(&kms, &mallory, &id).await?;
    }

    // OCSP is configured at startup: restart on the same database with the CA as responder.
    drop(kms);
    let kms = test_kms_with_config(config(&sqlite_path, Some(ca_id))).await?;
    assert_eq!(
        ocsp_status(&kms, &ca, &revoked_leaf).await?,
        OcspCertStatus::REVOKED
    );
    assert_eq!(
        ocsp_status(&kms, &ca, &active_leaf).await?,
        OcspCertStatus::GOOD
    );
    Ok(())
}

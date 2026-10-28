//! Sub-CA whose private key is non-extractable and lives in the HSM: CSR generation, certificate
//! issuance and CRL signing all go through the crypto oracle, the key never leaves the HSM.

use std::sync::Arc;

use actix_web::{App, test, web::Data};
use cosmian_kms_access::access::Access;
use cosmian_kms_interfaces::{ObjectHandle, as_hsm_uid};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{ErrorReason, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        KmipOperation,
        extra::{
            VENDOR_ATTR_X509_EXTENSION,
            tagging::{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX, VENDOR_ID_COSMIAN},
        },
        kmip_attributes::{Attribute, Attributes},
        kmip_objects::Object,
        kmip_operations::{
            AddAttribute, Certify, CreateKeyPair, Get, GetAttributes, ReCertify, Revoke,
        },
        kmip_types::{
            CertificateAttributes, CertificateRequestType, CryptographicAlgorithm, Link, LinkType,
            LinkedObjectIdentifier, RecommendedCurve, UniqueIdentifier, VendorAttribute,
            VendorAttributeValue,
        },
        requests::{create_ec_key_pair_request, create_rsa_key_pair_request},
    },
};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    ocsp::{OcspCertId, OcspCertStatus as OpenSslOcspStatus, OcspFlag, OcspRequest, OcspResponse},
    stack::Stack,
    x509::{X509, X509Crl, store::X509StoreBuilder},
};
use uuid::Uuid;

use crate::{
    core::{
        KMS,
        operations::{
            generate_crl::{CrlRequester, generate_crl},
            generate_csr::generate_csr,
        },
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    routes::ocsp,
    tests::{
        hsm::{EMPTY_TAGS, hsm_clap_config},
        test_utils::{get_tmp_sqlite_path, test_kms_with_config},
    },
};

const CA_EXT: &[u8] = b"[v3_ca]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,crlSign
";

fn certify_request(subject: Option<&str>, links: &[(LinkType, &str)]) -> KResult<Certify> {
    let mut attributes = Attributes {
        certificate_attributes: subject
            .map(CertificateAttributes::parse_subject_line)
            .transpose()?,
        vendor_attributes: Some(vec![VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_X509_EXTENSION.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(CA_EXT.to_vec()),
        }]),
        ..Attributes::default()
    };
    if subject.is_some() {
        attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
        attributes.cryptographic_length = Some(2048);
    }
    for (link_type, id) in links {
        attributes.set_link(
            *link_type,
            LinkedObjectIdentifier::TextString((*id).to_owned()),
        );
    }
    Ok(Certify {
        attributes: Some(attributes),
        ..Certify::default()
    })
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
        return Err(KmsError::ServerError("not a certificate".to_owned()));
    };
    Ok(X509::from_der(&certificate.certificate_value)?)
}

/// Create a non-extractable key pair `sk_id` in the HSM, get its CSR signed by the HSM and
/// certified by `root_id` through the `CertificateLink` only (the root key is found through the
/// root certificate), link the certificate to the key, then issue a leaf and a CRL through the
/// HSM. Returns `(sub-CA certificate id, leaf certificate id)`.
async fn sub_ca_flow(
    kms: &KMS,
    owner: &UserId,
    root_id: &str,
    sk_id: &str,
    key_pair_request: Result<CreateKeyPair, KmsError>,
) -> KResult<(String, String)> {
    let created = kms.create_key_pair(key_pair_request?, owner).await?;
    // Both halves are created directly in the HSM: HSM routing ids, public key readable back
    // from the HSM, private key a non-extractable (sensitive) HSM object.
    assert_eq!(created.private_key_unique_identifier.to_string(), sk_id);
    let pk_id = created.public_key_unique_identifier.to_string();
    assert_eq!(pk_id, format!("{sk_id}_pk"));
    assert!(ObjectHandle::from(sk_id).is_hsm() && ObjectHandle::from(pk_id.as_str()).is_hsm());
    assert!(kms.database.retrieve_object_arc(&pk_id).await?.is_some());
    let sk_attributes = kms
        .get_attributes(GetAttributes::from(sk_id.to_owned()), owner)
        .await?
        .attributes;
    assert_eq!(sk_attributes.sensitive, Some(true));

    // CSR signed by the HSM, then certified by the root.
    let csr = generate_csr(kms, sk_id, "C=FR, O=KMS Test, CN=HSM Sub CA", owner).await?;
    assert!(csr.verify(csr.public_key()?.as_ref())?);
    let mut request = certify_request(None, &[(LinkType::CertificateLink, root_id)])?;
    request.certificate_request_type = Some(CertificateRequestType::PKCS10);
    request.certificate_request_value = Some(csr.to_der()?);
    let sub_id = kms
        .certify(request, owner)
        .await?
        .unique_identifier
        .to_string();
    let root = certificate(kms, owner, root_id).await?;
    let sub = certificate(kms, owner, &sub_id).await?;
    assert!(sub.verify(root.public_key()?.as_ref())?);
    assert!(sub.public_key()?.public_eq(csr.public_key()?.as_ref()));

    // Link the certificate to its HSM key, then issue a leaf and a CRL through the HSM.
    kms.add_attribute(
        AddAttribute {
            unique_identifier: UniqueIdentifier::TextString(sub_id.clone()),
            new_attribute: Attribute::Link(Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(sk_id.to_owned()),
            }),
        },
        owner,
    )
    .await?;
    let leaf_id = kms
        .certify(
            certify_request(
                Some("C=FR, O=KMS Test, CN=Leaf"),
                &[
                    (LinkType::CertificateLink, &sub_id),
                    (LinkType::PrivateKeyLink, sk_id),
                ],
            )?,
            owner,
        )
        .await?
        .unique_identifier
        .to_string();
    let leaf = certificate(kms, owner, &leaf_id).await?;
    assert!(
        leaf.verify(sub.public_key()?.as_ref())?,
        "leaf is signed by the HSM sub-CA key"
    );

    let crl: X509Crl =
        Box::pin(generate_crl(kms, &sub_id, None, CrlRequester::User(owner))).await?;
    assert!(
        crl.verify(sub.public_key()?.as_ref())?,
        "CRL is signed by the HSM sub-CA key"
    );
    Ok((sub_id, leaf_id))
}

/// POST a DER OCSP request for `leaf` (issued by `sub`) and return the verified status.
async fn ocsp_status(
    kms: &Arc<KMS>,
    root: &X509,
    sub: &X509,
    leaf: &X509,
) -> KResult<OpenSslOcspStatus> {
    let app = test::init_service(
        App::new()
            .app_data(Data::new(kms.clone()))
            .service(ocsp::post_ocsp),
    )
    .await;
    let mut request = OcspRequest::new()?;
    request.add_id(OcspCertId::from_cert(MessageDigest::sha1(), leaf, sub)?)?;
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
    let body = test::read_body(response).await;

    let basic = OcspResponse::from_der(&body)?.basic()?;
    let mut trusted = X509StoreBuilder::new()?;
    trusted.add_cert(root.clone())?;
    trusted.add_cert(sub.clone())?;
    let mut others = Stack::new()?;
    others.push(sub.clone())?;
    basic.verify(&others, &trusted.build(), OcspFlag::empty())?;
    let id = OcspCertId::from_cert(MessageDigest::sha1(), leaf, sub)?;
    Ok(basic
        .find_status(&id)
        .ok_or_else(|| KmsError::ServerError("no OCSP status for the leaf".to_owned()))?
        .status)
}

/// Offline-root stand-in: a self-signed root whose non-extractable key pair `root_sk_id` is in
/// the HSM. Returns the root certificate id.
async fn create_hsm_root(kms: &KMS, owner: &UserId, root_sk_id: &str) -> KResult<String> {
    kms.create_key_pair(
        create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(root_sk_id.to_owned())),
            EMPTY_TAGS,
            2048,
            true,
            None,
        )?,
        owner,
    )
    .await?;
    // self-signed from the HSM public key: the private key is derived from `<sk>_pk`
    let mut root_request = certify_request(Some("C=FR, O=KMS Test, CN=HSM Root"), &[])?;
    root_request.unique_identifier = Some(UniqueIdentifier::TextString(format!("{root_sk_id}_pk")));
    let root_id = kms
        .certify(root_request, owner)
        .await?
        .unique_identifier
        .to_string();
    // the root certificate keeps its link to the HSM key (HSM objects carry no links)
    assert_eq!(
        kms.get_attributes(GetAttributes::from(root_id.clone()), owner)
            .await?
            .attributes
            .get_link(LinkType::PrivateKeyLink)
            .map(|link| link.to_string()),
        Some(root_sk_id.to_owned())
    );
    Ok(root_id)
}

/// A non-admin user needs an explicit grant per operation on an HSM key (`Get` is no wildcard):
/// `Sign` for a CSR, `Certify` for a CRL (plus `Get` on the CA certificate).
async fn non_admin_grants(kms: &KMS, owner: &UserId, sub_id: &str, sub_sk_id: &str) -> KResult<()> {
    let operator_name = Uuid::new_v4().to_string();
    let operator = UserId::from(operator_name.as_str());
    let access = |id: &str, operation: KmipOperation| Access {
        unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
        user_id: operator_name.clone(),
        operation_types: vec![operation],
    };

    kms.grant_access(&access(sub_sk_id, KmipOperation::Get), owner)
        .await?;
    let result = generate_csr(kms, sub_sk_id, "CN=Operator", &operator).await;
    assert!(
        matches!(
            result,
            Err(KmsError::Kmip21Error(ErrorReason::Object_Not_Found, _))
        ),
        "Get on an HSM key does not allow a CSR, got {:?}",
        result.map(|_csr| ())
    );
    kms.grant_access(&access(sub_sk_id, KmipOperation::Sign), owner)
        .await?;
    let csr = generate_csr(kms, sub_sk_id, "CN=Operator", &operator).await?;
    assert!(csr.verify(csr.public_key()?.as_ref())?);

    // CRL: reading the CA certificate and holding Sign on its HSM key is not enough
    kms.grant_access(&access(sub_id, KmipOperation::Get), owner)
        .await?;
    let result = Box::pin(generate_crl(
        kms,
        sub_id,
        None,
        CrlRequester::User(&operator),
    ))
    .await;
    assert!(
        result
            .as_ref()
            .is_err_and(|e| e.to_string().contains("object not found")),
        "a CRL needs the Certify grant on the HSM key, got {:?}",
        result.map(|_crl| ())
    );
    let leaf_request = || {
        certify_request(
            Some("C=FR, O=KMS Test, CN=Operator Leaf"),
            &[
                (LinkType::CertificateLink, sub_id),
                (LinkType::PrivateKeyLink, sub_sk_id),
            ],
        )
    };
    let result = kms.certify(leaf_request()?, &operator).await;
    assert!(
        result.is_err(),
        "issuing with an HSM CA key needs the Certify grant, got {:?}",
        result.map(|_response| ())
    );
    kms.grant_access(&access(sub_sk_id, KmipOperation::Certify), owner)
        .await?;
    let crl = Box::pin(generate_crl(
        kms,
        sub_id,
        None,
        CrlRequester::User(&operator),
    ))
    .await?;
    let sub = certificate(kms, owner, sub_id).await?;
    let leaf_id = kms
        .certify(leaf_request()?, &operator)
        .await?
        .unique_identifier
        .to_string();
    let leaf = certificate(kms, &operator, &leaf_id).await?;
    assert!(
        leaf.verify(sub.public_key()?.as_ref())?,
        "the operator's leaf is signed by the HSM sub-CA key"
    );
    assert!(crl.verify(sub.public_key()?.as_ref())?);
    Ok(())
}

pub(super) async fn test_hsm_sub_ca() -> KResult<()> {
    let owner_name = Uuid::new_v4().to_string();
    let owner = UserId::from(owner_name.as_str());
    let mut clap_config = hsm_clap_config(&owner_name, None)?;
    let sqlite_path = get_tmp_sqlite_path();
    clap_config.db.sqlite_path = sqlite_path.clone();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    let root_sk_id = as_hsm_uid!(slot, Uuid::new_v4());
    let root_id = create_hsm_root(&kms, &owner, &root_sk_id).await?;
    // A CSR signed by a sensitive HSM key can name only the issuer private key: the issuer
    // certificate is resolved through its persisted PrivateKeyLink, not HSM key attributes.
    let csr_subject_sk_id = as_hsm_uid!(slot, Uuid::new_v4());
    kms.create_key_pair(
        create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(csr_subject_sk_id.clone())),
            EMPTY_TAGS,
            2048,
            true,
            None,
        )?,
        &owner,
    )
    .await?;
    let csr = generate_csr(
        &kms,
        &csr_subject_sk_id,
        "C=FR, O=KMS Test, CN=CSR Subject",
        &owner,
    )
    .await?;
    let mut csr_request =
        certify_request(None, &[(LinkType::PrivateKeyLink, root_sk_id.as_str())])?;
    csr_request.certificate_request_type = Some(CertificateRequestType::PKCS10);
    csr_request.certificate_request_value = Some(csr.to_der()?);
    let csr_certificate_id = kms
        .certify(csr_request, &owner)
        .await?
        .unique_identifier
        .to_string();
    let root = certificate(&kms, &owner, &root_id).await?;
    let csr_certificate = certificate(&kms, &owner, &csr_certificate_id).await?;
    assert!(csr_certificate.verify(root.public_key()?.as_ref())?);

    // Sub-CA with a non-extractable RSA key pair inside the HSM.
    let sub_sk_id = as_hsm_uid!(slot, Uuid::new_v4());
    let (sub_id, leaf_id) = Box::pin(sub_ca_flow(
        &kms,
        &owner,
        &root_id,
        &sub_sk_id,
        create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(sub_sk_id.clone())),
            EMPTY_TAGS,
            2048,
            true,
            None,
        )
        .map_err(KmsError::from),
    ))
    .await?;

    // ReCertify with the HSM issuer: re-signed through the oracle, serial tag replaced by the new serial.
    let mut renew_attributes = Attributes::default();
    renew_attributes.set_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(sub_id.clone()),
    );
    renew_attributes.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(sub_sk_id.clone()),
    );
    let renewed_id = kms
        .recertify(
            ReCertify {
                unique_identifier: Some(UniqueIdentifier::TextString(leaf_id)),
                certificate_request_type: None,
                certificate_request_value: None,
                offset: None,
                attributes: Some(renew_attributes),
                protection_storage_masks: None,
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();
    let sub_before_restart = certificate(&kms, &owner, &sub_id).await?;
    let renewed = certificate(&kms, &owner, &renewed_id).await?;
    assert!(
        renewed.verify(sub_before_restart.public_key()?.as_ref())?,
        "the renewed leaf is signed by the HSM sub-CA key"
    );
    let renewed_serial = renewed.serial_number().to_bn()?.to_hex_str()?.to_string();
    let serial_tags: Vec<String> = kms
        .database
        .retrieve_tags(&renewed_id)
        .await?
        .into_iter()
        .filter(|tag| tag.starts_with(SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX))
        .collect();
    assert_eq!(
        serial_tags,
        vec![format!(
            "{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX}{renewed_serial}"
        )]
    );

    // A certificate paired with another HSM key must not produce a certificate (fails closed).
    let mismatch = kms
        .certify(
            certify_request(
                Some("C=FR, O=KMS Test, CN=Mismatch"),
                &[
                    (LinkType::CertificateLink, &sub_id),
                    (LinkType::PrivateKeyLink, &root_sk_id),
                ],
            )?,
            &owner,
        )
        .await;
    assert!(
        mismatch.is_err(),
        "the sub-CA certificate paired with the root HSM key must not issue, got {:?}",
        mismatch.map(|_response| ())
    );

    // An extractable (non-sensitive) HSM key never signs a CSR: the key must stay in the HSM.
    let extractable_sk_id = as_hsm_uid!(slot, Uuid::new_v4());
    kms.create_key_pair(
        create_rsa_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(extractable_sk_id.clone())),
            EMPTY_TAGS,
            2048,
            false,
            None,
        )?,
        &owner,
    )
    .await?;
    let result = generate_csr(&kms, &extractable_sk_id, "CN=Extractable", &owner).await;
    assert!(
        matches!(&result, Err(KmsError::InvalidRequest(msg)) if msg.contains("is extractable")),
        "an extractable HSM key must be refused, got {:?}",
        result.map(|_csr| ())
    );

    Box::pin(non_admin_grants(&kms, &owner, &sub_id, &sub_sk_id)).await?;

    // OCSP responses signed by the HSM sub-CA key: restart on the same database with OCSP on.
    drop(kms);
    let mut clap_config = hsm_clap_config(&owner_name, None)?;
    clap_config.db.sqlite_path = sqlite_path;
    clap_config.ocsp.ocsp_enabled = true;
    clap_config.ocsp.ocsp_ca_uid = Some(sub_id.clone());
    clap_config.ocsp.ocsp_include_cert_chain = true;
    let kms = test_kms_with_config(clap_config).await?;
    let root = certificate(&kms, &owner, &root_id).await?;
    let sub = certificate(&kms, &owner, &sub_id).await?;
    // ReCertify deactivated the original leaf (Get is refused): the renewed one is checked
    let leaf = certificate(&kms, &owner, &renewed_id).await?;
    assert_eq!(
        ocsp_status(&kms, &root, &sub, &leaf).await?,
        OpenSslOcspStatus::GOOD
    );
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(renewed_id)),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: false,
        },
        &owner,
    )
    .await?;
    assert_eq!(
        ocsp_status(&kms, &root, &sub, &leaf).await?,
        OpenSslOcspStatus::REVOKED
    );
    Ok(())
}

/// Sub-CA with an Ed25519 HSM key, signed by an RSA HSM root.
#[cfg(feature = "non-fips")]
pub(super) async fn test_hsm_sub_ca_ed25519() -> KResult<()> {
    let owner_name = Uuid::new_v4().to_string();
    let owner = UserId::from(owner_name.as_str());
    let mut clap_config = hsm_clap_config(&owner_name, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    let root_id = create_hsm_root(&kms, &owner, &as_hsm_uid!(slot, Uuid::new_v4())).await?;
    let ed_sk_id = as_hsm_uid!(slot, Uuid::new_v4());
    Box::pin(sub_ca_flow(
        &kms,
        &owner,
        &root_id,
        &ed_sk_id,
        create_ec_key_pair_request(
            VENDOR_ID_COSMIAN,
            Some(UniqueIdentifier::TextString(ed_sk_id.clone())),
            EMPTY_TAGS,
            RecommendedCurve::CURVEED25519,
            true,
            None,
        )
        .map_err(KmsError::from),
    ))
    .await?;
    Ok(())
}

/// Sub-CA with an ECDSA HSM key (P-256 and P-384), signed by an RSA HSM root: the HSM's raw r||s
/// signatures must come back DER-encoded in the CSR, the leaf certificate and the CRL.
pub(super) async fn test_hsm_sub_ca_ec() -> KResult<()> {
    let owner_name = Uuid::new_v4().to_string();
    let owner = UserId::from(owner_name.as_str());
    let mut clap_config = hsm_clap_config(&owner_name, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    let root_id = create_hsm_root(&kms, &owner, &as_hsm_uid!(slot, Uuid::new_v4())).await?;
    for curve in [RecommendedCurve::P256, RecommendedCurve::P384] {
        let sk_id = as_hsm_uid!(slot, Uuid::new_v4());
        let (_sub_id, leaf_id) = Box::pin(sub_ca_flow(
            &kms,
            &owner,
            &root_id,
            &sk_id,
            create_ec_key_pair_request(
                VENDOR_ID_COSMIAN,
                Some(UniqueIdentifier::TextString(sk_id.clone())),
                EMPTY_TAGS,
                curve,
                true,
                None,
            )
            .map_err(KmsError::from),
        ))
        .await?;
        let leaf = certificate(&kms, &owner, &leaf_id).await?;
        assert_eq!(
            leaf.signature_algorithm().object().nid(),
            Nid::ECDSA_WITH_SHA256,
            "{curve:?}: an EC HSM CA signs ecdsa-with-SHA256"
        );
    }
    Ok(())
}

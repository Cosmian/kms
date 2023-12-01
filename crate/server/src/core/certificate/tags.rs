use std::collections::HashSet;

use cosmian_kmip::kmip::kmip_types::{Attributes, LinkType, LinkedObjectIdentifier};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use openssl::{sha::Sha1, x509::X509};

use crate::{core::KMS, error::KmsError, result::KResult};

/// Add system tags to the certificate user tags
///
/// The additional tags are added to compensate the lack of support for attributes
/// TODO see https://github.com/Cosmian/kms/issues/88
pub fn add_certificate_system_tags(
    user_tags: &mut HashSet<String>,
    certificate: &X509,
) -> KResult<()> {
    // The certificate "system" tag
    user_tags.insert("_cert".to_string());

    // add the SPKI tag corresponding to the `SubjectKeyIdentifier` X509 extension
    let hash_value = hex::encode(get_or_create_subject_key_identifier_value(certificate)?);
    let spki_tag = format!("_cert_spki={hash_value}");
    user_tags.insert(spki_tag);

    // add a tag with Subject Common Name
    let subject_name = certificate.subject_name();
    if let Some(subject_common_name) = subject_name
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|cn| cn.data().as_utf8().ok())
    {
        let cn_tag = format!("_cert_cn={subject_common_name}");
        user_tags.insert(cn_tag);
    }
    Ok(())
}

/// Get the `SubjectKeyIdentifier` X509 extension value
/// If it is not available, it is
/// calculated according to RFC 5280 section 4.2.1.2
fn get_or_create_subject_key_identifier_value(certificate: &X509) -> Result<Vec<u8>, KmsError> {
    Ok(if let Some(ski) = certificate.subject_key_id() {
        ski.as_slice().to_vec()
    } else {
        let pk = certificate.public_key()?;
        let spki_der = pk.public_key_to_der()?;
        let mut sha1 = Sha1::default();
        sha1.update(&spki_der);
        sha1.finish().to_vec()
    })
}

/// Retrieve certificate Attributes from Tags
///TODO: retrieve attributes from tags until https://github.com/Cosmian/kms/issues/88 is fixed
pub async fn add_certificate_tags_to_attributes(
    attributes: &mut Attributes,
    certificate_id: &str,
    kms: &KMS,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let tags = kms.db.retrieve_tags(certificate_id, params).await?;
    // add link to the private key
    if let Some(id) = tags
        .iter()
        .find(|tag| tag.starts_with("_cert_sk="))
        .map(|tag| tag.replace("_cert_sk=", ""))
    {
        attributes.add_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(id),
        );
    }
    // add link to the public key
    if let Some(id) = tags
        .iter()
        .find(|tag| tag.starts_with("_cert_pk="))
        .map(|tag| tag.replace("_cert_pk=", ""))
    {
        attributes.add_link(
            LinkType::PublicKeyLink,
            LinkedObjectIdentifier::TextString(id),
        );
    }
    // add link to issuer certificate
    if let Some(id) = tags
        .iter()
        .find(|tag| tag.starts_with("_cert_issuer="))
        .map(|tag| tag.replace("_cert_issuer=", ""))
    {
        attributes.add_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(id),
        );
    }
    Ok(())
}

/// Convert certificate attributes to tags
/// TODO: remove when https://github.com/Cosmian/kms/issues/88 is fixed
pub fn add_attributes_to_certificate_tags(
    tags: &mut HashSet<String>,
    attributes: &Attributes,
) -> KResult<()> {
    if let Some(link) = attributes.get_link(LinkType::PrivateKeyLink) {
        tags.insert(format!("_cert_sk={link}"));
    }
    if let Some(link) = attributes.get_link(LinkType::PublicKeyLink) {
        tags.insert(format!("_cert_pk={link}"));
    }
    if let Some(link) = attributes.get_link(LinkType::CertificateLink) {
        tags.insert(format!("_cert_issuer={link}"));
    }
    Ok(())
}

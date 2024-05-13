use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        extra::{x509_extensions, VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_objects::Object,
        kmip_types::{Attributes, CertificateAttributes, LinkType},
    },
    openssl::openssl_certificate_to_kmip,
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, PKeyRef, Public},
    x509::{X509Name, X509NameRef, X509},
};

use crate::{
    core::operations::certify::{issuer::Issuer, X509_VERSION3},
    error::KmsError,
    result::KResult,
};

/// The party that gets signed by the issuer and gets the certificate
pub struct Subject {}

impl Subject {
    pub fn subject_name(&self) -> KResult<&X509NameRef> {
        unimplemented!()
    }

    pub fn public_key(&self) -> KResult<&PKeyRef<Public>> {
        unimplemented!()
    }
}

fn build_and_sign_certificate(
    tags: &mut HashSet<String>,
    attributes: &mut Attributes,
    issuer: &Issuer,
    not_before: Asn1Time,
    number_of_days: usize,
    subject_name: X509Name,
    certificate_public_key: PKey<Public>,
) -> Result<Object, KmsError> {
    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(X509_VERSION3)?;
    x509_builder.set_subject_name(subject_name.as_ref())?;
    x509_builder.set_pubkey(certificate_public_key.as_ref())?;
    x509_builder.set_not_before(not_before.as_ref())?;
    // Sign the X509 struct with the PKey struct.
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days as u32)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;
    x509_builder.set_issuer_name(&issuer.subject_name)?;
    x509_builder.sign(&*issuer.private_key, MessageDigest::sha256())?;

    // Extensions
    if let Some(extensions) =
        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION)
    {
        let extensions_as_str = String::from_utf8(extensions.to_vec())?;
        let issuer_x509 = issuer.x509.as_ref().map(|x509| x509.as_ref());
        let context = x509_builder.x509v3_context(issuer_x509, None);
        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
    }

    let x509 = x509_builder.build();

    // link the certificate to the issuer certificate
    attributes.add_link(
        LinkType::CertificateLink,
        issuer.certificate_id.clone().into(),
    );

    // add the certificate "system" tag
    tags.insert("_cert".to_string());
    let certificate_attributes = CertificateAttributes::from(&x509);
    attributes.certificate_attributes = Some(Box::new(certificate_attributes));

    openssl_certificate_to_kmip(&x509).map_err(KmsError::from)
}

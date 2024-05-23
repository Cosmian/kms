use cosmian_kmip::{kmip::kmip_types::UniqueIdentifier, openssl::kmip_certificate_to_openssl};
use openssl::{
    asn1::Asn1Time,
    pkey::{PKey, PKeyRef, Private},
    x509::{X509Name, X509NameRef, X509},
};

use crate::{
    database::object_with_metadata::ObjectWithMetadata,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// A certificate Issuer is constructed from
///  - either a private key and a certificate.
///  - or a private key, subject name and expiry days.
pub enum Issuer<'a> {
    PrivateKeyAndCertificate(UniqueIdentifier, ObjectWithMetadata, ObjectWithMetadata),
    PrivateKeyAndSubjectName(
        UniqueIdentifier,
        ObjectWithMetadata,
        &'a X509NameRef,
        Option<ObjectWithMetadata>,
    ),
}

impl<'a> Issuer<'a> {
    pub fn unique_identifier(&self) -> &UniqueIdentifier {
        match self {
            Issuer::PrivateKeyAndCertificate(unique_identifier, _, _) => unique_identifier,
            Issuer::PrivateKeyAndSubjectName(unique_identifier, _, _, _) => unique_identifier,
        }
    }

    pub fn private_key(&self) -> &PKeyRef<Private> {
        &self.private_key.as_ref()
    }

    pub fn subject_name(&self) -> KResult<&X509NameRef> {
        match self {
            Issuer::PrivateKeyAndCertificate(_, _, certificate) => {
                Ok(kmip_certificate_to_openssl(&certificate.object)?.subject_name())
            }
            Issuer::PrivateKeyAndSubjectName(_, _, subject_name, _) => Ok(subject_name),
        }
    }

    pub fn expiry_days(&self) -> KResult<usize> {
        self.x509.as_ref().map_or_else(
            || self.expiry_days.context("Invalid Issuer Expiry Days"),
            |x509| {
                let now = Asn1Time::days_from_now(0)?;
                let num_days = x509.not_after().diff(now.as_ref())?.days as usize;
                if num_days <= 0 {
                    kms_bail!("Invalid Issuer Expiry Days: Certificate is already expired")
                }
                Ok(num_days)
            },
        )
    }
}

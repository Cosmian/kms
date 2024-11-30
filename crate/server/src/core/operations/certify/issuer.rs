use cosmian_kmip::kmip::kmip_types::UniqueIdentifier;
use openssl::{
    asn1::Asn1TimeRef,
    pkey::{PKey, PKeyRef, Private},
    x509::{X509NameRef, X509Ref, X509},
};

/// A certificate Issuer is constructed from a unique identifier and
///  - either a private key and a certificate.
///  - or a private key, a subject name and a certificate.
pub(crate) enum Issuer<'a> {
    PrivateKeyAndCertificate(
        UniqueIdentifier,
        /// Private key
        PKey<Private>,
        /// Certificate
        X509,
    ),
    PrivateKeyAndSubjectName(
        UniqueIdentifier,
        /// Private key
        PKey<Private>,
        /// Subject name
        &'a X509NameRef,
    ),
}

impl Issuer<'_> {
    pub(crate) const fn unique_identifier(&self) -> &UniqueIdentifier {
        match self {
            Issuer::PrivateKeyAndCertificate(unique_identifier, _, _)
            | Issuer::PrivateKeyAndSubjectName(unique_identifier, _, _) => unique_identifier,
        }
    }

    pub(crate) fn private_key(&self) -> &PKeyRef<Private> {
        match self {
            Issuer::PrivateKeyAndCertificate(_, private_key, _)
            | Issuer::PrivateKeyAndSubjectName(_, private_key, _) => private_key.as_ref(),
        }
    }

    pub(crate) fn subject_name(&self) -> &X509NameRef {
        match self {
            Issuer::PrivateKeyAndCertificate(_, _, certificate) => certificate.subject_name(),
            Issuer::PrivateKeyAndSubjectName(_, _, subject_name) => subject_name,
        }
    }

    pub(crate) fn certificate(&self) -> Option<&X509Ref> {
        match self {
            Issuer::PrivateKeyAndCertificate(_, _, certificate) => Some(certificate.as_ref()),
            Issuer::PrivateKeyAndSubjectName(_, _, _) => None,
        }
    }

    pub(crate) fn not_after(&self) -> Option<&Asn1TimeRef> {
        match self {
            Issuer::PrivateKeyAndCertificate(_, _, certificate) => Some(certificate.not_after()),
            Issuer::PrivateKeyAndSubjectName(_, _, _) => None,
        }
    }
}

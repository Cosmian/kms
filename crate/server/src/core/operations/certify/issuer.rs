use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
use openssl::{
    asn1::Asn1TimeRef,
    pkey::{PKey, Private},
    x509::{X509, X509NameRef, X509Ref},
};

use crate::core::certificate::oracle_signing::OracleSigningKey;

/// Key used to sign issued certificates.
pub(crate) enum IssuerKey {
    /// Key material loaded in process memory (keys stored in the KMS database).
    Local(PKey<Private>),
    /// HSM-resident key: signs through the crypto oracle, material never leaves the HSM.
    Oracle(OracleSigningKey),
}

/// A certificate Issuer is constructed from a unique identifier and
///  - either a signing key and a certificate.
///  - or a signing key, a subject name and a certificate.
pub(crate) enum Issuer<'a> {
    PrivateKeyAndCertificate(
        UniqueIdentifier,
        /// Signing key
        IssuerKey,
        /// Certificate
        X509,
    ),
    PrivateKeyAndSubjectName(
        UniqueIdentifier,
        /// Signing key
        IssuerKey,
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

    pub(crate) const fn key(&self) -> &IssuerKey {
        match self {
            Issuer::PrivateKeyAndCertificate(_, key, _)
            | Issuer::PrivateKeyAndSubjectName(_, key, _) => key,
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

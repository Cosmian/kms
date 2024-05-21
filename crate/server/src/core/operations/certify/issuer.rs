use cosmian_kmip::kmip::kmip_types::UniqueIdentifier;
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
pub enum Issuer {
    PrivateKeyAndCertificate(UniqueIdentifier, ObjectWithMetadata, ObjectWithMetadata),
}

impl Issuer {
    pub fn from_x509(
        unique_identifier: UniqueIdentifier,
        private_key: PKey<Private>,
        x509: X509,
    ) -> Self {
        Self {
            unique_identifier,
            private_key,
            subject_name: None,
            expiry_days: None,
            x509: Some(x509),
        }
    }

    pub fn from_subject_name_and_expiry_days(
        unique_identifier: UniqueIdentifier,
        private_key: PKey<Private>,
        subject_name: X509Name,
        expiry_days: usize,
    ) -> Self {
        Self {
            unique_identifier,
            private_key,
            subject_name: Some(subject_name),
            expiry_days: Some(expiry_days),
            x509: None,
        }
    }

    pub fn unique_identifier(&self) -> &UniqueIdentifier {
        &self.unique_identifier
    }

    pub fn private_key(&self) -> &PKeyRef<Private> {
        &self.private_key.as_ref()
    }

    pub fn subject_name(&self) -> KResult<&X509NameRef> {
        self.x509.as_ref().map_or_else(
            || {
                self.subject_name
                    .as_ref()
                    .map(|sn| sn.as_ref())
                    .context("Invalid Issuer Subect Name")
            },
            |x509| Ok(x509.subject_name()),
        )
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

use std::{
    collections::HashSet,
    fmt::{self, Display, Formatter},
};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::Object, kmip_types::UniqueIdentifier,
    },
    cosmian_kms_crypto::openssl::{kmip_public_key_to_openssl, openssl_certificate_extensions},
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use openssl::{
    pkey::{PKey, Public},
    x509::{X509, X509Extension, X509Name, X509NameRef, X509Req},
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::{kms_error, result::KResult};

/// This holds `KeyPair` information when one is created for the subject
pub(crate) struct KeyPairData {
    pub(crate) private_key_id: UniqueIdentifier,
    pub(crate) private_key_object: Object,
    pub(crate) private_key_tags: HashSet<String>,
    pub(crate) public_key_id: UniqueIdentifier,
    pub(crate) public_key_object: Object,
    pub(crate) public_key_tags: HashSet<String>,
}

impl Display for KeyPairData {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyPairData {{ private_key_id: {}, private_key_object: {}, private_key_tags: {:?}, \
             public_key_id: {}, public_key_object: {}, public_key_tags: {:?} }}",
            self.private_key_id,
            self.private_key_object,
            self.private_key_tags,
            self.public_key_id,
            self.public_key_object,
            self.public_key_tags
        )
    }
}

/// The party that gets signed by the issuer and gets the certificate
#[expect(clippy::large_enum_variant)]
pub(crate) enum Subject {
    X509Req(
        /// Unique identifier of the certificate to create
        UniqueIdentifier,
        /// Certificate request PKCS#10
        X509Req,
    ),
    Certificate(
        /// Unique identifier of the certificate to renew
        UniqueIdentifier,
        /// Certificate to renew
        X509,
        /// The attributes of the certificate to renew
        Attributes,
    ),
    PublicKeyAndSubjectName(
        /// Unique identifier of the certificate to create
        UniqueIdentifier,
        /// Public key of the certificate
        ObjectWithMetadata,
        /// Subject name of the certificate
        X509Name,
    ),
    KeypairAndSubjectName(
        /// Unique identifier of the certificate to create
        UniqueIdentifier,
        /// Generated `KeyPair` from which the certificate is created
        KeyPairData,
        /// Subject name of the certificate
        X509Name,
    ),
}

impl Subject {
    pub(crate) fn subject_name(&self) -> &X509NameRef {
        match self {
            Self::X509Req(_, req) => req.subject_name(),
            Self::Certificate(_, x509, _) => x509.subject_name(),
            Self::PublicKeyAndSubjectName(_, _owm, sn) => sn.as_ref(),
            Self::KeypairAndSubjectName(_, _keypair, sn) => sn.as_ref(),
        }
    }

    pub(crate) fn public_key(&self) -> KResult<PKey<Public>> {
        match self {
            Self::X509Req(_, req) => req
                .public_key()
                .map_err(|e| kms_error!("No public key: {e}")),
            Self::Certificate(_, x509, _) => x509
                .public_key()
                .map_err(|e| kms_error!("No public key: {e}")),
            Self::PublicKeyAndSubjectName(_, owm, _sn) => {
                kmip_public_key_to_openssl(owm.object()).map_err(Into::into)
            }
            Self::KeypairAndSubjectName(_, keypair, _sn) => {
                kmip_public_key_to_openssl(&keypair.public_key_object).map_err(Into::into)
            }
        }
    }

    pub(crate) fn extensions(&self) -> KResult<Vec<X509Extension>> {
        match self {
            Self::X509Req(_, req) => req
                .extensions()
                .map(|stack| stack.into_iter().collect::<Vec<_>>())
                .map_err(|e| kms_error!("No extensions: {e}")),
            Self::Certificate(_, x509, _) => {
                openssl_certificate_extensions(x509).map_err(Into::into)
            }
            _ => Ok(vec![]),
        }
    }

    /// Returns `true` when the subject already carries a `crlDistributionPoints` extension
    /// (OID `2.5.29.31`, DER bytes `55 1d 1f`).
    ///
    /// This prevents [`crate::core::operations::certify::build_certificate`] from injecting
    /// a duplicate CDP when re-certifying a certificate that was previously issued with one.
    pub(crate) fn has_crl_distribution_points(&self) -> bool {
        // OID 2.5.29.31 — id-ce-cRLDistributionPoints DER bytes
        const CDP_OID: &[u8] = &[0x55, 0x1d, 0x1f];
        match self {
            Self::Certificate(_, x509, _) => {
                let Ok(der) = x509.to_der() else { return false };
                let Ok((_, parsed)) = X509Certificate::from_der(&der) else {
                    return false;
                };
                parsed
                    .extensions()
                    .iter()
                    .any(|ext| ext.oid.as_bytes() == CDP_OID)
            }
            Self::X509Req(_, req) => {
                // CSR extensions live inside a requestedExtensions attribute
                req.extensions().is_ok_and(|stack| {
                    // Check if any extension OID matches id-ce-cRLDistributionPoints.
                    // We cannot inspect the OID bytes from openssl::x509::X509Extension
                    // directly, so we encode each extension to DER and search for the OID.
                    stack.iter().any(|ext| {
                        ext.to_der().is_ok_and(|der| {
                            // OID appears near the start; simple byte search suffices.
                            der.windows(CDP_OID.len()).any(|w| w == CDP_OID)
                        })
                    })
                })
            }
            _ => false,
        }
    }

    pub(crate) fn tags(&self, vendor_id: &str) -> HashSet<String> {
        match self {
            Self::Certificate(_, _, attributes) => attributes.get_tags(vendor_id),
            // It is an open question whether the tags from an existing public key should be
            // added to those of the certificate. For now, we return an empty set.
            _ => HashSet::new(),
        }
    }
}

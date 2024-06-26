use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_types::{Attributes, UniqueIdentifier},
    },
    openssl::{kmip_public_key_to_openssl, openssl_certificate_extensions},
};
use openssl::{
    pkey::{PKey, Public},
    x509::{X509Extension, X509Name, X509NameRef, X509Req, X509},
};

use crate::{database::object_with_metadata::ObjectWithMetadata, kms_error, result::KResult};

/// This holds `KeyPair` information when one is created for the subject
pub struct KeyPairData {
    pub(crate) private_key_id: UniqueIdentifier,
    pub(crate) private_key_object: Object,
    pub(crate) private_key_tags: HashSet<String>,
    pub(crate) public_key_id: UniqueIdentifier,
    pub(crate) public_key_object: Object,
    pub(crate) public_key_tags: HashSet<String>,
}

/// The party that gets signed by the issuer and gets the certificate
pub enum Subject {
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
    pub fn subject_name(&self) -> &X509NameRef {
        match self {
            Subject::X509Req(_, req) => req.subject_name(),
            Subject::Certificate(_, x509, _) => x509.subject_name(),
            Subject::PublicKeyAndSubjectName(_, _owm, sn) => sn.as_ref(),
            Subject::KeypairAndSubjectName(_, _keypair, sn) => sn.as_ref(),
        }
    }

    pub fn public_key(&self) -> KResult<PKey<Public>> {
        match self {
            Subject::X509Req(_, req) => req
                .public_key()
                .map_err(|e| kms_error!("No public key: {e}")),
            Subject::Certificate(_, x509, _) => x509
                .public_key()
                .map_err(|e| kms_error!("No public key: {e}")),
            Subject::PublicKeyAndSubjectName(_, owm, _sn) => {
                kmip_public_key_to_openssl(&owm.object).map_err(Into::into)
            }
            Subject::KeypairAndSubjectName(_, keypair, _sn) => {
                kmip_public_key_to_openssl(&keypair.public_key_object).map_err(Into::into)
            }
        }
    }

    pub fn extensions(&self) -> KResult<Vec<X509Extension>> {
        match self {
            Subject::X509Req(_, req) => req
                .extensions()
                .map(|stack| stack.into_iter().collect::<Vec<_>>())
                .map_err(|e| kms_error!("No extensions: {e}")),
            Subject::Certificate(_, x509, _) => {
                openssl_certificate_extensions(x509).map_err(Into::into)
            }
            _ => Ok(vec![]),
        }
    }

    pub fn tags(&self) -> HashSet<String> {
        match self {
            Subject::Certificate(_, _, attributes) => attributes.get_tags(),
            // It is an open question whether the tags from an existing public key should be
            // added to those of the certificate. For now, we return an empty set.
            _ => HashSet::new(),
        }
    }
}

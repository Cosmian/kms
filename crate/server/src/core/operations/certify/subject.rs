use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{kmip_objects::Object, kmip_types::UniqueIdentifier},
    openssl::{
        kmip_certificate_to_openssl, kmip_public_key_to_openssl, openssl_certificate_extensions,
    },
};
use openssl::{
    pkey::{PKeyRef, Public},
    x509::{X509Extension, X509Name, X509NameRef, X509Req},
};

use crate::{
    database::object_with_metadata::ObjectWithMetadata, kms_bail, kms_error, result::KResult,
};

/// This holds KeyPair information when one is created for the subject
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
        ObjectWithMetadata,
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
        /// Generated KeyPair from which the certificate is created
        KeyPairData,
        /// Subject name of the certificate
        X509Name,
    ),
}

impl Subject {
    pub fn unique_identifier(&self) -> &UniqueIdentifier {
        match self {
            Subject::X509Req(uid, _) => uid,
            Subject::Certificate(uid, _) => uid,
            Subject::PublicKeyAndSubjectName(uid, _, _) => uid,
            Subject::KeypairAndSubjectName(uid, _, _) => uid,
        }
    }

    pub fn subject_name(&self) -> KResult<&X509NameRef> {
        match self {
            Subject::X509Req(_uid, req) => Ok(req.subject_name()),
            Subject::Certificate(_uid, owm) => {
                Ok(kmip_certificate_to_openssl(&owm.object)?.subject_name())
            }
            Subject::PublicKeyAndSubjectName(_uid, _owm, sn) => Ok(sn.as_ref()),
            Subject::KeypairAndSubjectName(_uid, _keypair, sn) => Ok(sn.as_ref()),
        }
    }

    pub fn public_key(&self) -> KResult<&PKeyRef<Public>> {
        match self {
            Subject::X509Req(_uid, req) => req
                .public_key()
                .map_or_else(|e| kms_bail!("No public key: {e}"), |key| Ok(key.as_ref())),
            Subject::Certificate(_uid, owm) => kmip_certificate_to_openssl(&owm.object)?
                .public_key()
                .map_or_else(|e| kms_bail!("No public key: {e}"), |key| Ok(key.as_ref())),
            Subject::PublicKeyAndSubjectName(_uid, owm, _sn) => {
                kmip_public_key_to_openssl(&owm.object)
                    .map(|p_key| p_key.as_ref())
                    .map_err(Into::into)
            }
            Subject::KeypairAndSubjectName(_uid, keypair, _sn) => {
                kmip_public_key_to_openssl(&keypair.public_key_object)
                    .map(|p_key| p_key.as_ref())
                    .map_err(Into::into)
            }
        }
    }

    pub fn extensions(&self) -> KResult<Vec<X509Extension>> {
        match self {
            Subject::X509Req(_uid, req) => req
                .extensions()
                .map(|stack| stack.into_iter().collect::<Vec<_>>())
                .map_err(|e| kms_error!("No extensions: {e}")),
            Subject::Certificate(_uid, owm) => {
                openssl_certificate_extensions(&kmip_certificate_to_openssl(&owm.object)?)
                    .map_err(Into::into)
            }
            _ => Ok(vec![]),
        }
    }

    pub fn tags(&self) -> HashSet<String> {
        match self {
            Subject::Certificate(_uid, owm) => owm.attributes.get_tags(),
            // It is an open question whether the tags form an existing public key should be
            // added to those of the certificate. For now, we return an empty set.
            _ => HashSet::new(),
        }
    }
}

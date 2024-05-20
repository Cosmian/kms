use std::collections::HashSet;

use cosmian_kmip::{
    crypto::KeyPair,
    kmip::kmip_types::UniqueIdentifier,
    openssl::{kmip_public_key_to_openssl, openssl_certificate_extensions},
};
use openssl::{
    pkey::{PKey, PKeyRef, Public},
    x509::{X509Extension, X509Name, X509NameRef, X509Req, X509},
};

use crate::{kms_bail, kms_error, result::KResult};

/// The party that gets signed by the issuer and gets the certificate
pub struct Subject {
    unique_identifier: UniqueIdentifier,
    x509_req: Option<X509Req>,
    x509: Option<X509>,
    subject_name: Option<X509Name>,
    public_key: Option<PKey<Public>>,
    extensions: Vec<X509Extension>,
    key_pair: Option<(KeyPair, HashSet<String>, HashSet<String>)>,
}

impl Subject {
    pub fn from_x509_req(unique_identifier: UniqueIdentifier, req: X509Req) -> Self {
        Self {
            unique_identifier,
            x509_req: Some(req),
            x509: None,
            subject_name: None,
            public_key: None,
            extensions: vec![],
            key_pair: None,
        }
    }

    pub fn from_x509(unique_identifier: UniqueIdentifier, x509: X509) -> Self {
        Self {
            unique_identifier,
            x509: Some(x509),
            x509_req: None,
            subject_name: None,
            public_key: None,
            extensions: vec![],
            key_pair: None,
        }
    }

    pub fn from_subject_name_and_public_key(
        unique_identifier: UniqueIdentifier,
        subject_name: X509Name,
        public_key: PKey<Public>,
    ) -> Self {
        Self {
            unique_identifier,
            x509_req: None,
            x509: None,
            subject_name: Some(subject_name),
            public_key: Some(public_key),
            extensions: vec![],
            key_pair: None,
        }
    }

    pub fn from_subject_name_and_key_pair(
        unique_identifier: UniqueIdentifier,
        subject_name: X509Name,
        key_pair: KeyPair,
        secret_key_tags: HashSet<String>,
        public_key_tags: HashSet<String>,
    ) -> Self {
        Self {
            unique_identifier,
            x509_req: None,
            x509: None,
            subject_name: Some(subject_name),
            public_key: None,
            extensions: vec![],
            key_pair: Some((key_pair, secret_key_tags, public_key_tags)),
        }
    }

    pub fn subject_name(&self) -> KResult<&X509NameRef> {
        self.x509.as_ref().map_or_else(
            || {
                self.x509_req.as_ref().map_or_else(
                    || {
                        self.subject_name
                            .as_ref()
                            .map_or_else(|| kms_bail!("No subject name"), |name| Ok(name.as_ref()))
                    },
                    |req| Ok(req.subject_name()),
                )
            },
            |cert| Ok(cert.subject_name()),
        )
    }

    pub fn public_key(&self) -> KResult<&PKeyRef<Public>> {
        self.x509.as_ref().map_or_else(
            || {
                self.x509_req.as_ref().map_or_else(
                    || {
                        self.public_key.as_ref().map_or_else(
                            || {
                                self.key_pair.as_ref().map_or_else(
                                    || kms_bail!("No public key"),
                                    |(key_pair, _, _)| {
                                        let p_key =
                                            kmip_public_key_to_openssl(key_pair.public_key())?;
                                        Ok(p_key.as_ref())
                                    },
                                )
                            },
                            |key| Ok(key.as_ref()),
                        )
                    },
                    |req| {
                        req.public_key().map_or_else(
                            |e| kms_bail!("No public key: {e}"),
                            |key| Ok(key.as_ref()),
                        )
                    },
                )
            },
            |cert| Ok(cert.public_key()?.as_ref()),
        )
    }

    pub fn extensions(&self) -> KResult<&[X509Extension]> {
        self.x509.as_ref().map_or_else(
            || {
                self.x509_req.as_ref().map_or_else(
                    || Ok(self.extensions.as_ref()),
                    |req| {
                        req.extensions()
                            .map(|stack| stack.into_iter().collect::<Vec<_>>().as_ref())
                            .map_err(|e| kms_error!("No extensions: {e}"))
                    },
                )
            },
            |cert| {
                openssl_certificate_extensions(cert)
                    .map(|exts| exts.as_ref())
                    .map_err(Into::into)
            },
        )
    }
}

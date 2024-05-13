use openssl::{
    pkey::{PKey, PKeyRef, Private, Public},
    x509::{X509Extension, X509Name, X509NameRef, X509Req, X509},
};

use crate::{kms_bail, result::KResult};

/// The party that gets signed by the issuer and gets the certificate
#[derive(Default)]
pub struct Subject {
    x509_req: Option<X509Req>,
    x509: Option<X509>,
    subject_name: Option<X509Name>,
    public_key: Option<PKey<Public>>,
    private_key: Option<PKey<Private>>,
    extensions: Option<Vec<X509Extension>>,
}

impl Subject {
    pub fn from_x509_req(req: X509Req) -> Self {
        Self {
            x509_req: Some(req),
            ..Default::default()
        }
    }

    pub fn from_x509(x509: X509) -> Self {
        Self {
            x509: Some(x509),
            ..Default::default()
        }
    }

    pub fn from_subject_name_and_public_key(
        subject_name: X509Name,
        public_key: PKey<Public>,
        private_key: Option<PKey<Private>>,
        extensions: Option<Vec<X509Extension>>,
    ) -> Self {
        Self {
            x509_req: None,
            x509: None,
            subject_name: Some(subject_name),
            public_key: Some(public_key),
            private_key,
            extensions,
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
                        self.public_key
                            .as_ref()
                            .map_or_else(|| kms_bail!("No public key"), |key| Ok(key.as_ref()))
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

    pub fn extensions(&self) -> KResult<Option<&[X509Extension]>> {
        Ok(self.extensions.as_ref().map(|exts| exts.as_slice()))
    }
}

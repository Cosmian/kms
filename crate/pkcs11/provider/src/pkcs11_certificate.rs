use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::CertificateType};
use cosmian_pkcs11_module::traits::{Certificate, PublicKey};
use x509_cert::{
    der::{Decode, Encode},
    Certificate as X509Certificate,
};

use crate::{error::Pkcs11Error, kms_object::KmsObject};

/// A PKCS11 Certificate is a Certificate that wraps data from a KMS object
#[derive(Debug)]
pub(crate) struct Pkcs11Certificate {
    pub certificate: X509Certificate,
    pub label: String,
}

impl TryFrom<KmsObject> for Pkcs11Certificate {
    type Error = Pkcs11Error;

    fn try_from(kms_object: KmsObject) -> Result<Self, Self::Error> {
        match kms_object.object {
            Object::Certificate {
                certificate_type,
                certificate_value,
                ..
            } => match certificate_type {
                CertificateType::X509 => Ok(Self {
                    certificate: X509Certificate::from_der(&certificate_value).map_err(|e| {
                        Pkcs11Error::ServerError(format!(
                            "Invalid X509 Certificate DER bytes: {e:?}"
                        ))
                    })?,
                    label: kms_object.other_tags.join(","),
                }),
                CertificateType::PGP | CertificateType::PKCS7 => Err(Pkcs11Error::ServerError(
                    format!("Invalid Certificate Type: {certificate_type:?}"),
                )),
            },
            o => Err(Pkcs11Error::ServerError(format!(
                "Invalid KMS Object for a certificate: {o}"
            ))),
        }
    }
}

impl Certificate for Pkcs11Certificate {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn to_der(&self) -> cosmian_pkcs11_module::MResult<Vec<u8>> {
        self.certificate
            .to_der()
            .map_err(|e| Pkcs11Error::from(e).into())
    }

    fn public_key(&self) -> &dyn PublicKey {
        todo!("implement get public key got certificate")
    }

    fn issuer(&self) -> cosmian_pkcs11_module::MResult<Vec<u8>> {
        Encode::to_der(&self.certificate.tbs_certificate.issuer)
            .map_err(|e| Pkcs11Error::from(e).into())
    }

    fn serial_number(&self) -> cosmian_pkcs11_module::MResult<Vec<u8>> {
        Encode::to_der(&self.certificate.tbs_certificate.serial_number)
            .map_err(|e| Pkcs11Error::from(e).into())
    }

    fn subject(&self) -> cosmian_pkcs11_module::MResult<Vec<u8>> {
        Encode::to_der(&self.certificate.tbs_certificate.subject)
            .map_err(|e| Pkcs11Error::from(e).into())
    }
}

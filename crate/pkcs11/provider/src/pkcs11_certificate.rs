use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{CertificateType, LinkType},
};
use cosmian_pkcs11_module::traits::{Certificate, PublicKey};
use x509_cert::{
    der::{Decode, Encode},
    Certificate as X509Certificate,
};

use crate::{error::Pkcs11Error, kms_object::KmsObject, pkcs11_public_key::Pkcs11PublicKey};

/// A PKCS11 Certificate is a Certificate that wraps data from a KMS object
#[derive(Debug)]
pub struct Pkcs11Certificate {
    /// The remote id
    pub remote_id: String,
    /// The certificate
    pub certificate: X509Certificate,
    /// The private key ID
    /// This is the CKA_ID of the private key associated with the certificate
    pub private_key_id: String,
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
                    remote_id: kms_object.remote_id.clone(),
                    private_key_id: kms_object
                        .attributes
                        .get_link(LinkType::PrivateKeyLink)
                        .ok_or_else(|| {
                            Pkcs11Error::ServerError(format!(
                                "No private key link found for certificate: {:?}",
                                kms_object.remote_id
                            ))
                        })?
                        .to_string(),
                }),
                _ => Err(Pkcs11Error::ServerError(format!(
                    "Invalid Certificate Type: {certificate_type:?}"
                ))),
            },
            o => Err(Pkcs11Error::ServerError(format!(
                "Invalid KMS Object for a certificate: {o:?}"
            ))),
        }
    }
}

impl Certificate for Pkcs11Certificate {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn to_der(&self) -> cosmian_pkcs11_module::MResult<Vec<u8>> {
        self.certificate
            .to_der()
            .map_err(|e| Pkcs11Error::from(e).into())
    }

    fn public_key(&self) -> cosmian_pkcs11_module::MResult<Box<dyn PublicKey>> {
        Pkcs11PublicKey::try_from_spki(&self.certificate.tbs_certificate.subject_public_key_info)
            .map_err(|e| Pkcs11Error::from(e).into())
            .map(|pk| Box::new(pk) as Box<dyn PublicKey>)
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

    fn private_key_id(&self) -> String {
        self.private_key_id.clone()
    }
}

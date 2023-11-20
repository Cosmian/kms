use openssl::x509::X509;

use crate::{
    error::KmipError,
    id,
    kmip::{
        kmip_objects::{Object, Object::Certificate},
        kmip_types::CertificateType,
    },
};

/// Generate a KMIP certificate from an OpenSSL certificate and a unique ID
pub fn openssl_certificate_to_kmip(certificate: X509) -> Result<(String, Object), KmipError> {
    let der_bytes = certificate.to_der()?;
    Ok((
        id(&der_bytes)?,
        Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der_bytes,
        },
    ))
}

pub fn kmip_certificate_to_openssl(certificate: &Object) -> Result<X509, KmipError> {
    match certificate {
        Certificate {
            certificate_value, ..
        } => X509::from_der(certificate_value).map_err(|e| {
            KmipError::InvalidKmipValue(
                crate::kmip::kmip_operations::ErrorReason::Invalid_Attribute_Value,
                format!("failed to parse certificate: {}", e),
            )
        }),
        _ => Err(KmipError::InvalidKmipValue(
            crate::kmip::kmip_operations::ErrorReason::Invalid_Attribute_Value,
            "expected a certificate".to_string(),
        )),
    }
}

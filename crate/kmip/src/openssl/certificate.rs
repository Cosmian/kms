use openssl::{
    nid::Nid,
    x509::{X509Name, X509NameBuilder, X509},
};

use crate::{
    error::KmipError,
    id,
    kmip::{
        kmip_objects::{Object, Object::Certificate},
        kmip_types::{CertificateAttributes, CertificateType},
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

impl CertificateAttributes {
    pub fn build_subject_name(&self) -> Result<X509Name, KmipError> {
        let mut builder = X509NameBuilder::new()?;
        builder.append_entry_by_nid(Nid::COMMONNAME, &*self.certificate_subject_cn)?;
        builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &*self.certificate_subject_ou)?;
        builder.append_entry_by_nid(Nid::COUNTRYNAME, &*self.certificate_subject_c)?;
        builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, &*self.certificate_subject_st)?;
        builder.append_entry_by_nid(Nid::LOCALITYNAME, &*self.certificate_subject_l)?;
        builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &*self.certificate_subject_o)?;
        builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, &*self.certificate_subject_email)?;
        Ok(builder.build())
    }
}

// builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, "Dis")?;

// builder.append_entry_by_nid(Nid::COUNTRYNAME, "US")?;
// builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, "Denial")?;
// builder.append_entry_by_nid(Nid::LOCALITYNAME, "Springfield")?;
// builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Dis")?;

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
    result::KmipResultHelper,
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
                format!("failed to parse certificate: {e}"),
            )
        }),
        _ => Err(KmipError::InvalidKmipValue(
            crate::kmip::kmip_operations::ErrorReason::Invalid_Attribute_Value,
            "expected a certificate".to_string(),
        )),
    }
}

impl CertificateAttributes {
    /// Get the OpenSSL `X509Name` for the subject
    pub fn subject_name(&self) -> Result<X509Name, KmipError> {
        let mut builder = X509NameBuilder::new()?;
        if !self.certificate_subject_cn.is_empty() {
            builder
                .append_entry_by_nid(Nid::COMMONNAME, &self.certificate_subject_cn)
                .context("invalid common name")?;
        }
        if !self.certificate_subject_ou.is_empty() {
            builder
                .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &self.certificate_subject_ou)
                .context("invalid organizational unit")?;
        }
        if !self.certificate_subject_c.is_empty() {
            builder
                .append_entry_by_nid(Nid::COUNTRYNAME, &self.certificate_subject_c)
                .context("invalid country name")?;
        }
        if !self.certificate_subject_st.is_empty() {
            builder
                .append_entry_by_nid(Nid::STATEORPROVINCENAME, &self.certificate_subject_st)
                .context("invalid state or province")?;
        }
        if !self.certificate_subject_l.is_empty() {
            builder
                .append_entry_by_nid(Nid::LOCALITYNAME, &self.certificate_subject_l)
                .context("invalid locality")?;
        }
        if !self.certificate_subject_o.is_empty() {
            builder
                .append_entry_by_nid(Nid::ORGANIZATIONNAME, &self.certificate_subject_o)
                .context("invalid organization")?;
        }
        if !self.certificate_subject_email.is_empty() {
            builder
                .append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, &self.certificate_subject_email)
                .context("invalid email")?;
        }
        Ok(builder.build())
    }
}

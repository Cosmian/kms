use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object::{self, Certificate},
    kmip_types::{CertificateAttributes, CertificateType},
};
use openssl::{
    asn1::{Asn1Object, Asn1OctetString},
    nid::Nid,
    sha::Sha1,
    x509::{X509, X509Extension, X509Name, X509NameBuilder},
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::error::{CryptoError, result::CryptoResultHelper};

/// Generate a KMIP certificate from an OpenSSL certificate
pub fn openssl_certificate_to_kmip(certificate: &X509) -> Result<Object, CryptoError> {
    let der_bytes = certificate.to_der()?;
    Ok(Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: der_bytes,
    })
}

pub fn kmip_certificate_to_openssl(certificate: &Object) -> Result<X509, CryptoError> {
    match certificate {
        Certificate {
            certificate_value, ..
        } => X509::from_der(certificate_value)
            .map_err(|e| CryptoError::Kmip(format!("failed to parse certificate: {e}"))),
        _ => Err(CryptoError::Kmip("expected a certificate".to_owned())),
    }
}

/// Extract the `X509Extensions` of an openssl X509 certificate
/// This is still an open issue in the openssl crate: <https://github.com/sfackler/rust-openssl/pull/1095>
/// (The PR was closed)
/// If this is ever fixed, this method should be replaced by the one in the openssl crate
pub fn openssl_certificate_extensions(
    certificate: &X509,
) -> Result<Vec<X509Extension>, CryptoError> {
    let der_bytes = certificate.to_der()?;
    let (_, certificate) = X509Certificate::from_der(der_bytes.as_slice())
        .map_err(|e| CryptoError::Kmip(format!("failed to parse certificate: {e}")))?;
    certificate
        .iter_extensions()
        .map(|ext| {
            let oid = Asn1Object::from_str(ext.oid.to_string().as_str())?;
            let value = Asn1OctetString::new_from_bytes(ext.value)?;
            X509Extension::new_from_der(oid.as_ref(), ext.critical, value.as_ref())
                .map_err(Into::into)
        })
        .collect()
}

#[must_use]
pub fn openssl_x509_to_certificate_attributes(x509: &X509) -> CertificateAttributes {
    let mut attributes = CertificateAttributes::default();
    for entry in x509.subject_name().entries() {
        match entry.object().nid() {
            Nid::COMMONNAME => {
                if let Ok(cn) = entry.data().as_utf8() {
                    attributes.certificate_subject_cn = cn.to_string();
                }
            }
            Nid::ORGANIZATIONALUNITNAME => {
                if let Ok(ou) = entry.data().as_utf8() {
                    attributes.certificate_subject_ou = ou.to_string();
                }
            }
            Nid::COUNTRYNAME => {
                if let Ok(country) = entry.data().as_utf8() {
                    attributes.certificate_subject_c = country.to_string();
                }
            }
            Nid::STATEORPROVINCENAME => {
                if let Ok(st) = entry.data().as_utf8() {
                    attributes.certificate_subject_st = st.to_string();
                }
            }
            Nid::LOCALITYNAME => {
                if let Ok(l) = entry.data().as_utf8() {
                    attributes.certificate_subject_l = l.to_string();
                }
            }
            Nid::ORGANIZATIONNAME => {
                if let Ok(o) = entry.data().as_utf8() {
                    attributes.certificate_subject_o = o.to_string();
                }
            }
            Nid::PKCS9_EMAILADDRESS => {
                if let Ok(email) = entry.data().as_utf8() {
                    attributes.certificate_subject_email = email.to_string();
                }
            }
            _ => (),
        }
    }
    if let Ok(serial_number) = x509.serial_number().to_bn() {
        if let Ok(serial_number) = serial_number.to_hex_str() {
            attributes.certificate_subject_serial_number = serial_number.to_string();
        }
    }

    // add the SPKI tag corresponding to the `SubjectKeyIdentifier` X509 extension
    if let Ok(spki) = get_or_create_subject_key_identifier_value(x509) {
        attributes.certificate_subject_uid = hex::encode(spki);
    }

    for entry in x509.issuer_name().entries() {
        match entry.object().nid() {
            Nid::COMMONNAME => {
                if let Ok(cn) = entry.data().as_utf8() {
                    attributes.certificate_issuer_cn = cn.to_string();
                }
            }
            Nid::ORGANIZATIONALUNITNAME => {
                if let Ok(ou) = entry.data().as_utf8() {
                    attributes.certificate_issuer_ou = ou.to_string();
                }
            }
            Nid::COUNTRYNAME => {
                if let Ok(country) = entry.data().as_utf8() {
                    attributes.certificate_issuer_c = country.to_string();
                }
            }
            Nid::STATEORPROVINCENAME => {
                if let Ok(st) = entry.data().as_utf8() {
                    attributes.certificate_issuer_st = st.to_string();
                }
            }
            Nid::LOCALITYNAME => {
                if let Ok(l) = entry.data().as_utf8() {
                    attributes.certificate_issuer_l = l.to_string();
                }
            }
            Nid::ORGANIZATIONNAME => {
                if let Ok(o) = entry.data().as_utf8() {
                    attributes.certificate_issuer_o = o.to_string();
                }
            }
            Nid::PKCS9_EMAILADDRESS => {
                if let Ok(email) = entry.data().as_utf8() {
                    attributes.certificate_issuer_email = email.to_string();
                }
            }
            _ => (),
        }
    }
    attributes
}

/// Get the OpenSSL `X509Name` for the subject
pub fn certificate_attributes_to_subject_name(
    attributes: &CertificateAttributes,
) -> Result<X509Name, CryptoError> {
    let mut builder = X509NameBuilder::new()?;
    if !attributes.certificate_subject_cn.is_empty() {
        builder
            .append_entry_by_nid(Nid::COMMONNAME, &attributes.certificate_subject_cn)
            .context("invalid common name")?;
    }
    if !attributes.certificate_subject_ou.is_empty() {
        builder
            .append_entry_by_nid(
                Nid::ORGANIZATIONALUNITNAME,
                &attributes.certificate_subject_ou,
            )
            .context("invalid organizational unit")?;
    }
    if !attributes.certificate_subject_c.is_empty() {
        builder
            .append_entry_by_nid(Nid::COUNTRYNAME, &attributes.certificate_subject_c)
            .context("invalid country name")?;
    }
    if !attributes.certificate_subject_st.is_empty() {
        builder
            .append_entry_by_nid(Nid::STATEORPROVINCENAME, &attributes.certificate_subject_st)
            .context("invalid state or province")?;
    }
    if !attributes.certificate_subject_l.is_empty() {
        builder
            .append_entry_by_nid(Nid::LOCALITYNAME, &attributes.certificate_subject_l)
            .context("invalid locality")?;
    }
    if !attributes.certificate_subject_o.is_empty() {
        builder
            .append_entry_by_nid(Nid::ORGANIZATIONNAME, &attributes.certificate_subject_o)
            .context("invalid organization")?;
    }
    if !attributes.certificate_subject_email.is_empty() {
        builder
            .append_entry_by_nid(
                Nid::PKCS9_EMAILADDRESS,
                &attributes.certificate_subject_email,
            )
            .context("invalid email")?;
    }
    Ok(builder.build())
}

/// Get the `SubjectKeyIdentifier` X509 extension value
/// If it is not available, it is
/// calculated according to RFC 5280 section 4.2.1.2
fn get_or_create_subject_key_identifier_value(certificate: &X509) -> Result<Vec<u8>, CryptoError> {
    Ok(if let Some(ski) = certificate.subject_key_id() {
        ski.as_slice().to_vec()
    } else {
        let pk = certificate.public_key()?;
        let spki_der = pk.public_key_to_der()?;
        let mut sha1 = Sha1::default();
        sha1.update(&spki_der);
        sha1.finish().to_vec()
    })
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use crate::openssl::certificate::openssl_x509_to_certificate_attributes;

    #[test]
    fn test_parsing_certificate_attributes() {
        use std::{fs::File, io::Read};

        let mut buffer = Vec::new();
        let pem_filepath = "../../test_data/certificates/openssl/rsa-4096-cert.pem";
        File::open(pem_filepath)
            .unwrap()
            .read_to_end(&mut buffer)
            .unwrap();
        let cert = openssl::x509::X509::from_pem(&buffer).unwrap();
        let certificate_attributes = openssl_x509_to_certificate_attributes(&cert);
        // Issuer: C = US, ST = Denial, L = Springfield, O = Dis, CN = www.RSA-4096-example.com
        // Validity
        //     Not Before: Oct  2 13:51:50 2023 GMT
        //     Not After : Oct  1 13:51:50 2024 GMT
        // Subject: C = US, ST = Denial, L = Springfield, O = Dis, CN = www.RSA-4096-example.com
        // ----> Check subject name
        assert_eq!(
            certificate_attributes.certificate_subject_c,
            "US".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_subject_st,
            "Denial".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_subject_l,
            "Springfield".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_subject_o,
            "Dis".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_subject_cn,
            "www.RSA-4096-example.com".to_owned()
        );

        // ----> Check issuer name
        assert_eq!(certificate_attributes.certificate_issuer_c, "US".to_owned());
        assert_eq!(
            certificate_attributes.certificate_issuer_st,
            "Denial".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_issuer_l,
            "Springfield".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_issuer_o,
            "Dis".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_issuer_cn,
            "www.RSA-4096-example.com".to_owned()
        );

        // ----> Check SPKI
        assert_eq!(
            certificate_attributes.certificate_subject_uid,
            "33a90ad71894709603a677775d0b902edcd9eaeb".to_owned()
        );
        assert_eq!(
            certificate_attributes.certificate_subject_serial_number,
            "715437E16BFD2371DB5074169C3EE44E30EEB88C".to_owned()
        );
    }
}

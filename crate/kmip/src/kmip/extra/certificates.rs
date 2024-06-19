use crate::{
    error::KmipError,
    kmip::{
        extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
        kmip_operations::ErrorReason,
        kmip_types::Attributes,
    },
};

const VENDOR_ATTR_REQUESTED_VALIDITY_DAYS: &str = "requested_validity_days";

impl Attributes {
    /// Set the requested validity days
    pub fn set_requested_validity_days(&mut self, requested_validity_days: usize) -> &mut Self {
        self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            VENDOR_ATTR_REQUESTED_VALIDITY_DAYS,
            requested_validity_days.to_string().as_bytes().to_vec(),
        )
    }

    /// Extract the requested validity days
    pub fn extract_requested_validity_days(&mut self) -> Result<Option<usize>, KmipError> {
        let bytes = self
            .extract_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_REQUESTED_VALIDITY_DAYS);
        let validity_days = bytes
            .map(|value| {
                String::from_utf8(value)
                    .map_err(|e| {
                        KmipError::InvalidKmipValue(ErrorReason::Codec_Error, e.to_string())
                    })
                    .and_then(|s| {
                        s.parse::<usize>().map_err(|e| {
                            KmipError::InvalidKmipValue(ErrorReason::Codec_Error, e.to_string())
                        })
                    })
            })
            .transpose()?;
        Ok(validity_days)
    }

    /// Set an X509 extensions file containing a `v3_ca` parag.
    pub fn set_x509_extension_file(&mut self, x509_extension_file: Vec<u8>) -> &mut Self {
        self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            VENDOR_ATTR_X509_EXTENSION,
            x509_extension_file,
        )
    }

    pub fn set_x509_extension_authority_key_identifier(&mut self, aki: String) -> &mut Self {
        self.set_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION, {
            let attr = "authorityKeyIdentifier=".to_string();
            attr.to_string().push_str(aki.as_str());
            attr.as_bytes().to_vec()
        })
    }

    pub fn set_x509_extension_subject_key_identifier(&mut self, ski: String) -> &mut Self {
        self.set_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION, {
            let attr = "subjectKeyIdentifier=".to_string();
            attr.to_string().push_str(ski.as_str());
            attr.as_bytes().to_vec()
        })
    }
}

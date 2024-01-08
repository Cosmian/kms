use crate::{
    error::KmipError,
    kmip::{
        extra::{VENDOR_ID_COSMIAN, VENDOR_ID_X509_EXTENSION},
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

    pub fn append_x509_extension(
        &mut self,
        x509_extension_name: &str,
        x509_extension: openssl::x509::X509Extension,
    ) -> &mut Self {
        self.set_vendor_attribute(
            VENDOR_ID_X509_EXTENSION,
            x509_extension_name,
            x509_extension.to_der().unwrap(),
        )
    }
}

use crate::kmip_2_1::{
    extra::{VENDOR_ATTR_X509_EXTENSION, VENDOR_ID_COSMIAN},
    kmip_attributes::Attributes,
    kmip_types::VendorAttributeValue,
};

const VENDOR_ATTR_REQUESTED_VALIDITY_DAYS: &str = "requested_validity_days";

impl Attributes {
    /// Set the requested validity days
    /// This is the number of days the certificate will be valid for
    /// The requested validity days is stored as a vendor attribute
    ///
    /// # Arguments
    /// * `requested_validity_days` - The requested validity days to set
    ///
    /// # Returns
    /// * The requested validity days if it was set before
    pub fn set_requested_validity_days(&mut self, requested_validity_days: i32) -> Option<i32> {
        let val = self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            VENDOR_ATTR_REQUESTED_VALIDITY_DAYS,
            VendorAttributeValue::Integer(requested_validity_days),
        )?;
        if let VendorAttributeValue::Integer(val) = val {
            Some(val)
        } else {
            None
        }
    }

    /// Extract the requested validity days
    ///
    /// # Returns
    /// * The requested validity days if it was set before
    /// * `None` if it was not set
    pub fn remove_validity_days(&mut self) -> Option<i32> {
        let val =
            self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_REQUESTED_VALIDITY_DAYS)?;
        if let VendorAttributeValue::Integer(val) = val {
            Some(val)
        } else {
            None
        }
    }

    /// Set an X509 extensions file containing a `v3_ca` parag.
    ///
    /// # Arguments
    /// * `x509_extension_file` - The X509 extensions file to set
    ///
    /// # Returns
    /// * The X509 extensions file if it was set before
    /// * `None` if it was not set
    pub fn set_x509_extension_file(&mut self, x509_extension_file: Vec<u8>) -> Option<Vec<u8>> {
        let val = self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            VENDOR_ATTR_X509_EXTENSION,
            VendorAttributeValue::ByteString(x509_extension_file),
        )?;
        if let VendorAttributeValue::ByteString(val) = val {
            Some(val)
        } else {
            None
        }
    }

    /// Extract the X509 extensions file
    ///
    /// # Returns
    /// * The X509 extensions file if it was set before
    /// * `None` if it was not set
    pub fn remove_x509_extension_file(&mut self) -> Option<Vec<u8>> {
        let val = self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_X509_EXTENSION)?;
        if let VendorAttributeValue::ByteString(val) = val {
            Some(val)
        } else {
            None
        }
    }
}

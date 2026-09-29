use std::convert::TryFrom;

use cosmian_kmip::kmip_2_1::{
    extra::tagging::VENDOR_ID_COSMIAN,
    kmip_attributes::Attributes,
    kmip_types::{VendorAttribute, VendorAttributeValue},
};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;

const ENCLAVE_SHARED_KEY_ATTR_NAME: &str = "enclave_shared_key_create_request";

#[derive(Serialize, Deserialize, Debug)]
pub struct EnclaveSharedKeyCreateRequest {
    pub algo_provider_public_key_uid: String,
    pub algo_provider_secret_key_uid: String,
    pub data_provider_public_key_uid: String,
}

impl EnclaveSharedKeyCreateRequest {
    /// Convert to a `VendorAttribute` using the given vendor identification.
    pub fn to_vendor_attribute(&self, vendor_id: &str) -> Result<VendorAttribute, CryptoError> {
        Ok(VendorAttribute {
            vendor_identification: vendor_id.to_owned(),
            attribute_name: ENCLAVE_SHARED_KEY_ATTR_NAME.to_owned(),
            attribute_value: VendorAttributeValue::ByteString(serde_json::to_vec(self).map_err(
                |e| {
                    CryptoError::Kmip(format!(
                        "failed serializing the shared key setup value. Error: {e:?}"
                    ))
                },
            )?),
        })
    }

    /// Extract from `Attributes` using the given vendor identification.
    pub fn from_attributes(vendor_id: &str, attributes: &Attributes) -> Result<Self, CryptoError> {
        let vdr = attributes.vendor_attributes.as_ref().ok_or_else(|| {
            CryptoError::Kmip(
                "the attributes do not contain any vendor attribute, hence no shared key setup \
                 data"
                    .to_owned(),
            )
        })?;

        let va = vdr
            .iter()
            .find(|att| {
                att.attribute_name == ENCLAVE_SHARED_KEY_ATTR_NAME
                    && att.vendor_identification == vendor_id
            })
            .ok_or_else(|| {
                CryptoError::Kmip(
                    "the attributes do not contain any vendor attribute, hence no shared key \
                     setup data"
                        .to_owned(),
                )
            })?;
        Self::try_from(va)
    }
}

/// Create enclave `VendorAttribute` to set in a `CreateRequest` for a DH shared
/// Key (uses "cosmian" as vendor identification for backward compatibility)
impl TryFrom<&EnclaveSharedKeyCreateRequest> for VendorAttribute {
    type Error = CryptoError;

    fn try_from(request: &EnclaveSharedKeyCreateRequest) -> Result<Self, CryptoError> {
        request.to_vendor_attribute(VENDOR_ID_COSMIAN)
    }
}

impl TryFrom<&VendorAttribute> for EnclaveSharedKeyCreateRequest {
    type Error = CryptoError;

    fn try_from(attribute: &VendorAttribute) -> Result<Self, CryptoError> {
        if attribute.attribute_name != *ENCLAVE_SHARED_KEY_ATTR_NAME {
            return Err(CryptoError::Kmip(
                "the attributes in not a shared key create request".to_owned(),
            ));
        }
        let VendorAttributeValue::ByteString(value) = &attribute.attribute_value else {
            return Err(CryptoError::Kmip(
                "the attributes in not a shared key create request".to_owned(),
            ));
        };
        serde_json::from_slice::<Self>(value).map_err(|e| {
            CryptoError::Kmip(format!(
                "failed deserializing the Shared Key Create Request. Error: {e:?}"
            ))
        })
    }
}

impl TryFrom<&Attributes> for EnclaveSharedKeyCreateRequest {
    type Error = CryptoError;

    fn try_from(attributes: &Attributes) -> Result<Self, CryptoError> {
        Self::from_attributes(VENDOR_ID_COSMIAN, attributes)
    }
}

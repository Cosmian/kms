use std::convert::TryFrom;

use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_attributes::Attributes,
    kmip_types::{VendorAttribute, VendorAttributeValue},
};
use serde::{Deserialize, Serialize};

use crate::error::CryptoError;

#[derive(Serialize, Deserialize, Debug)]
pub struct EnclaveSharedKeyCreateRequest {
    pub algo_provider_public_key_uid: String,
    pub algo_provider_secret_key_uid: String,
    pub data_provider_public_key_uid: String,
}

/// Create enclave `VendorAttribute` to set in a `CreateRequest` for a DH shared
/// Key
impl TryFrom<&EnclaveSharedKeyCreateRequest> for VendorAttribute {
    type Error = CryptoError;

    fn try_from(request: &EnclaveSharedKeyCreateRequest) -> Result<Self, CryptoError> {
        Ok(Self {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: "enclave_shared_key_create_request".to_owned(),
            attribute_value: VendorAttributeValue::ByteString(
                serde_json::to_vec(&request).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed serializing the shared key setup value. Error: {e:?}"
                    ))
                })?,
            ),
        })
    }
}

impl TryFrom<&VendorAttribute> for EnclaveSharedKeyCreateRequest {
    type Error = CryptoError;

    fn try_from(attribute: &VendorAttribute) -> Result<Self, CryptoError> {
        if attribute.vendor_identification != VENDOR_ID_COSMIAN
            || &attribute.attribute_name != "enclave_shared_key_create_request"
        {
            return Err(CryptoError::Kmip(
                "the attributes in not a shared key create request".to_owned(),
            ))
        }
        let VendorAttributeValue::ByteString(value) = &attribute.attribute_value else {
            return Err(CryptoError::Kmip(
                "the attributes in not a shared key create request".to_owned(),
            ))
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
                &att.attribute_name == "enclave_shared_key_create_request"
                    && att.vendor_identification == VENDOR_ID_COSMIAN
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

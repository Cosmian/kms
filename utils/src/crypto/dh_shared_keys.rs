use std::convert::TryFrom;

use cosmian_kmip::kmip::{
    kmip_operations::ErrorReason,
    kmip_types::{Attributes, VendorAttribute},
};
use serde::{Deserialize, Serialize};

use crate::{
    error::LibError,
    lib_error,
    result::{LibResult, LibResultHelper},
};

#[derive(Serialize, Deserialize, Debug)]
pub struct EnclaveSharedKeyCreateRequest {
    pub algo_provider_public_key_uid: String,
    pub algo_provider_secret_key_uid: String,
    pub data_provider_public_key_uid: String,
}

/// Create enclave `VendorAttribute` to set in a `CreateRequest` for a DH shared
/// Key
impl TryFrom<&EnclaveSharedKeyCreateRequest> for VendorAttribute {
    type Error = LibError;

    fn try_from(request: &EnclaveSharedKeyCreateRequest) -> LibResult<Self> {
        Ok(VendorAttribute {
            vendor_identification: "cosmian".to_owned(),
            attribute_name: "enclave_shared_key_create_request".to_owned(),
            attribute_value: serde_json::to_vec(&request)
                .context("failed serializing the shared key setup value")
                .reason(ErrorReason::Invalid_Attribute_Value)?,
        })
    }
}

impl TryFrom<&VendorAttribute> for EnclaveSharedKeyCreateRequest {
    type Error = LibError;

    fn try_from(attribute: &VendorAttribute) -> LibResult<Self> {
        if &attribute.vendor_identification != "cosmian"
            || &attribute.attribute_name != "enclave_shared_key_create_request"
        {
            return Err(lib_error!(
                "the attributes in not a shared key create request"
            ))
            .reason(ErrorReason::Invalid_Attribute_Value)
        }
        serde_json::from_slice::<EnclaveSharedKeyCreateRequest>(&attribute.attribute_value)
            .context("failed deserializing the Shared Key Create Request")
            .reason(ErrorReason::Invalid_Attribute_Value)
    }
}

impl TryFrom<&Attributes> for EnclaveSharedKeyCreateRequest {
    type Error = LibError;

    fn try_from(attributes: &Attributes) -> LibResult<Self> {
        let vdr = attributes.vendor_attributes.as_ref().context(
            "the attributes do not contain any vendor attribute, hence no shared key setup data",
        )?;
        let va = vdr
            .iter()
            .find(|att| {
                &att.attribute_name == "enclave_shared_key_create_request"
                    && &att.vendor_identification == "cosmian"
            })
            .context("this attribute response does not contain a Shared Key Create Request")?;
        EnclaveSharedKeyCreateRequest::try_from(va)
    }
}

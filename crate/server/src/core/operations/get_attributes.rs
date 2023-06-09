use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, GetAttributesResponse},
    kmip_types::{AttributeReference, Attributes, Tag},
};
use cosmian_kms_utils::types::{ExtraDatabaseParams, ObjectOperationTypes};
use tracing::{debug, trace};

use crate::{core::KMS, error::KmsError, result::KResult};

pub async fn get_attributes(
    kms: &KMS,
    request: GetAttributes,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetAttributesResponse> {
    trace!("Get attributes: {}", serde_json::to_string(&request)?);
    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    trace!("retrieving attributes of KMIP Object with id: {uid}");
    let (object, _state) = kms
        .db
        .retrieve(uid, owner, ObjectOperationTypes::Get, params)
        .await?
        .ok_or_else(|| KmsError::ItemNotFound(format!("Object with uid: {uid} not found")))?;

    let object_type = object.object_type();
    let attributes = object.attributes()?;

    let req_attributes = match &request.attribute_references {
        None => {
            return Ok(GetAttributesResponse {
                unique_identifier: uid.clone(),
                attributes: attributes.clone(),
            })
        }
        Some(attrs) => attrs,
    };
    let mut res = Attributes::new(object_type);
    for requested in req_attributes {
        match requested {
            AttributeReference::Vendor(req_vdr_attr) => {
                if let Some(vdr_attrs) = attributes.vendor_attributes.as_ref() {
                    let mut list = res.vendor_attributes.as_ref().unwrap_or(&vec![]).clone();
                    vdr_attrs
                        .iter()
                        .filter(|attr| {
                            attr.vendor_identification == req_vdr_attr.vendor_identification
                                && attr.attribute_name == req_vdr_attr.attribute_name
                        })
                        .for_each(|vdr_attr| {
                            list.push(vdr_attr.clone());
                        });
                    if !list.is_empty() {
                        res.vendor_attributes = Some(list);
                    }
                }
            }
            AttributeReference::Standard(tag) => match tag {
                Tag::ActivationDate => {
                    res.activation_date = attributes.activation_date;
                }
                Tag::CryptographicAlgorithm => {
                    res.cryptographic_algorithm = attributes.cryptographic_algorithm;
                }
                Tag::CryptographicLength => {
                    res.cryptographic_length = attributes.cryptographic_length;
                }
                Tag::CryptographicParameters => {
                    res.cryptographic_parameters = attributes.cryptographic_parameters.clone();
                }
                Tag::CryptographicUsageMask => {
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask;
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                _ => {}
            },
        }
    }
    debug!("Retrieved Attributes for object {uid}: {res:?}");
    Ok(GetAttributesResponse {
        unique_identifier: uid.clone(),
        attributes: res,
    })
}

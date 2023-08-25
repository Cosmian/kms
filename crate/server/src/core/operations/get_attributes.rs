use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, GetAttributesResponse},
    kmip_types::{AttributeReference, Attributes, Tag},
};
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::{debug, trace};

use crate::{
    core::{operations::get::get_active_object, KMS},
    error::KmsError,
    result::KResult,
};

pub async fn get_attributes(
    kms: &KMS,
    request: GetAttributes,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<GetAttributesResponse> {
    trace!("Get attributes: {}", serde_json::to_string(&request)?);

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .clone()
        .ok_or(KmsError::UnsupportedPlaceholder)?;

    // recover an active object
    let owm = get_active_object(kms, &uid_or_tags, user, params).await?;
    let object_type = owm.object.object_type();
    let attributes = owm.object.attributes()?;

    let req_attributes = match &request.attribute_references {
        None => {
            return Ok(GetAttributesResponse {
                unique_identifier: owm.id.clone(),
                attributes: attributes.clone(),
            })
        }
        Some(attrs) => attrs,
    };
    let mut res = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
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
                    res.cryptographic_usage_mask = attributes.cryptographic_usage_mask.clone();
                }
                Tag::KeyFormatType => {
                    res.key_format_type = attributes.key_format_type;
                }
                _ => {}
            },
        }
    }
    debug!("Retrieved Attributes for object {}: {:?}", owm.id, res);
    Ok(GetAttributesResponse {
        unique_identifier: owm.id,
        attributes: res,
    })
}

use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes};
use tracing::trace;

use crate::crypto::gpsw::attributes::{access_policy_from_attributes, attributes_from_attributes};

/// 2 types of KMIP attributes comparison: (it depends if
/// `researched_attributes` contains "`abe_attributes`" vendor attributes) first:
///   compare only access policies of the 2 `Attributes` input parameters
/// second:
///   return `true` if both `Attributes` contains the same master private key
/// unique identifier and if one of the ABE attributes (found in
/// `researched_attributes` through vendor attributes) is found in `attributes`
pub fn compare_abe_attributes(
    attributes: &Attributes,
    researched_attributes: &Attributes,
) -> Result<bool, KmipError> {
    trace!("Compare: {attributes:#?} <==> {researched_attributes:#?}");

    if let Ok(access_policy) = access_policy_from_attributes(attributes) {
        if let Ok(researched_access_policy) = access_policy_from_attributes(researched_attributes) {
            if researched_access_policy == access_policy {
                return Ok(true)
            }
        } else {
            let abe_attributes =
                attributes_from_attributes(researched_attributes).unwrap_or_default();

            if access_policy
                .attributes()
                .iter()
                .any(|attr| abe_attributes.contains(attr))
            {
                return Ok(true)
            }
        }
    }
    Ok(false)
}

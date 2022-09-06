use std::collections::HashSet;

use abe_policy::AccessPolicy;
use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes};

use crate::crypto::cover_crypt::attributes::{
    access_policy_from_attributes, attributes_from_attributes,
};

/// 2 types of KMIP attributes comparison: (it depends if
/// `researched_attributes` contains "`cover_crypt_attributes`" vendor attributes) first:
///   compare only access policies of the 2 `Attributes` input parameters
/// second:
///   return `true` if both `Attributes` contains the same master private key
/// unique identifier and if one of the CoverCrypt attributes (found in
/// `researched_attributes` through vendor attributes) is found in `attributes`
/// /// TODO: BGR: it would be better, faster, safer to reconstruct the partitions list and check for intersections
/// TODO: this code should be in the abe_policy crate
pub fn compare_cover_crypt_attributes(
    attributes: &Attributes,
    researched_attributes: &Attributes,
) -> Result<bool, KmipError> {
    match access_policy_from_attributes(attributes) {
        Ok(access_policy) => {
            if access_policy == AccessPolicy::All {
                return Ok(true)
            }

            match access_policy_from_attributes(researched_attributes) {
                Ok(researched_access_policy) => {
                    // println!("Compare: {access_policy:#?}  <==> {researched_access_policy:#?}");
                    if researched_access_policy == access_policy {
                        return Ok(true)
                    }
                }
                Err(_) => {
                    let cover_crypt_attributes =
                        attributes_from_attributes(researched_attributes).unwrap_or_default();
                    let master_private_key_unique_identifier = match attributes.get_parent_id() {
                        Some(id) => id,
                        None => return Ok(false),
                    };
                    let researched_master_private_key_unique_identifier =
                        match researched_attributes.get_parent_id() {
                            Some(id) => id,
                            None => return Ok(false),
                        };
                    // TODO: This should not be necessary anymore (the Find should do this correctly)
                    if master_private_key_unique_identifier
                        == researched_master_private_key_unique_identifier
                    {
                        let access_policy_attributes = access_policy.attributes();
                        let access_policy_axes: HashSet<String> = access_policy_attributes
                            .iter()
                            .map(|att| att.axis.clone())
                            .collect();
                        // if a research attribute axis is not present in the access policy,
                        // it means that the access policy accepts all values for that axis,
                        // so there is an intersection
                        if cover_crypt_attributes
                            .iter()
                            .any(|attr| !access_policy_axes.contains(&attr.axis))
                        {
                            return Ok(true)
                        }
                        // check if the access policy contains the name of one of the researched attributes
                        if access_policy_attributes
                            .iter()
                            .any(|attr| cover_crypt_attributes.contains(attr))
                        {
                            return Ok(true)
                        }
                    }
                }
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}

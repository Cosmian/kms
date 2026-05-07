use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute, kmip_operations::SetAttribute, kmip_types::UniqueIdentifier,
    },
};

use crate::error::result::{KmsCliResult, KmsCliResultHelper};

/// Apply rotation policy attributes to an existing object via `SetAttribute`.
///
/// Calls the KMS server with up to three sequential `SetAttribute` requests for
/// `RotateInterval`, `RotateName`, and `RotateOffset`. Only attributes with a
/// `Some` value are sent.
pub(crate) async fn apply_rotation_policy_if_set(
    kms_rest_client: &KmsClient,
    uid: &str,
    rotate_interval: Option<i32>,
    rotate_name: Option<&str>,
    rotate_offset: Option<i32>,
) -> KmsCliResult<()> {
    let unique_identifier = UniqueIdentifier::TextString(uid.to_owned());

    if let Some(interval) = rotate_interval {
        let req = SetAttribute {
            unique_identifier: Some(unique_identifier.clone()),
            new_attribute: Attribute::RotateInterval(interval),
        };
        kms_rest_client
            .set_attribute(req)
            .await
            .with_context(|| "failed to set RotateInterval")?;
    }

    if let Some(name) = rotate_name {
        let req = SetAttribute {
            unique_identifier: Some(unique_identifier.clone()),
            new_attribute: Attribute::RotateName(name.to_owned()),
        };
        kms_rest_client
            .set_attribute(req)
            .await
            .with_context(|| "failed to set RotateName")?;
    }

    if let Some(offset) = rotate_offset {
        let req = SetAttribute {
            unique_identifier: Some(unique_identifier.clone()),
            new_attribute: Attribute::RotateOffset(offset),
        };
        kms_rest_client
            .set_attribute(req)
            .await
            .with_context(|| "failed to set RotateOffset")?;
    }

    Ok(())
}

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute, kmip_operations::SetAttribute, kmip_types::UniqueIdentifier,
    },
};

use crate::error::result::{KmsCliResult, KmsCliResultHelper};

/// Optional rotation policy arguments that can be added to key creation commands.
///
/// When provided, these are applied as `SetAttribute` calls immediately after the key is created.
#[derive(Parser, Default, Debug, Clone)]
pub struct RotationPolicyArgs {
    /// Assign a keyset name for addressing key generations via `name@latest`, `name@first`, `name@N` syntax.
    /// Must not contain the `@` character.
    #[clap(
        long = "rotation-name",
        short = 'n',
        required = false,
        verbatim_doc_comment
    )]
    pub rotate_name: Option<String>,

    /// Rotation interval in seconds. The key will be automatically re-keyed at this interval.
    /// Set to 0 to disable automatic rotation while preserving other policy fields.
    #[clap(long = "rotation-interval", required = false)]
    pub rotate_interval: Option<i64>,

    /// Offset in seconds from the initial date before the first rotation occurs.
    #[clap(long = "rotation-offset", required = false)]
    pub rotate_offset: Option<i64>,
}

impl RotationPolicyArgs {
    /// Returns `true` if at least one rotation policy field is set.
    #[must_use]
    pub const fn is_set(&self) -> bool {
        self.rotate_name.is_some() || self.rotate_interval.is_some() || self.rotate_offset.is_some()
    }

    /// Apply rotation policy attributes via `SetAttribute` calls on the given key ID.
    pub async fn apply(&self, kms_rest_client: &KmsClient, key_id: &str) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(key_id.to_owned());

        if let Some(interval) = self.rotate_interval {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateInterval(interval),
                })
                .await
                .with_context(|| "failed setting RotateInterval attribute")?;
        }

        if let Some(offset) = self.rotate_offset {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateOffset(offset),
                })
                .await
                .with_context(|| "failed setting RotateOffset attribute")?;
        }

        if let Some(ref name) = self.rotate_name {
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateName(name.clone()),
                })
                .await
                .with_context(|| "failed setting RotateName attribute")?;
        }

        Ok(())
    }
}

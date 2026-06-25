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

    /// Validate `rotate_name` / `key_id` consistency and return the effective key ID to use.
    ///
    /// For SQL keys the keyset invariant requires `key_id == rotate_name` at creation time.
    /// This check runs client-side so the user gets a clear error before any request is sent.
    ///
    /// Rules:
    /// - If `rotate_name` is `None`, return `key_id` unchanged.
    /// - If `rotate_name` is set and `key_id` is `None`, use `rotate_name` as the key ID.
    /// - If both are set and equal, return `key_id` unchanged.
    /// - If both are set but differ, return an error immediately.
    ///
    /// # Errors
    /// Returns an error when `rotate_name` and `key_id` are both set but do not match.
    pub fn effective_key_id<'a>(&'a self, key_id: Option<&'a str>) -> KmsCliResult<Option<String>> {
        self.rotate_name
            .as_deref()
            .map_or_else(
                || Ok(key_id.map(ToOwned::to_owned)),
                |name| match key_id {
                    None => Ok(Some(name.to_owned())),
                    Some(id) if id == name => Ok(Some(id.to_owned())),
                    Some(id) => Err(crate::error::KmsCliError::Default(format!(
                        "key ID '{id}' must equal the rotation name '{name}' — \
                         use --key-id {name} or omit --key-id to use the rotation name as the key ID"
                    ))),
                },
            )
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

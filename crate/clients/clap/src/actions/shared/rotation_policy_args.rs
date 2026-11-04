use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{CreateKeyPairResponse, SetAttribute},
        kmip_types::UniqueIdentifier,
    },
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Optional rotation policy arguments that can be added to key creation commands.
///
/// When provided, these are applied as `SetAttribute` calls immediately after the key is created.
#[derive(Parser, Default, Debug, Clone)]
pub struct RotationPolicyArgs {
    /// Enroll this key in a keyset so it can be addressed via `name@latest`,
    /// `name@first`, `name@N` syntax. The keyset name is set automatically to
    /// the key's own ID returned by the server.
    #[clap(
        long = "enroll-keyset",
        short = 'n',
        default_value = "false",
        verbatim_doc_comment
    )]
    pub enroll_keyset: bool,

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
        self.enroll_keyset || self.rotate_interval.is_some() || self.rotate_offset.is_some()
    }

    /// Apply rotation policy attributes via `SetAttribute` calls on the given key ID.
    ///
    /// When `--enroll-keyset` is set, the keyset name is automatically set to `key_id`
    /// (the ID returned by the server), so the key can be addressed via `key_id@latest`,
    /// `key_id@first`, `key_id@N` syntax.
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

        if self.enroll_keyset {
            // Use the server-assigned key ID as the keyset name so the keyset
            // invariant (key_id == rotate_name) is always satisfied automatically.
            kms_rest_client
                .set_attribute(SetAttribute {
                    unique_identifier: Some(uid.clone()),
                    new_attribute: Attribute::RotateName(key_id.to_owned()),
                })
                .await
                .with_context(|| "failed setting RotateName attribute")?;
        }

        Ok(())
    }

    /// Finish a key pair creation: apply this policy (when set) to the private key,
    /// which is the keyset anchor, print `message` with `tags` and both key ids,
    /// and return the `(private, public)` key ids.
    ///
    /// # Errors
    ///
    /// Fails if the private key id is not a string, the policy cannot be applied,
    /// or the summary cannot be written.
    pub(crate) async fn finish_key_pair_creation(
        &self,
        kms_rest_client: &KmsClient,
        response: CreateKeyPairResponse,
        tags: &Vec<String>,
        message: &str,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        if self.is_set() {
            let sk_id = response
                .private_key_unique_identifier
                .as_str()
                .with_context(|| "the server did not return a private key id as a string")?;
            self.apply(kms_rest_client, sk_id).await?;
        }

        let mut stdout = console::Stdout::new(message);
        stdout.set_tags(Some(tags));
        stdout.set_key_pair_unique_identifier(
            &response.private_key_unique_identifier,
            &response.public_key_unique_identifier,
        );
        stdout.write()?;

        Ok((
            response.private_key_unique_identifier,
            response.public_key_unique_identifier,
        ))
    }
}

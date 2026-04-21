use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier,
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{ModifyAttribute, ModifyAttributeResponse},
    },
};
use cosmian_kms_logger::{info, trace};

use super::set::SetOrDeleteAttributes;
use crate::{
    actions::{console, labels::ATTRIBUTE_ID, shared::get_key_uid},
    cli_bail,
    error::result::KmsCliResult,
};

/// Modify existing KMIP object attributes.
///
/// The `ModifyAttribute` operation replaces the value of an attribute that
/// already exists on a managed object.  Unlike `SetAttribute`, it does not
/// create the attribute if it is absent.
///
/// A notable side-effect: setting an `activation_date` that is ≤ the current
/// time on a *Pre-Active* object will automatically transition the object to
/// the *Active* state (KMIP spec §3.22).
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ModifyAttributesAction {
    #[clap(flatten)]
    pub(crate) requested_attributes: SetOrDeleteAttributes,
}

impl ModifyAttributesAction {
    pub(crate) async fn modify_attribute(
        &self,
        kms_rest_client: &KmsClient,
        id: &str,
        attribute: Attribute,
    ) -> KmsCliResult<()> {
        let uid = UniqueIdentifier::TextString(id.to_owned());
        let ModifyAttributeResponse {
            unique_identifier, ..
        } = kms_rest_client
            .modify_attribute(ModifyAttribute {
                unique_identifier: Some(uid.clone()),
                new_attribute: attribute.clone(),
            })
            .await?;
        let effective_uid = unique_identifier.unwrap_or(uid);
        info!("ModifyAttributes response for {effective_uid}: {attribute}");
        let mut stdout = console::Stdout::new("Attribute modified successfully");
        stdout.set_tags(self.requested_attributes.tags.as_ref());
        stdout.set_unique_identifier(&effective_uid);
        stdout.set_attribute(attribute);
        stdout.write()?;
        Ok(())
    }

    /// Processes the `ModifyAttributes` action.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Neither `--id` nor `--tag` is specified.
    /// - No attribute to modify is specified.
    /// - The server rejects the modification.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        trace!("{self:?}");
        let id = get_key_uid(
            self.requested_attributes.id.as_ref(),
            self.requested_attributes.tags.as_ref(),
            ATTRIBUTE_ID,
        )?;

        let attributes_to_modify = self.requested_attributes.get_attributes_from_args()?;
        if attributes_to_modify.is_empty() {
            cli_bail!("No attribute specified")
        }

        for attribute in attributes_to_modify {
            self.modify_attribute(&kms_rest_client, &id, attribute)
                .await?;
        }

        Ok(())
    }
}

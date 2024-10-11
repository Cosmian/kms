use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::UniqueIdentifier,
    kmip::{
        kmip_operations::{DeleteAttribute, DeleteAttributeResponse},
        kmip_types::{Attribute, AttributeReference, Tag},
    },
    KmsClient,
};
use tracing::trace;

use super::set::SetOrDeleteAttributes;
use crate::{actions::console, cli_bail, error::result::CliResult};

/// Delete the KMIP object attributes.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DeleteAttributesAction {
    #[clap(flatten)]
    requested_attributes: SetOrDeleteAttributes,

    /// The attributes or tags to retrieve.
    /// To specify multiple attributes, use the option multiple times.
    #[clap(long = "attribute", value_name = "ATTRIBUTE", verbatim_doc_comment)]
    attribute_tags: Option<Vec<Tag>>,
}

impl DeleteAttributesAction {
    async fn delete_attribute(
        &self,
        kms_rest_client: &KmsClient,
        id: &str,
        current_attribute: Option<Attribute>,
        attribute_references: Option<Vec<AttributeReference>>,
    ) -> CliResult<()> {
        let DeleteAttributeResponse { unique_identifier } = kms_rest_client
            .delete_attribute(DeleteAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
                current_attribute: current_attribute.clone(),
                attribute_references,
            })
            .await?;
        trace!("delete_attribute response for {unique_identifier}: {current_attribute:?}",);
        let mut stdout = console::Stdout::new("Attribute deleted successfully");
        stdout.set_tags(self.requested_attributes.tags.as_ref());
        stdout.set_unique_identifier(id);
        if let Some(current_attribute) = current_attribute {
            stdout.set_attribute(current_attribute);
        }
        stdout.write()?;

        Ok(())
    }

    /// Processes the `DeleteAttributes` action.
    ///
    /// # Errors
    ///
    /// This function can return a `CliError` if one of the following conditions occur:
    ///
    /// - Either `--id` or one or more `--tag` must be specified.
    ///
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        trace!("DeleteAttributeAction: {:?}", self);
        let id = if let Some(key_id) = &self.requested_attributes.id {
            key_id.clone()
        } else if let Some(tags) = &self.requested_attributes.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --id or one or more --tag must be specified")
        };

        for attribute in self.requested_attributes.get_attributes_from_args()? {
            self.delete_attribute(kms_rest_client, &id, Some(attribute), None)
                .await?;
        }

        if let Some(tags) = &self.attribute_tags {
            let mut references: Vec<AttributeReference> = Vec::with_capacity(tags.len());
            for tag in tags {
                references.push(AttributeReference::Standard(tag.to_owned()));
            }
            self.delete_attribute(kms_rest_client, &id, None, Some(references))
                .await?;
        }

        Ok(())
    }
}

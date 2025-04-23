use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{
        kmip_operations::{GetAttributes, GetAttributesResponse},
        kmip_types::{AttributeReference, Tag, UniqueIdentifier},
    },
    reexport::cosmian_kms_client_utils::attributes_utils::{CLinkType, parse_selected_attributes},
    write_bytes_to_file,
};
use tracing::{debug, trace};

use crate::{
    actions::{
        console,
        kms::{labels::ATTRIBUTE_ID, shared::get_key_uid},
    },
    error::result::CosmianResult,
};

/// Get the KMIP object attributes and tags.
///
/// When using tags to retrieve the object, rather than the object id,
/// an error is returned if multiple objects matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GetAttributesAction {
    /// The unique identifier of the cryptographic object.
    /// If not specified, tags should be specified
    #[clap(long = ATTRIBUTE_ID, short = 'i', group = "id-tags")]
    id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "id-tags")]
    tags: Option<Vec<String>>,

    /// The attributes or `KMIP-tags` to retrieve.
    /// To specify multiple attributes, use the option multiple times.
    /// If not specified, all possible attributes are returned.
    #[clap(
        long = "attribute",
        short = 'a',
        value_name = "ATTRIBUTE",
        verbatim_doc_comment
    )]
    attribute_tags: Vec<Tag>,

    /// Filter on retrieved links. Only if KMIP tag `LinkType` is used in `attribute` parameter.
    /// To specify multiple attributes, use the option multiple times.
    /// If not specified, all possible link types are returned.
    #[clap(
        long = "link-type",
        short = 'l',
        value_name = "LINK_TYPE",
        verbatim_doc_comment
    )]
    attribute_link_types: Vec<CLinkType>,

    /// An optional file where to export the attributes.
    /// The attributes will be in JSON TTLV format.
    #[clap(long = "output-file", short = 'o', verbatim_doc_comment)]
    output_file: Option<PathBuf>,
}

impl GetAttributesAction {
    /// Get the KMIP object attributes and tags.
    ///
    /// When using tags to retrieve the object, rather than the object id,
    /// an error is returned if multiple objects matching the tags are found.
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - The `--id` or one or more `--tag` options is not specified.
    /// - There is an error serializing the tags to a string.
    /// - There is an error performing the Get Attributes request.
    /// - There is an error serializing the attributes to JSON.
    /// - There is an error writing the attributes to the output file.
    /// - There is an error writing to the console.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CosmianResult<()> {
        trace!("GetAttributesAction: {:?}", self);
        let id = get_key_uid(self.id.as_ref(), self.tags.as_ref(), ATTRIBUTE_ID)?;

        let mut references: Vec<AttributeReference> = Vec::with_capacity(self.attribute_tags.len());
        for tag in &self.attribute_tags {
            references.push(AttributeReference::Standard(*tag));
        }

        // perform the Get Attributes request
        let GetAttributesResponse {
            unique_identifier,
            attributes,
        } = kms_rest_client
            .get_attributes(GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(id)),
                attribute_reference: Some(references),
            })
            .await?;

        debug!("GetAttributes response for {unique_identifier}: {attributes:?}",);

        let results = parse_selected_attributes(
            &attributes,
            &self.attribute_tags,
            &self.attribute_link_types,
        )?;

        if let Some(output_file) = &self.output_file {
            let json = serde_json::to_string_pretty(&results)?;
            debug!("GetAttributes response for {unique_identifier}: {}", json);
            write_bytes_to_file(json.as_bytes(), output_file)?;
            let stdout = format!(
                "The attributes for {unique_identifier} were exported to {}",
                output_file.display()
            );
            console::Stdout::new(&stdout).write()?;
        } else {
            let mut stdout = console::Stdout::new(&format!("Attributes for {unique_identifier}"));
            stdout.set_unique_identifier(unique_identifier);
            stdout.set_attributes(results);
            stdout.write()?;
        }
        Ok(())
    }
}

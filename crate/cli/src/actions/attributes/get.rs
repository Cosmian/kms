use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_operations::{GetAttributes, GetAttributesResponse},
        kmip_types::{AttributeReference, LinkType, Tag, UniqueIdentifier},
    },
    write_bytes_to_file, KmsClient,
};
use serde_json::Value;
use strum::IntoEnumIterator;
use tracing::{debug, trace};

use crate::{actions::console, cli_bail, error::result::CliResult};

/// Get the KMIP object attributes and tags.
///
/// When using tags to retrieve the object, rather than the object id,
/// an error is returned if multiple objects matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GetAttributesAction {
    /// The unique identifier of the cryptographic object.
    /// If not specified, tags should be specified
    #[clap(long = "id", short = 'i', group = "id-tags")]
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
    attribute_link_types: Vec<LinkType>,

    /// An optional file where to export the attributes.
    /// The attributes will be in JSON TTLV format.
    #[clap(long = "output-file", short = 'o', verbatim_doc_comment)]
    output_file: Option<PathBuf>,
}

fn add_if_not_empty(tag: Tag, new_value: &str, results: &mut HashMap<String, Value>) {
    if !new_value.is_empty() {
        results.insert(
            tag.to_string(),
            serde_json::to_value(new_value).unwrap_or_default(),
        );
    }
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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        trace!("GetAttributesAction: {:?}", self);
        let id = if let Some(key_id) = &self.id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --id or one or more --tag must be specified")
        };

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
                attribute_references: Some(references),
            })
            .await?;

        debug!("GetAttributes response for {unique_identifier}: {attributes:?}",);

        // if no tag asked -> return values for all possible tags
        let tags = if self.attribute_tags.is_empty() {
            trace!("No attribute tag specified, returning all possible tags");
            let mut all_tags = Vec::new();
            for tag in Tag::iter() {
                all_tags.push(tag);
            }
            all_tags
        } else {
            self.attribute_tags.clone()
        };

        let mut results: HashMap<String, Value> = HashMap::new();
        for tag in &tags {
            match tag {
                Tag::ActivationDate => {
                    if let Some(v) = attributes.activation_date.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CertificateLength => {
                    if let Some(v) = attributes.certificate_length.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CertificateType => {
                    if let Some(v) = attributes.certificate_type.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CertificateSubjectC => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_c, &mut results);
                    }
                }
                Tag::CertificateSubjectCN => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_cn, &mut results);
                    }
                }
                Tag::CertificateSubjectDC => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_dc, &mut results);
                    }
                }
                Tag::CertificateSubjectEmail => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_email, &mut results);
                    }
                }
                Tag::CertificateSubjectL => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_l, &mut results);
                    }
                }
                Tag::CertificateSubjectO => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_o, &mut results);
                    }
                }
                Tag::CertificateSubjectOU => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_ou, &mut results);
                    }
                }
                Tag::CertificateSubjectST => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_st, &mut results);
                    }
                }
                Tag::CertificateSubjectDNQualifier => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_dn_qualifier, &mut results);
                    }
                }
                Tag::CertificateSubjectSerialNumber => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_serial_number, &mut results);
                    }
                }
                Tag::CertificateSubjectTitle => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_title, &mut results);
                    }
                }
                Tag::CertificateSubjectUID => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_subject_uid, &mut results);
                    }
                }
                Tag::CertificateIssuerC => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_c, &mut results);
                    }
                }
                Tag::CertificateIssuerCN => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_cn, &mut results);
                    }
                }
                Tag::CertificateIssuerDC => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_dc, &mut results);
                    }
                }
                Tag::CertificateIssuerEmail => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_email, &mut results);
                    }
                }
                Tag::CertificateIssuerL => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_l, &mut results);
                    }
                }
                Tag::CertificateIssuerO => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_o, &mut results);
                    }
                }
                Tag::CertificateIssuerOU => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_ou, &mut results);
                    }
                }
                Tag::CertificateIssuerST => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_st, &mut results);
                    }
                }
                Tag::CertificateIssuerDNQualifier => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_dn_qualifier, &mut results);
                    }
                }
                Tag::CertificateIssuerUID => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_uid, &mut results);
                    }
                }
                Tag::CertificateIssuerSerialNumber => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_serial_number, &mut results);
                    }
                }
                Tag::CertificateIssuerTitle => {
                    if let Some(v) = attributes.certificate_attributes.as_ref() {
                        add_if_not_empty(*tag, &v.certificate_issuer_title, &mut results);
                    }
                }
                Tag::CryptographicAlgorithm => {
                    if let Some(v) = attributes.cryptographic_algorithm.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CryptographicLength => {
                    if let Some(v) = attributes.cryptographic_length.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CryptographicParameters => {
                    if let Some(v) = attributes.cryptographic_parameters.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CryptographicDomainParameters => {
                    if let Some(v) = attributes.cryptographic_domain_parameters.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::CryptographicUsageMask => {
                    if let Some(v) = attributes.cryptographic_usage_mask.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::KeyFormatType => {
                    if let Some(v) = attributes.key_format_type.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::ObjectType => {
                    if let Some(v) = attributes.object_type.as_ref() {
                        results
                            .insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                    }
                }
                Tag::Tag => {
                    let tags = attributes.get_tags();
                    results.insert(
                        tag.to_string(),
                        serde_json::to_value(tags).unwrap_or_default(),
                    );
                }
                Tag::VendorExtension => {
                    if let Some(vendor_attributes) = attributes.vendor_attributes.as_ref() {
                        results.insert(
                            tag.to_string(),
                            serde_json::to_value(vendor_attributes).unwrap_or_default(),
                        );
                    }
                }
                _x => {}
            }
        }

        // if no link asked -> return values for all possible links
        let link_types = if self.attribute_link_types.is_empty() {
            trace!("No link type specified, returning all possible link types");
            let mut all_links = Vec::new();
            for link in LinkType::iter() {
                all_links.push(link);
            }
            all_links
        } else {
            self.attribute_link_types.clone()
        };

        trace!("Attributes at this point: {attributes:?}",);
        for link_type in &link_types {
            trace!("Processing link type: {link_type:?}",);
            if let Some(v) = attributes.get_link(*link_type).as_ref() {
                trace!("Link type {link_type} found: {v:?}",);
                results.insert(
                    link_type.to_string(),
                    serde_json::to_value(v).unwrap_or_default(),
                );
            }
        }

        if let Some(output_file) = &self.output_file {
            let json = serde_json::to_string_pretty(&results)?;
            debug!("GetAttributes response for {unique_identifier}: {}", json);
            write_bytes_to_file(json.as_bytes(), output_file)?;
            let stdout = format!(
                "The attributes for {unique_identifier} were exported to {:?}",
                &output_file
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

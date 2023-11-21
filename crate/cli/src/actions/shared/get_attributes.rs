use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::{
    kmip_operations::{GetAttributes, GetAttributesResponse},
    kmip_types::{AttributeReference, LinkType, Tag},
};
use cosmian_kms_client::KmsRestClient;
use serde_json::Value;
use tracing::debug;

use crate::{actions::shared::utils::write_bytes_to_file, cli_bail, error::CliError};

#[derive(clap::ValueEnum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributeTag {
    ActivationDate,
    CryptographicAlgorithm,
    CryptographicLength,
    CryptographicParameters,
    CryptographicUsageMask,
    KeyFormatType,
    LinkedPrivateKeyId,
    LinkedPublicKeyId,
    LinkedIssuerCertificateId,
    LinkedCertificateId,
}

/// Get the KMIP attributes.
///
/// When using tags to retrieve the object, rather than the object id,
/// an error is returned if multiple objects matching the tags are found.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct GetAttributesAction {
    /// The key unique identifier of the cryptographic object.
    /// If not specified, tags should be specified
    #[clap(long = "id", short = 'i', group = "id-tags")]
    id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "id-tags")]
    tags: Option<Vec<String>>,

    /// The attributes to retrieve.
    /// To specify multiple attributes, use the option multiple times.
    #[clap(
        long = "attribute",
        short = 'a',
        value_name = "ATTRIBUTE",
        verbatim_doc_comment
    )]
    attribute_tags: Vec<AttributeTag>,

    /// An optional file where to export the attributes.
    /// The attributes will be in JSON TTLV format.
    #[clap(long = "output-file", short = 'o', verbatim_doc_comment)]
    output_file: Option<PathBuf>,
}

impl GetAttributesAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        let id = if let Some(key_id) = &self.id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        let mut references: Vec<AttributeReference> = Vec::with_capacity(self.attribute_tags.len());
        for tag in &self.attribute_tags {
            match tag {
                AttributeTag::ActivationDate => {
                    references.push(AttributeReference::Standard(Tag::ActivationDate))
                }
                AttributeTag::CryptographicAlgorithm => {
                    references.push(AttributeReference::Standard(Tag::CryptographicAlgorithm))
                }
                AttributeTag::CryptographicLength => {
                    references.push(AttributeReference::Standard(Tag::CryptographicLength))
                }
                AttributeTag::CryptographicParameters => {
                    references.push(AttributeReference::Standard(Tag::CryptographicParameters))
                }
                AttributeTag::CryptographicUsageMask => {
                    references.push(AttributeReference::Standard(Tag::CryptographicUsageMask))
                }
                AttributeTag::KeyFormatType => {
                    references.push(AttributeReference::Standard(Tag::KeyFormatType))
                }
                AttributeTag::LinkedPrivateKeyId => {
                    references.push(AttributeReference::Standard(Tag::PrivateKey))
                }
                AttributeTag::LinkedPublicKeyId => {
                    references.push(AttributeReference::Standard(Tag::PublicKey))
                }
                AttributeTag::LinkedIssuerCertificateId => {
                    references.push(AttributeReference::Standard(Tag::Certificate))
                }
                AttributeTag::LinkedCertificateId => {
                    references.push(AttributeReference::Standard(Tag::Certificate))
                }
            }
        }

        // perform the reauest
        let get_attributes = GetAttributes {
            unique_identifier: Some(id),
            attribute_references: Some(references),
        };
        let GetAttributesResponse {
            unique_identifier,
            attributes,
        } = kms_rest_client.get_attributes(get_attributes).await?;

        let mut results: HashMap<String, Value> = HashMap::new();
        for tag in &self.attribute_tags {
            match tag {
                AttributeTag::ActivationDate => {
                    attributes.activation_date.as_ref().map(|v| {
                        results.insert(
                            "activation-date".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::CryptographicAlgorithm => {
                    attributes.cryptographic_algorithm.as_ref().map(|v| {
                        results.insert(
                            "cryptographic-algorithm".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::CryptographicLength => {
                    attributes.cryptographic_length.as_ref().map(|v| {
                        results.insert(
                            "cryptographic-length".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::CryptographicParameters => {
                    attributes.cryptographic_parameters.as_ref().map(|v| {
                        results.insert(
                            "cryptographic-parameters".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::CryptographicUsageMask => {
                    attributes.cryptographic_usage_mask.as_ref().map(|v| {
                        results.insert(
                            "cryptographic-usage-mask".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::KeyFormatType => {
                    attributes.key_format_type.as_ref().map(|v| {
                        results.insert(
                            "key-format-type".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::LinkedPrivateKeyId => {
                    attributes.get_link(LinkType::PrivateKeyLink).map(|v| {
                        results.insert(
                            "linked-private-key-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::LinkedPublicKeyId => {
                    attributes.get_link(LinkType::PublicKeyLink).map(|v| {
                        results.insert(
                            "linked-public-key-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::LinkedIssuerCertificateId => {
                    attributes.get_link(LinkType::CertificateLink).map(|v| {
                        results.insert(
                            "linked-issuer-certificate-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    });
                }
                AttributeTag::LinkedCertificateId => {
                    attributes
                        .get_link(LinkType::PKCS12CertificateLink)
                        .map(|v| {
                            results.insert(
                                "linked-certificate-id".to_string(),
                                serde_json::to_value(v).unwrap_or_default(),
                            );
                        });
                }
            }
        }
        let json = serde_json::to_string_pretty(&results)?;

        if let Some(output_file) = &self.output_file {
            debug!("GetAttributes response for {unique_identifier}: {}", json);
            write_bytes_to_file(&json.as_bytes(), output_file)?;
            println!(
                "The attributes for {unique_identifier} were exported to {:?}",
                &output_file
            );
        } else {
            println!("Attributes for {unique_identifier}:");
            println!("{}", json);
        }
        Ok(())
    }
}

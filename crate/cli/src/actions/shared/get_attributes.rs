use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        extra::{tagging::VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
        kmip_operations::{GetAttributes, GetAttributesResponse},
        kmip_types::{
            AttributeReference, LinkType, Tag, UniqueIdentifier, VendorAttributeReference,
        },
    },
    KmsRestClient,
};
use cosmian_kms_client::{write_bytes_to_file, KmsClient};
use serde_json::Value;
use tracing::debug;

use crate::{cli_bail, error::CliError};

#[derive(clap::ValueEnum, Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributeTag {
    ActivationDate,
    CryptographicAlgorithm,
    CryptographicLength,
    CryptographicParameters,
    CryptographicDomainParameters,
    CryptographicUsageMask,
    KeyFormatType,
    LinkedPrivateKeyId,
    LinkedPublicKeyId,
    LinkedIssuerCertificateId,
    LinkedCertificateId,
    Tags,
}

const ALL_ATTRIBUTE_TAGS: [AttributeTag; 12] = [
    AttributeTag::ActivationDate,
    AttributeTag::CryptographicAlgorithm,
    AttributeTag::CryptographicLength,
    AttributeTag::CryptographicParameters,
    AttributeTag::CryptographicDomainParameters,
    AttributeTag::CryptographicUsageMask,
    AttributeTag::KeyFormatType,
    AttributeTag::LinkedPrivateKeyId,
    AttributeTag::LinkedPublicKeyId,
    AttributeTag::LinkedIssuerCertificateId,
    AttributeTag::LinkedCertificateId,
    AttributeTag::Tags,
];

/// Get the KMIP object attributes and tags.
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

    /// The attributes or tags to retrieve.
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
    pub async fn process(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
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
                    references.push(AttributeReference::Standard(Tag::ActivationDate));
                }
                AttributeTag::CryptographicAlgorithm => {
                    references.push(AttributeReference::Standard(Tag::CryptographicAlgorithm));
                }
                AttributeTag::CryptographicLength => {
                    references.push(AttributeReference::Standard(Tag::CryptographicLength));
                }
                AttributeTag::CryptographicParameters => {
                    references.push(AttributeReference::Standard(Tag::CryptographicParameters));
                }
                AttributeTag::CryptographicDomainParameters => references.push(
                    AttributeReference::Standard(Tag::CryptographicDomainParameters),
                ),
                AttributeTag::CryptographicUsageMask => {
                    references.push(AttributeReference::Standard(Tag::CryptographicUsageMask));
                }
                AttributeTag::KeyFormatType => {
                    references.push(AttributeReference::Standard(Tag::KeyFormatType));
                }
                AttributeTag::LinkedPrivateKeyId => {
                    references.push(AttributeReference::Standard(Tag::PrivateKey));
                }
                AttributeTag::LinkedPublicKeyId => {
                    references.push(AttributeReference::Standard(Tag::PublicKey));
                }
                AttributeTag::LinkedIssuerCertificateId => {
                    references.push(AttributeReference::Standard(Tag::Certificate));
                }
                AttributeTag::LinkedCertificateId => {
                    references.push(AttributeReference::Standard(Tag::Certificate));
                }
                AttributeTag::Tags => {
                    references.push(AttributeReference::Vendor(VendorAttributeReference {
                        vendor_identification: VENDOR_ID_COSMIAN.to_string(),
                        attribute_name: VENDOR_ATTR_TAG.to_string(),
                    }));
                }
            }
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

        // if no tag asked -> return values for all possible tags
        let tags = if self.attribute_tags.is_empty() {
            ALL_ATTRIBUTE_TAGS.to_vec()
        } else {
            self.attribute_tags.clone()
        };
        let mut results: HashMap<String, Value> = HashMap::new();
        for tag in &tags {
            match tag {
                AttributeTag::ActivationDate => {
                    if let Some(v) = attributes.activation_date.as_ref() {
                        results.insert(
                            "activation-date".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::CryptographicAlgorithm => {
                    if let Some(v) = attributes.cryptographic_algorithm.as_ref() {
                        results.insert(
                            "cryptographic-algorithm".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::CryptographicLength => {
                    if let Some(v) = attributes.cryptographic_length.as_ref() {
                        results.insert(
                            "cryptographic-length".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::CryptographicParameters => {
                    if let Some(v) = attributes.cryptographic_parameters.as_ref() {
                        results.insert(
                            "cryptographic-parameters".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::CryptographicDomainParameters => {
                    if let Some(v) = attributes.cryptographic_domain_parameters.as_ref() {
                        results.insert(
                            "cryptographic-domain-parameters".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::CryptographicUsageMask => {
                    if let Some(v) = attributes.cryptographic_usage_mask.as_ref() {
                        results.insert(
                            "cryptographic-usage-mask".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::KeyFormatType => {
                    if let Some(v) = attributes.key_format_type.as_ref() {
                        results.insert(
                            "key-format-type".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::LinkedPrivateKeyId => {
                    if let Some(v) = attributes.get_link(LinkType::PrivateKeyLink) {
                        results.insert(
                            "linked-private-key-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::LinkedPublicKeyId => {
                    if let Some(v) = attributes.get_link(LinkType::PublicKeyLink) {
                        results.insert(
                            "linked-public-key-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::LinkedIssuerCertificateId => {
                    if let Some(v) = attributes.get_link(LinkType::CertificateLink) {
                        results.insert(
                            "linked-issuer-certificate-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::LinkedCertificateId => {
                    if let Some(v) = attributes.get_link(LinkType::PKCS12CertificateLink) {
                        results.insert(
                            "linked-certificate-id".to_string(),
                            serde_json::to_value(v).unwrap_or_default(),
                        );
                    }
                }
                AttributeTag::Tags => {
                    if let Some(v) =
                        attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
                    {
                        results.insert(
                            "tags".to_string(),
                            serde_json::from_slice::<Value>(v).unwrap_or_default(),
                        );
                    }
                }
            }
        }
        let json = serde_json::to_string_pretty(&results)?;

        if let Some(output_file) = &self.output_file {
            debug!("GetAttributes response for {unique_identifier}: {}", json);
            write_bytes_to_file(json.as_bytes(), output_file)?;
            println!(
                "The attributes for {unique_identifier} were exported to {:?}",
                &output_file
            );
        } else {
            println!("Attributes for {unique_identifier}:");
            println!("{json}");
        }
        Ok(())
    }
}

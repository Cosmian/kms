use std::convert::TryFrom;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::kmip::kmip_types::UniqueIdentifier,
    kmip::{
        kmip_operations::{SetAttribute, SetAttributeResponse},
        kmip_types::{
            self, Attribute, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier,
            VendorAttribute,
        },
    },
    KmsClient,
};
use serde::Deserialize;
use tracing::{info, trace};

use crate::{
    actions::{
        console,
        shared::utils::{build_usage_mask_from_key_usage, KeyUsage},
    },
    cli_bail,
    error::result::CliResult,
};

#[derive(Parser, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct VendorAttributeCli {
    /// The vendor identification.
    #[clap(long, short = 'v', requires = "attribute_name")]
    pub vendor_identification: Option<String>,
    /// The attribute name.
    #[clap(long, short = 'n', requires = "vendor_identification")]
    pub attribute_name: Option<String>,
    /// The attribute value (in hex format).
    #[clap(long, requires = "vendor_identification")]
    pub attribute_value: Option<String>,
}

impl TryFrom<&VendorAttributeCli> for Attribute {
    type Error = crate::error::CliError;

    fn try_from(vendor_attribute: &VendorAttributeCli) -> Result<Self, Self::Error> {
        let vendor_attribute = kmip_types::VendorAttribute {
            vendor_identification: vendor_attribute
                .vendor_identification
                .clone()
                .unwrap_or_default(),
            attribute_name: vendor_attribute.attribute_name.clone().unwrap_or_default(),
            attribute_value: hex::decode(
                vendor_attribute.attribute_value.clone().unwrap_or_default(),
            )?,
        };
        Ok(Self::VendorAttributes(vec![vendor_attribute]))
    }
}

impl TryFrom<&VendorAttributeCli> for VendorAttribute {
    type Error = crate::error::CliError;

    fn try_from(vendor_attribute: &VendorAttributeCli) -> Result<Self, Self::Error> {
        let vendor_attribute = Self {
            vendor_identification: vendor_attribute
                .vendor_identification
                .clone()
                .unwrap_or_default(),
            attribute_name: vendor_attribute.attribute_name.clone().unwrap_or_default(),
            attribute_value: hex::decode(
                vendor_attribute.attribute_value.clone().unwrap_or_default(),
            )?,
        };
        Ok(vendor_attribute)
    }
}

#[derive(Parser, Default, Debug)]
pub struct SetOrDeleteAttributes {
    /// The unique identifier of the cryptographic object.
    /// If not specified, tags should be specified
    #[clap(long = "id", short = 'i', group = "id-tags")]
    pub(crate) id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "id-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// Set the activation date of the key. Epoch time (or Unix time) in milliseconds.
    #[clap(long, short = 'd')]
    pub(crate) activation_date: Option<u64>,

    /// The cryptographic algorithm used by the key.
    #[clap(long, short = 'a')]
    pub(crate) cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// The length of the cryptographic key.
    #[clap(long)]
    pub(crate) cryptographic_length: Option<i32>,

    /// The key usage. Add multiple times to specify multiple key usages.
    #[clap(long, short = 'u')]
    pub(crate) key_usage: Option<Vec<KeyUsage>>,

    /// The link to the corresponding public key id if any.
    #[clap(long)]
    pub(crate) public_key_id: Option<String>,

    /// The link to the corresponding private key id if any.
    #[clap(long)]
    pub(crate) private_key_id: Option<String>,

    /// The link to the corresponding certificate id if any.
    #[clap(long)]
    pub(crate) certificate_id: Option<String>,

    /// The link to the corresponding PKCS12 certificate id if any.
    #[clap(long = "p12-id")]
    pub(crate) pkcs12_certificate_id: Option<String>,

    /// The link to the corresponding PKCS12 password certificate if any.
    #[clap(long = "p12-pwd")]
    pub(crate) pkcs12_password_certificate: Option<String>,

    /// The link to the corresponding parent id if any.
    #[clap(long)]
    pub(crate) parent_id: Option<String>,

    /// The link to the corresponding child id if any.
    #[clap(long)]
    pub(crate) child_id: Option<String>,

    #[clap(flatten)]
    pub vendor_attributes: Option<VendorAttributeCli>,
}

impl SetOrDeleteAttributes {
    pub(crate) fn get_attributes_from_args(&self) -> CliResult<Vec<Attribute>> {
        let mut result = Vec::new();

        if let Some(activation_date) = &self.activation_date {
            let attribute = Attribute::ActivationDate(*activation_date);
            result.push(attribute);
        }

        if let Some(cryptographic_algorithm) = &self.cryptographic_algorithm {
            let attribute = Attribute::CryptographicAlgorithm(cryptographic_algorithm.to_owned());
            result.push(attribute);
        }

        if let Some(cryptographic_length) = &self.cryptographic_length {
            let attribute = Attribute::CryptographicLength(*cryptographic_length);
            result.push(attribute);
        }

        if let Some(key_usage) = &self.key_usage {
            let cryptographic_usage_mask =
                build_usage_mask_from_key_usage(key_usage).ok_or_else(|| {
                    crate::error::CliError::Conversion(format!(
                        "Could not convert {key_usage:?} to cryptographic usage mask"
                    ))
                })?;
            let attribute = Attribute::CryptographicUsageMask(cryptographic_usage_mask);
            result.push(attribute);
        }

        if let Some(public_key_id) = &self.public_key_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::PublicKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(public_key_id.clone()),
            }]);
            result.push(attribute);
        }

        if let Some(private_key_id) = &self.private_key_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::PrivateKeyLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    private_key_id.clone(),
                ),
            }]);
            result.push(attribute);
        }

        if let Some(certificate_id) = &self.certificate_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    certificate_id.clone(),
                ),
            }]);
            result.push(attribute);
        }

        if let Some(pkcs12_certificate_id) = &self.pkcs12_certificate_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::PKCS12CertificateLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    pkcs12_certificate_id.clone(),
                ),
            }]);
            result.push(attribute);
        }

        if let Some(pkcs12_password_certificate) = &self.pkcs12_password_certificate {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::PKCS12PasswordLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(
                    pkcs12_password_certificate.clone(),
                ),
            }]);
            result.push(attribute);
        }

        if let Some(parent_id) = &self.parent_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::ParentLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(parent_id.clone()),
            }]);
            result.push(attribute);
        }

        if let Some(child_id) = &self.child_id {
            let attribute = Attribute::Links(vec![Link {
                link_type: LinkType::ChildLink,
                linked_object_identifier: LinkedObjectIdentifier::TextString(child_id.clone()),
            }]);
            result.push(attribute);
        }

        if let Some(vendor_attributes) = &self.vendor_attributes {
            let attribute = Attribute::try_from(vendor_attributes)?;
            result.push(attribute);
        }

        Ok(result)
    }
}

/// Set the KMIP object attributes.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SetAttributesAction {
    #[clap(flatten)]
    requested_attributes: SetOrDeleteAttributes,
}

impl SetAttributesAction {
    async fn set_attribute(
        &self,
        kms_rest_client: &KmsClient,
        id: &str,
        attribute: Attribute,
    ) -> CliResult<()> {
        let SetAttributeResponse { unique_identifier } = kms_rest_client
            .set_attribute(SetAttribute {
                unique_identifier: Some(UniqueIdentifier::TextString(id.to_owned())),
                new_attribute: attribute.clone(),
            })
            .await?;
        info!("SetAttributes response for {unique_identifier}: {attribute:?}");
        let mut stdout = console::Stdout::new("Attribute set successfully");
        stdout.set_tags(self.requested_attributes.tags.as_ref());
        stdout.set_unique_identifier(id);
        stdout.set_attribute(attribute);
        stdout.write()?;
        Ok(())
    }

    /// Processes the `SetAttributes` action.
    ///
    /// # Errors
    ///
    /// This function can return a `CliError` if one of the following conditions occur:
    ///
    /// - Either `--id` or one or more `--tag` must be specified.
    ///
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        trace!("SetAttributeAction: {:?}", self);
        let id = if let Some(key_id) = &self.requested_attributes.id {
            key_id.clone()
        } else if let Some(tags) = &self.requested_attributes.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --id or one or more --tag must be specified")
        };

        let attributes_to_set = self.requested_attributes.get_attributes_from_args()?;
        if attributes_to_set.is_empty() {
            cli_bail!("No attribute specified")
        }

        for attribute in attributes_to_set {
            self.set_attribute(kms_rest_client, &id, attribute).await?;
        }

        Ok(())
    }
}

use std::{convert::TryFrom, fmt::Display};

use clap::{Parser, ValueEnum};
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier,
    kmip_2_1::{
        kmip_attributes::Attribute,
        kmip_operations::{SetAttribute, SetAttributeResponse},
        kmip_types::{
            self, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier, Name, NameType,
            VendorAttribute, VendorAttributeValue,
        },
    },
    reexport::cosmian_kms_client_utils::import_utils::{KeyUsage, build_usage_mask_from_key_usage},
};
use cosmian_logger::{info, trace};
use serde::Deserialize;
use strum::EnumIter;
use time::OffsetDateTime;

use crate::{
    actions::{console, labels::ATTRIBUTE_ID, shared::get_key_uid},
    cli_bail,
    error::result::KmsCliResult,
};

#[derive(ValueEnum, Clone, Copy, Debug, EnumIter)]
pub enum CCryptographicAlgorithm {
    AES,
    /// This is `CKM_RSA_PKCS_OAEP` from PKCS#11
    /// see <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
    /// To use  `CKM_RSA_AES_KEY_WRAP` from PKCS#11, use and RSA key with AES as the algorithm
    /// See <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226908
    RSA,
    ECDSA,
    ECDH,
    EC,
    Chacha20,
    Chacha20Poly1305,
    SHA3224,
    SHA3256,
    SHA3384,
    SHA3512,
    Ed25519,
    Ed448,
    Covercrypt,
    CovercryptBulk,
}

impl Display for CCryptographicAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::AES => "aes",
            Self::RSA => "rsa",
            Self::ECDSA => "ecdsa",
            Self::ECDH => "ecdh",
            Self::EC => "ec",
            Self::Chacha20 => "chacha20",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::SHA3224 => "sha3224",
            Self::SHA3256 => "sha3256",
            Self::SHA3384 => "sha3384",
            Self::SHA3512 => "sha3512",
            Self::Ed25519 => "ed25519",
            Self::Ed448 => "ed448",
            Self::Covercrypt => "covercrypt",
            Self::CovercryptBulk => "covercrypt-bulk",
        };
        write!(f, "{value}")
    }
}

impl From<CCryptographicAlgorithm> for CryptographicAlgorithm {
    fn from(value: CCryptographicAlgorithm) -> Self {
        match value {
            CCryptographicAlgorithm::AES => Self::AES,
            CCryptographicAlgorithm::RSA => Self::RSA,
            CCryptographicAlgorithm::ECDSA => Self::ECDSA,
            CCryptographicAlgorithm::ECDH => Self::ECDH,
            CCryptographicAlgorithm::EC => Self::EC,
            CCryptographicAlgorithm::Chacha20 => Self::ChaCha20,
            CCryptographicAlgorithm::Chacha20Poly1305 => Self::ChaCha20Poly1305,
            CCryptographicAlgorithm::SHA3224 => Self::SHA3224,
            CCryptographicAlgorithm::SHA3256 => Self::SHA3256,
            CCryptographicAlgorithm::SHA3384 => Self::SHA3384,
            CCryptographicAlgorithm::SHA3512 => Self::SHA3512,
            CCryptographicAlgorithm::Ed25519 => Self::Ed25519,
            CCryptographicAlgorithm::Ed448 => Self::Ed448,
            CCryptographicAlgorithm::Covercrypt => Self::CoverCrypt,
            CCryptographicAlgorithm::CovercryptBulk => Self::CoverCryptBulk,
        }
    }
}

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
    type Error = crate::error::KmsCliError;

    fn try_from(vendor_attribute: &VendorAttributeCli) -> Result<Self, Self::Error> {
        let vendor_attribute = kmip_types::VendorAttribute {
            vendor_identification: vendor_attribute
                .vendor_identification
                .clone()
                .unwrap_or_default(),
            attribute_name: vendor_attribute.attribute_name.clone().unwrap_or_default(),
            attribute_value: VendorAttributeValue::ByteString(hex::decode(
                vendor_attribute.attribute_value.clone().unwrap_or_default(),
            )?),
        };
        Ok(Self::VendorAttribute(vendor_attribute))
    }
}

impl TryFrom<&VendorAttributeCli> for VendorAttribute {
    type Error = crate::error::KmsCliError;

    fn try_from(vendor_attribute: &VendorAttributeCli) -> Result<Self, Self::Error> {
        let vendor_attribute = Self {
            vendor_identification: vendor_attribute
                .vendor_identification
                .clone()
                .unwrap_or_default(),
            attribute_name: vendor_attribute.attribute_name.clone().unwrap_or_default(),
            attribute_value: VendorAttributeValue::ByteString(hex::decode(
                vendor_attribute.attribute_value.clone().unwrap_or_default(),
            )?),
        };
        Ok(vendor_attribute)
    }
}

#[derive(Parser, Default, Debug, Clone)]
pub struct SetOrDeleteAttributes {
    /// The unique identifier of the cryptographic object.
    /// If not specified, tags should be specified
    #[clap(long = ATTRIBUTE_ID, short = 'i', group = "id-tags")]
    pub id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "id-tags")]
    pub tags: Option<Vec<String>>,

    /// Set the activation date of the key. Epoch time (or Unix time) in milliseconds.
    #[clap(long, short = 'd')]
    pub activation_date: Option<i64>,

    /// The cryptographic algorithm used by the key.
    #[clap(long, short = 'a')]
    pub cryptographic_algorithm: Option<CCryptographicAlgorithm>,

    /// The length of the cryptographic key.
    #[clap(long)]
    pub cryptographic_length: Option<i32>,

    /// The key usage. Add multiple times to specify multiple key usages.
    #[clap(long, short = 'u')]
    pub key_usage: Option<Vec<KeyUsage>>,

    /// The link to the corresponding public key id if any.
    #[clap(long)]
    pub public_key_id: Option<String>,

    /// The link to the corresponding private key id if any.
    #[clap(long)]
    pub private_key_id: Option<String>,

    /// The link to the corresponding certificate id if any.
    #[clap(long)]
    pub certificate_id: Option<String>,

    /// The link to the corresponding PKCS12 certificate id if any.
    #[clap(long = "p12-id")]
    pub pkcs12_certificate_id: Option<String>,

    /// The link to the corresponding PKCS12 password certificate if any.
    #[clap(long = "p12-pwd")]
    pub pkcs12_password_certificate: Option<String>,

    /// The link to the corresponding parent id if any.
    #[clap(long)]
    pub parent_id: Option<String>,

    /// The link to the corresponding child id if any.
    #[clap(long)]
    pub child_id: Option<String>,

    /// The name of the object (standard KMIP Name attribute).
    /// The name is stored as an `UninterpretedTextString` by default.
    #[clap(long = "name")]
    pub name: Option<String>,

    /// The Sensitive attribute (True/False). When set to True the object value
    /// can only be retrieved wrapped. Setting it to False permanently clears the
    /// server-managed Always Sensitive attribute (KMIP 2.1 §4.3).
    #[clap(long)]
    pub sensitive: Option<bool>,

    #[clap(flatten)]
    pub vendor_attributes: Option<VendorAttributeCli>,
}

/// Push a `Link` attribute into the result vector if the field is `Some`.
macro_rules! push_link {
    ($self:expr, $result:expr, $field:ident, $link_type:expr) => {
        if let Some(id) = &$self.$field {
            $result.push(Attribute::Link(Link {
                link_type: $link_type,
                linked_object_identifier: LinkedObjectIdentifier::TextString(id.clone()),
            }));
        }
    };
}

impl SetOrDeleteAttributes {
    pub(crate) fn get_attributes_from_args(&self) -> KmsCliResult<Vec<Attribute>> {
        let mut result = Vec::new();

        if let Some(timestamp) = self.activation_date {
            let activation_date = OffsetDateTime::from_unix_timestamp(timestamp).map_err(|e| {
                crate::error::KmsCliError::Conversion(format!(
                    "Could not convert {timestamp:?} to OffsetDateTime: {e:?}"
                ))
            })?;
            result.push(Attribute::ActivationDate(activation_date));
        }

        if let Some(cryptographic_algorithm) = &self.cryptographic_algorithm {
            result.push(Attribute::CryptographicAlgorithm(
                CryptographicAlgorithm::from(cryptographic_algorithm.to_owned()),
            ));
        }

        if let Some(cryptographic_length) = &self.cryptographic_length {
            result.push(Attribute::CryptographicLength(*cryptographic_length));
        }

        if let Some(key_usage) = &self.key_usage {
            let cryptographic_usage_mask =
                build_usage_mask_from_key_usage(key_usage).ok_or_else(|| {
                    crate::error::KmsCliError::Conversion(format!(
                        "Could not convert {key_usage:?} to cryptographic usage mask"
                    ))
                })?;
            result.push(Attribute::CryptographicUsageMask(cryptographic_usage_mask));
        }

        push_link!(self, result, public_key_id, LinkType::PublicKeyLink);
        push_link!(self, result, private_key_id, LinkType::PrivateKeyLink);
        push_link!(self, result, certificate_id, LinkType::CertificateLink);
        push_link!(
            self,
            result,
            pkcs12_certificate_id,
            LinkType::PKCS12CertificateLink
        );
        push_link!(
            self,
            result,
            pkcs12_password_certificate,
            LinkType::PKCS12PasswordLink
        );
        push_link!(self, result, parent_id, LinkType::ParentLink);
        push_link!(self, result, child_id, LinkType::ChildLink);

        if let Some(name_value) = &self.name {
            result.push(Attribute::Name(Name {
                name_value: name_value.clone(),
                name_type: NameType::UninterpretedTextString,
            }));
        }

        if let Some(sensitive) = self.sensitive {
            result.push(Attribute::Sensitive(sensitive));
        }

        if let Some(vendor_attributes) = &self.vendor_attributes {
            result.push(Attribute::try_from(vendor_attributes)?);
        }

        Ok(result)
    }
}

/// Set the KMIP object attributes.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SetAttributesAction {
    #[clap(flatten)]
    pub(crate) requested_attributes: SetOrDeleteAttributes,
}

impl SetAttributesAction {
    pub(crate) async fn set_attribute(
        &self,
        kms_rest_client: &KmsClient,
        id: &str,
        attribute: Attribute,
    ) -> KmsCliResult<()> {
        let id = UniqueIdentifier::TextString(id.to_owned());
        let SetAttributeResponse { unique_identifier } = kms_rest_client
            .set_attribute(SetAttribute {
                unique_identifier: Some(id.clone()),
                new_attribute: attribute.clone(),
            })
            .await?;
        info!("SetAttributes response for {unique_identifier}: {attribute}");
        let mut stdout = console::Stdout::new("Attribute set successfully");
        stdout.set_tags(self.requested_attributes.tags.as_ref());
        stdout.set_unique_identifier(&id);
        stdout.set_attribute(attribute);
        stdout.write()?;
        Ok(())
    }

    /// Processes the `SetAttributes` action.
    ///
    /// # Errors
    ///
    /// This function can return a `KmsCliError` if one of the following conditions occur:
    ///
    /// - Either `--id` or one or more `--tag` must be specified.
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        trace!("{self:?}");
        let id = get_key_uid(
            self.requested_attributes.id.as_ref(),
            self.requested_attributes.tags.as_ref(),
            ATTRIBUTE_ID,
        )?;

        let attributes_to_set = self.requested_attributes.get_attributes_from_args()?;
        if attributes_to_set.is_empty() {
            cli_bail!("No attribute specified")
        }

        for attribute in attributes_to_set {
            self.set_attribute(&kms_rest_client, &id, attribute).await?;
        }

        Ok(())
    }
}

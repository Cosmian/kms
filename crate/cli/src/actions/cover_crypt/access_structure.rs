use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use cosmian_cover_crypt::{AccessStructure, EncryptionHint, MasterPublicKey, QualifiedAttribute};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kms_client::{
    cosmian_kmip::KmipResultHelper,
    export_object,
    kmip_2_1::{
        kmip_objects::Object,
        ttlv::{deserializer::from_ttlv, TTLV},
    },
    read_from_json_file, ExportObjectParams, KmsClient,
};
use cosmian_kms_crypto::{
    crypto::cover_crypt::{
        attributes::RekeyEditAction, kmip_requests::build_rekey_keypair_request,
    },
    CryptoError,
};
use tracing::debug;

use crate::{actions::console, cli_bail, error::result::CliResult};

pub(crate) fn access_structure_from_json_file(
    specs_filename: &impl AsRef<Path>,
) -> CliResult<AccessStructure> {
    let access_structure_json: HashMap<String, Vec<String>> = read_from_json_file(&specs_filename)?;

    let mut access_structure = AccessStructure::new();
    for (dimension, attributes) in &access_structure_json {
        if dimension.contains("::<") {
            let trim_key_name = dimension.trim_end_matches("::<");
            access_structure.add_hierarchy(trim_key_name.to_owned())?;
        } else {
            access_structure.add_anarchy(dimension.clone())?;
        }

        for name in attributes.iter().rev() {
            let attribute = QualifiedAttribute {
                dimension: dimension.trim_end_matches("::<").to_owned(),
                name: name.trim_end_matches("::+").to_owned(),
            };
            let encryption_hint = if name.contains("::+") {
                EncryptionHint::Hybridized
            } else {
                EncryptionHint::Classic
            };
            debug!("cli parsing: attribute: {attribute:?}, encryption_hint: {encryption_hint:?}");
            access_structure.add_attribute(attribute, encryption_hint, None)?;
        }
    }

    Ok(access_structure)
}

/// Extract, view, or edit policies of existing keys
#[derive(Subcommand)]
pub enum AccessStructureCommands {
    View(ViewAction),
    AddAttribute(AddAttributeAction),
    RemoveAttribute(RemoveAttributeAction),
    DisableAttribute(DisableAttributeAction),
    RenameAttribute(RenameAttributeAction),
}

impl AccessStructureCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::View(action) => action.run(kms_rest_client).await?,
            Self::AddAttribute(action) => action.run(kms_rest_client).await?,
            Self::RemoveAttribute(action) => action.run(kms_rest_client).await?,
            Self::DisableAttribute(action) => action.run(kms_rest_client).await?,
            Self::RenameAttribute(action) => action.run(kms_rest_client).await?,
        }

        Ok(())
    }
}
/// View the access structure of an existing public or private master key.
///
///  - Use the `--key-id` switch to extract the access structure from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the access structure from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ViewAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in TTLV format.²
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// Show all the access structure details rather than just the specifications
    #[clap(
        required = false,
        long = "detailed",
        short = 'd',
        default_value = "false"
    )]
    detailed: bool,
}
impl ViewAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let object: Object = if self.key_id.is_some() {
            export_object(
                kms_rest_client,
                &self
                    .key_id
                    .clone()
                    .ok_or_else(|| CryptoError::Default("ID".to_owned()))?,
                ExportObjectParams {
                    unwrap: true,
                    ..ExportObjectParams::default()
                },
            )
            .await?
            .1
        } else if self.key_file.is_some() {
            let ttlv: TTLV = read_from_json_file(
                &self
                    .key_file
                    .clone()
                    .ok_or_else(|| CryptoError::Default("FILE".to_owned()))?,
            )?;
            from_ttlv(&ttlv)?
        } else {
            cli_bail!("either a key ID or a key TTLV file must be supplied");
        };
        let mpk = MasterPublicKey::deserialize(&object.key_block()?.key_bytes()?).map_err(|e| {
            CryptoError::Kmip(format!("Failed deserializing the CoverCrypt MPK: {e}"))
        })?;
        let stdout: String = format!("{:?}", mpk.access_structure);
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Add an attribute to the access structure of an existing private master key.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct AddAttributeAction {
    /// The name of the attribute to create.
    /// Example: `department::rd`
    #[clap(required = true)]
    attribute: String,

    /// Set encryption hint for the new attribute to use hybridized keys.
    #[clap(required = false, long = "hybridized", default_value = "false")]
    hybridized: bool,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}
impl AddAttributeAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        let enc_hint = EncryptionHint::new(self.hybridized);

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::AddAttribute(vec![(
                QualifiedAttribute::from((self.attribute.as_str(), "")),
                enc_hint,
                None,
            )]),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed adding an attribute to the master keys")?;

        let stdout = format!(
            "New attribute {} was successfully added to the master private key {} and master \
             public key {}.",
            &self.attribute,
            &rekey_response.private_key_unique_identifier,
            &rekey_response.public_key_unique_identifier,
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Rename an attribute in the access structure of an existing private master key.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct RenameAttributeAction {
    /// The name of the attribute to rename.
    /// Example: `department::mkg`
    #[clap(required = true)]
    attribute: String,

    /// The new name for the attribute.
    /// Example: `marketing`
    #[clap(required = true)]
    new_name: String,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}
impl RenameAttributeAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::RenameAttribute(vec![(
                QualifiedAttribute::from((self.attribute.as_str(), "")),
                self.new_name.clone(),
            )]),
        )?;

        // Query the KMS with your kmip data
        kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed renaming an attribute in the master keys' access structure")?;

        let stdout = format!(
            "Attribute {} was successfully renamed to {}.",
            &self.attribute, &self.new_name
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Disable an attribute from the access structure of an existing private master key.
/// Prevents the encryption of new messages for this attribute while keeping the ability to decrypt existing ciphertexts.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DisableAttributeAction {
    /// The name of the attribute to disable.
    /// Example: `department::marketing`
    #[clap(required = true)]
    attribute: String,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}
impl DisableAttributeAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::DisableAttribute(vec![QualifiedAttribute::from((
                self.attribute.as_str(),
                "",
            ))]),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed disabling an attribute from the master keys")?;

        let stdout = format!(
            "Attribute {} was successfully disabled from the master public key {}.",
            &self.attribute, &rekey_response.public_key_unique_identifier,
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Remove an attribute from the access structure of an existing private master key.
/// Permanently removes the ability to use this attribute in both encryptions and decryptions.
///
/// Note that messages whose encryption access structure does not contain any other attributes
/// belonging to the dimension of the deleted attribute will be lost.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct RemoveAttributeAction {
    /// The name of the attribute to remove.
    /// Example: `department::marketing`
    #[clap(required = true)]
    attribute: String,

    /// The private master key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,
}
impl RemoveAttributeAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let id = if let Some(key_id) = &self.secret_key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either --key-id or one or more --tag must be specified")
        };

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::DeleteAttribute(vec![QualifiedAttribute::new("dimension", "name")]),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed removing an attribute from the master keys")?;

        let stdout = format!(
            "Attribute {} was successfully removed from the master private key {} and master \
             public key {}.",
            &self.attribute,
            &rekey_response.private_key_unique_identifier,
            &rekey_response.public_key_unique_identifier,
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

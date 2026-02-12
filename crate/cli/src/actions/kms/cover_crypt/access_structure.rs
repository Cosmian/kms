use std::path::PathBuf;

use clap::{Parser, Subcommand};
use cosmian_kms_client::{
    ExportObjectParams, KmsClient,
    cosmian_kmip::{
        KmipResultHelper,
        ttlv::{TTLV, from_ttlv},
    },
    export_object,
    kmip_2_1::kmip_objects::Object,
    read_from_json_file,
};
use cosmian_kms_crypto::{
    CryptoError,
    crypto::cover_crypt::{
        attributes::RekeyEditAction, kmip_requests::build_rekey_keypair_request,
    },
    reexport::{
        cosmian_cover_crypt::{
            AccessStructure, EncryptionHint, MasterPublicKey, QualifiedAttribute,
        },
        cosmian_crypto_core::bytes_ser_de::Serializable,
    },
};

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    cli_bail,
    error::result::KmsCliResult,
};

/// Extract, view, or edit policies of existing keys
#[derive(Subcommand)]
pub enum AccessStructureCommands {
    View(ViewAction),
    AddAttribute(AddQualifiedAttributeAction),
    RemoveAttribute(RemoveAttributeAction),
    DisableAttribute(DisableAttributeAction),
    RenameAttribute(RenameAttributeAction),
}

impl AccessStructureCommands {
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::View(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::AddAttribute(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::RemoveAttribute(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::DisableAttribute(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::RenameAttribute(action) => {
                action.run(kms_rest_client).await?;
            }
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
    #[clap(long = KEY_ID, short = 'i', required_unless_present = "key_file")]
    pub(crate) key_id: Option<String>,

    /// If `key-id` is not provided, use `--key-file` to provide the file containing the public or private master key in TTLV format.
    #[clap(long = "key-file", short = 'f')]
    pub(crate) key_file: Option<PathBuf>,
}

impl ViewAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<AccessStructure> {
        let object: Object = if let Some(id) = &self.key_id {
            export_object(
                &kms_rest_client,
                id,
                ExportObjectParams {
                    unwrap: true,
                    ..ExportObjectParams::default()
                },
            )
            .await?
            .1
        } else if let Some(key_file) = &self.key_file {
            let ttlv: TTLV = read_from_json_file(key_file)?;
            from_ttlv(ttlv).map_err(|e| {
                CryptoError::Kmip(format!("Failed deserializing the CoverCrypt MPK: {e}"))
            })?
        } else {
            cli_bail!("either a key ID or a key TTLV file must be supplied");
        };
        let mpk = MasterPublicKey::deserialize(&object.key_block()?.covercrypt_key_bytes()?)
            .map_err(|e| {
                CryptoError::Kmip(format!("Failed deserializing the CoverCrypt MPK: {e}"))
            })?;

        let stdout: String = format!("{:?}", mpk.access_structure);
        console::Stdout::new(&stdout).write()?;

        Ok(mpk.access_structure)
    }
}

/// Add an attribute to the access structure of an existing private master key.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct AddQualifiedAttributeAction {
    /// The name of the attribute to create.
    /// Example: `department::rnd`
    #[clap(required = true)]
    pub(crate) attribute: String,

    /// Hybridize this qualified attribute.
    #[clap(required = false, long, default_value = "false")]
    pub(crate) hybridized: bool,

    /// The master secret key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl AddQualifiedAttributeAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let id = get_key_uid(self.secret_key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::AddAttribute(vec![(
                QualifiedAttribute::try_from(self.attribute.as_str())?,
                if self.hybridized {
                    EncryptionHint::Hybridized
                } else {
                    EncryptionHint::Classic
                },
                None,
            )]),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed adding an attribute to the master keys")?;

        let stdout = format!(
            "New attribute {} was successfully added to the master secret key {} and master \
             public key {}.",
            &self.attribute,
            &rekey_response.private_key_unique_identifier,
            &rekey_response.public_key_unique_identifier,
        );
        console::Stdout::new(&stdout).write()
    }
}

/// Rename an attribute in the access structure of an existing private master key.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct RenameAttributeAction {
    /// The name of the attribute to rename.
    /// Example: `department::mkg`
    #[clap(required = true)]
    pub(crate) attribute: String,

    /// The new name for the attribute.
    /// Example: `marketing`
    #[clap(required = true)]
    pub(crate) new_name: String,

    /// The master secret key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) master_secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RenameAttributeAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let id = get_key_uid(
            self.master_secret_key_id.as_ref(),
            self.tags.as_ref(),
            KEY_ID,
        )?;

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::RenameAttribute(vec![(
                QualifiedAttribute::try_from(self.attribute.as_str())?,
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

/// Disable an attribute from the access structure of an existing private master
/// key.
///
/// Prevents the creation of new ciphertexts for this attribute while keeping
/// the ability to decrypt existing ones.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct DisableAttributeAction {
    /// The name of the attribute to disable.
    /// Example: `department::marketing`
    #[clap(required = true)]
    pub(crate) attribute: String,

    /// The master secret key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) master_secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl DisableAttributeAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let id = get_key_uid(
            self.master_secret_key_id.as_ref(),
            self.tags.as_ref(),
            KEY_ID,
        )?;

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::DisableAttribute(vec![QualifiedAttribute::try_from(
                self.attribute.as_str(),
            )?]),
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
    /// Note: prevents ciphertexts only targeting this qualified attribute to be decrypted.
    #[clap(required = true)]
    pub(crate) attribute: String,

    /// The master secret key unique identifier stored in the KMS.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) master_secret_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,
}

impl RemoveAttributeAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let id = get_key_uid(
            self.master_secret_key_id.as_ref(),
            self.tags.as_ref(),
            KEY_ID,
        )?;

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::DeleteAttribute(vec![QualifiedAttribute::try_from(
                self.attribute.as_str(),
            )?]),
        )?;

        // Query the KMS with your kmip data
        let rekey_response = kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed removing an attribute from the master keys")?;

        let stdout = format!(
            "Attribute {} was successfully removed from the master secret key {} and master \
             public key {}.",
            &self.attribute,
            &rekey_response.private_key_unique_identifier,
            &rekey_response.public_key_unique_identifier,
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

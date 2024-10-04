use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use cloudproof::reexport::cover_crypt::abe_policy::{Attribute, EncryptionHint, Policy};
use cosmian_kms_client::{
    cosmian_kmip::{
        crypto::cover_crypt::{
            attributes::{policy_from_attributes, RekeyEditAction},
            kmip_requests::build_rekey_keypair_request,
        },
        kmip::{
            kmip_objects::Object,
            ttlv::{deserializer::from_ttlv, TTLV},
        },
    },
    export_object, read_bytes_from_file, read_from_json_file, write_json_object_to_file,
    ExportObjectParams, KmsClient,
};

use crate::{
    actions::console,
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

pub(crate) fn policy_from_binary_file(bin_filename: &impl AsRef<Path>) -> CliResult<Policy> {
    let policy_buffer = read_bytes_from_file(bin_filename)?;
    Policy::parse_and_convert(policy_buffer.as_slice()).with_context(|| {
        format!(
            "policy binary is malformed {}",
            bin_filename.as_ref().display()
        )
    })
}

pub(crate) fn policy_from_json_file(specs_filename: &impl AsRef<Path>) -> CliResult<Policy> {
    let policy_specs: HashMap<String, Vec<String>> = read_from_json_file(&specs_filename)?;
    policy_specs.try_into().with_context(|| {
        format!(
            "JSON policy is malformed {}",
            specs_filename.as_ref().display()
        )
    })
}

/// Extract, view, or edit policies of existing keys, and create a binary policy from specifications
#[derive(Subcommand)]
pub enum PolicyCommands {
    View(ViewAction),
    Specs(SpecsAction),
    Binary(BinaryAction),
    Create(CreateAction),
    AddAttribute(AddAttributeAction),
    RemoveAttribute(RemoveAttributeAction),
    DisableAttribute(DisableAttributeAction),
    RenameAttribute(RenameAttributeAction),
}

impl PolicyCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::View(action) => action.run(kms_rest_client).await?,
            Self::Specs(action) => action.run(kms_rest_client).await?,
            Self::Binary(action) => action.run(kms_rest_client).await?,
            Self::Create(action) => action.run()?,
            Self::AddAttribute(action) => action.run(kms_rest_client).await?,
            Self::RemoveAttribute(action) => action.run(kms_rest_client).await?,
            Self::DisableAttribute(action) => action.run(kms_rest_client).await?,
            Self::RenameAttribute(action) => action.run(kms_rest_client).await?,
        };

        Ok(())
    }
}

/// Create a policy binary file from policy specifications
///
/// The policy specifications must be passed as a JSON in a file, for example:
/// ```json
///     {
///        "Security Level::<": [
///            "Protected",
///            "Confidential",
///            "Top Secret::+"
///        ],
///        "Department": [
///            "R&D",
///            "HR",
///            "MKG",
///            "FIN"
///        ]
///    }
/// ```
/// These specifications create a policy where:
///  - the policy is defined with 2 policy axes: `Security Level` and `Department`
///  - the `Security Level` axis is hierarchical as indicated by the `::<` suffix,
///  - the `Security Level` axis has 3 possible values: `Protected`, `Confidential`, and `Top Secret`,
///  - the `Department` axis has 4 possible values: `R&D`, `HR`, `MKG`, and `FIN`,
///  - all partitions which are `Top Secret` will be encrypted using post-quantum hybridized cryptography, as indicated by the `::+` suffix on the value,
///  - all other partitions will use classic cryptography.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateAction {
    /// The policy specifications filename. The policy is expressed as a JSON object
    /// describing the Policy axes. See the documentation for
    /// details.
    #[clap(
        required = false,
        long = "specifications",
        short = 's',
        default_value = "policy_specifications.json"
    )]
    policy_specifications_file: PathBuf,

    /// The output binary policy file generated from the specifications file.
    #[clap(
        required = false,
        long = "policy",
        short = 'p',
        default_value = "policy.bin"
    )]
    policy_binary_file: PathBuf,
}

impl CreateAction {
    pub fn run(&self) -> CliResult<()> {
        // Parse the json policy file
        let policy = policy_from_json_file(&self.policy_specifications_file)?;

        // write the binary file
        write_json_object_to_file(&policy, &self.policy_binary_file)
            .with_context(|| "failed writing the policy binary file".to_owned())?;

        let stdout = format!(
            "The binary policy file was generated in {:?}.",
            &self.policy_binary_file
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Recover the Policy from a key store in the KMS or in a TTLV file
async fn recover_policy(
    key_id: Option<&str>,
    key_file: Option<&PathBuf>,
    unwrap: bool,
    kms_rest_client: &KmsClient,
) -> CliResult<Policy> {
    // Recover the KMIP Object
    let object: Object = if let Some(key_id) = key_id {
        export_object(
            kms_rest_client,
            key_id,
            ExportObjectParams {
                unwrap,
                ..ExportObjectParams::default()
            },
        )
        .await?
        .0
    } else if let Some(f) = key_file {
        let ttlv: TTLV = read_from_json_file(f)?;
        from_ttlv(&ttlv)?
    } else {
        cli_bail!("either a key ID or a key TTLV file must be supplied");
    };
    // Recover the policy
    policy_from_attributes(object.attributes()?)
        .with_context(|| "failed recovering the policy from the key")
}

/// Extract the policy specifications from a public or private master key to a policy specifications file
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct SpecsAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in JSON TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// The output policy specifications file.
    #[clap(
        required = false,
        long = "specifications",
        short = 's',
        default_value = "policy_specifications.json"
    )]
    policy_specs_file: PathBuf,
}
impl SpecsAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        let specs: HashMap<String, Vec<String>> = policy.try_into()?;
        // save the policy to the specifications file
        Ok(write_json_object_to_file(&specs, &self.policy_specs_file)?)
    }
}

/// Extract the policy from a public or private master key to a policy binary file
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct BinaryAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// The output binary policy file.
    #[clap(
        required = false,
        long = "policy",
        short = 'p',
        default_value = "policy.bin"
    )]
    policy_binary_file: PathBuf,
}
impl BinaryAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        // save the policy to the binary file
        Ok(write_json_object_to_file(
            &policy,
            &self.policy_binary_file,
        )?)
    }
}

/// View the policy of an existing public or private master key.
///
///  - Use the `--key-id` switch to extract the policy from a key stored in the KMS.
///  - Use the `--key-file` switch to extract the policy from a Key exported as TTLV.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct ViewAction {
    /// The public or private master key ID if the key is stored in the KMS
    #[clap(long = "key-id", short = 'i', required_unless_present = "key_file")]
    key_id: Option<String>,

    /// If `key-id` is not provided, the file containing the public or private master key in TTLV format.
    #[clap(long = "key-file", short = 'f')]
    key_file: Option<PathBuf>,

    /// Show all the policy details rather than just the specifications
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
        // Recover the policy
        let policy = recover_policy(
            self.key_id.as_deref(),
            self.key_file.as_ref(),
            true,
            kms_rest_client,
        )
        .await?;
        // get a pretty json and print it
        let json = if self.detailed {
            serde_json::to_string_pretty(&policy)?
        } else {
            let specs: HashMap<String, Vec<String>> = policy.try_into()?;
            serde_json::to_string_pretty(&specs)?
        };
        console::Stdout::new(&json).write()?;
        Ok(())
    }
}

/// Add an attribute to the policy of an existing private master key.
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

        let attr = Attribute::try_from(self.attribute.as_str())?;
        let enc_hint = EncryptionHint::new(self.hybridized);

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::AddAttribute(vec![(attr, enc_hint)]),
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

/// Rename an attribute in the policy of an existing private master key.
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

        let attr = Attribute::try_from(self.attribute.as_str())?;

        // Create the kmip query
        let rekey_query = build_rekey_keypair_request(
            &id,
            &RekeyEditAction::RenameAttribute(vec![(attr, self.new_name.clone())]),
        )?;

        // Query the KMS with your kmip data
        kms_rest_client
            .rekey_keypair(rekey_query)
            .await
            .with_context(|| "failed renaming an attribute in the master keys' policy")?;

        let stdout = format!(
            "Attribute {} was successfully renamed to {}.",
            &self.attribute, &self.new_name
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}

/// Disable an attribute from the policy of an existing private master key.
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

        let attr = Attribute::try_from(self.attribute.as_str())?;

        // Create the kmip query
        let rekey_query =
            build_rekey_keypair_request(&id, &RekeyEditAction::DisableAttribute(vec![attr]))?;

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

/// Remove an attribute from the policy of an existing private master key.
/// Permanently removes the ability to use this attribute in both encryptions and decryptions.
///
/// Note that messages whose encryption policy does not contain any other attributes
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

        let attr = Attribute::try_from(self.attribute.as_str())?;

        // Create the kmip query
        let rekey_query =
            build_rekey_keypair_request(&id, &RekeyEditAction::RemoveAttribute(vec![attr]))?;

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

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod tests {
    use std::path::PathBuf;

    use super::policy_from_binary_file;

    #[test]
    pub(crate) fn test_policy_bin_from_file() {
        //correct
        const CORRECT_FILE: &str = "test_data/policy.bin";
        let result = policy_from_binary_file(&PathBuf::from(CORRECT_FILE));
        assert!(result.is_ok(), "The policy should be ok");

        //file not found
        const WRONG_FILENAME: &str = "not_exist";
        let result = policy_from_binary_file(&PathBuf::from(WRONG_FILENAME));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("could not open the file {WRONG_FILENAME}"))
        );

        // malformed json
        const MALFORMED_FILE: &str = "test_data/policy.bad";
        let result = policy_from_binary_file(&PathBuf::from(MALFORMED_FILE));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("policy binary is malformed {MALFORMED_FILE}"))
        );

        // duplicate policies
        const DUPLICATED_POLICIES: &str = "test_data/policy.bad2";
        let result = policy_from_binary_file(&PathBuf::from(DUPLICATED_POLICIES));
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .starts_with(&format!("policy binary is malformed {DUPLICATED_POLICIES}"))
        );
    }
}

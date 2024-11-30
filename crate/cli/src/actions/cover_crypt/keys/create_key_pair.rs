use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::cover_crypt::kmip_requests::build_create_master_keypair_request,
    KmsClient,
};

use crate::{
    actions::{
        console,
        cover_crypt::policy::{policy_from_binary_file, policy_from_json_file},
    },
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Create a new master key pair for a given policy and return the key IDs.
///
///
///  - The master public key is used to encrypt the files and can be safely shared.
///  - The master secret key is used to generate user decryption keys and must be kept confidential.
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
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateMasterKeyPairAction {
    /// The JSON policy specifications file to use to generate the master keys.
    /// See the inline doc of the `create-master-key-pair` command for details.
    #[clap(long = "policy-specifications", short = 's', group = "policy")]
    policy_specifications_file: Option<PathBuf>,

    /// When not using policy specifications, a policy binary file can be used instead.
    /// See the `policy` command, to create this binary file from policy specifications
    /// or to extract it from existing keys.
    #[clap(long = "policy-binary", short = 'b', group = "policy")]
    policy_binary_file: Option<PathBuf>,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// Sensitive: if set, the private key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    sensitive: bool,
}

impl CreateMasterKeyPairAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Parse the json policy file
        let policy = if let Some(specs_file) = &self.policy_specifications_file {
            policy_from_json_file(specs_file)?
        } else if let Some(binary_file) = &self.policy_binary_file {
            policy_from_binary_file(binary_file)?
        } else {
            cli_bail!("either a policy specifications or policy binary file must be provided");
        };

        // Create the kmip query
        let create_key_pair =
            build_create_master_keypair_request(&policy, &self.tags, self.sensitive)?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair)
            .await
            .with_context(|| "failed creating a Covercrypt Master Key Pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        let mut stdout = console::Stdout::new("The master key pair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            private_key_unique_identifier,
            public_key_unique_identifier,
        );
        stdout.write()?;

        Ok(())
    }
}

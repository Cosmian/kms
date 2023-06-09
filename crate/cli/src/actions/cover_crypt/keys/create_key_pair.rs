use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::cover_crypt::kmip_requests::build_create_master_keypair_request;

use crate::{
    actions::cover_crypt::policy::{policy_from_binary_file, policy_from_specifications_file},
    cli_bail,
    error::{result::CliResultHelper, CliError},
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
}

impl CreateMasterKeyPairAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // Parse the json policy file
        let policy = if let Some(specs_file) = &self.policy_specifications_file {
            policy_from_specifications_file(specs_file)?
        } else if let Some(binary_file) = &self.policy_binary_file {
            policy_from_binary_file(binary_file)?
        } else {
            cli_bail!("either a policy specifications or policy binary file must be provided");
        };

        // Create the kmip query
        let create_key_pair = build_create_master_keypair_request(&policy)?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = client_connector
            .create_key_pair(create_key_pair)
            .await
            .with_context(|| "failed creating a Covercrypt Master Key Pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;

        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        println!("The master key pair has been properly generated.");
        println!("Store the followings securely for any further uses:\n");
        println!("  Private key unique identifier: {private_key_unique_identifier}\n");
        println!("  Public key unique identifier : {public_key_unique_identifier}");

        Ok(())
    }
}

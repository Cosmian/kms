use std::{fs::File, io::BufReader, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::KmsClient;
use cosmian_kms_crypto::crypto::cover_crypt::kmip_requests::build_create_covercrypt_master_keypair_request;
use serde::{Deserialize, Serialize};

use crate::{
    actions::console,
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
    /// The JSON policy specifications file to use to generate the keys.
    /// See the inline doc of the `create-master-key-pair` command for details.
    #[clap(long = "policy-specifications", short = 's', group = "policy")]
    policy_specifications_file: PathBuf,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,

    /// Sensitive: if set, the private key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    sensitive: bool,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicySpecs {
    #[serde(rename = "Security Level::<")]
    pub security_level: Vec<String>,
    #[serde(rename = "Department")]
    pub department: Vec<String>,
}

impl CreateMasterKeyPairAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let file = File::open(&self.policy_specifications_file)?;
        let buffer_reader = BufReader::new(file);
        let json_policy: PolicySpecs = serde_json::from_reader(buffer_reader)?;

        let access_structure: Vec<(String, Vec<String>)> = vec![
            ("Security Level".to_string(), json_policy.security_level),
            ("Department".to_string(), json_policy.department),
        ];
        let create_key_pair = build_create_covercrypt_master_keypair_request(
            &self.tags,
            self.sensitive,
            access_structure,
        )?;

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

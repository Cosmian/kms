use std::path::PathBuf;

use clap::Parser;
use cosmian_cover_crypt::MasterSecretKey;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kms_client::{read_bytes_from_file, KmsClient};
use cosmian_kms_crypto::{
    crypto::cover_crypt::kmip_requests::build_create_covercrypt_master_keypair_request, CryptoError,
};

use crate::{
    actions::console,
    error::{
        result::{CliResult, CliResultHelper},
        CliError,
    },
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
    policy_specifications_file: Option<PathBuf>,

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

        let file = &self
            .policy_specifications_file
            .clone()
            .ok_or_else(|| CliError::Default("File not found".to_string()))?;
        let policy_buffer = read_bytes_from_file(&file)?;
        let msk = MasterSecretKey::deserialize(&policy_buffer).map_err(|e| {
            CryptoError::Kmip(format!(
                "Failed deserializing the CoverCrypt Master Private Key: {e}"
            ))
        })?;
        // Create the kmip query
        let access_structure = msk.access_structure.serialize()?;
        let create_key_pair = build_create_covercrypt_master_keypair_request(
            &access_structure,
            &self.tags,
            self.sensitive,
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

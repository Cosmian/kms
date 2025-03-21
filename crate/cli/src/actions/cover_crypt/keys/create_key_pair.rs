use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsClient;
use cosmian_kms_crypto::crypto::cover_crypt::{
    access_structure::access_structure_from_json_file,
    kmip_requests::build_create_covercrypt_master_keypair_request,
};
use tracing::debug;

use crate::{
    actions::console,
    error::result::{CliResult, CliResultHelper},
};

/// Create a new master keypair for a given access structure and return the key
/// IDs.
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
///            "RnD",
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
///  - the `Department` axis has 4 possible values: `RnD`, `HR`, `MKG`, and `FIN`,
///  - all partitions which are `Top Secret` will be encrypted using post-quantum hybridized cryptography, as indicated by the `::+` suffix on the value,
///  - all other partitions will use classic cryptography.
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateMasterKeyPairAction {
    /// The JSON access structure specifications file to use to generate the keys.
    /// See the inline doc of the `create-master-key-pair` command for details.
    #[clap(long, short = 's')]
    specification: PathBuf,

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
        let access_structure = access_structure_from_json_file(&self.specification)?;

        debug!("client: access_structure: {access_structure:?}");

        let res = kms_rest_client
            .create_key_pair(build_create_covercrypt_master_keypair_request(
                &access_structure,
                &self.tags,
                self.sensitive,
            )?)
            .await
            .with_context(|| "failed creating a Covercrypt Master Key Pair")?;

        let mut stdout = console::Stdout::new("The master keypair has been properly generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            &res.private_key_unique_identifier,
            &res.public_key_unique_identifier,
        );
        stdout.write()
    }
}

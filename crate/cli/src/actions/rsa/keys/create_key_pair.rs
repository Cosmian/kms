use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::rsa::kmip_requests::create_rsa_key_pair_request, KmsClient,
};

use crate::{
    actions::console,
    error::{result::CliResultHelper, CliError},
};

/// Create a new RSA key pair
///
///  - The public is used to encrypt
///      and can be safely shared.
///  - The private key is used to decrypt
///      and must be kept secret.
///
/// Tags can later be used to retrieve the keys. Tags are optional.
#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct CreateKeyPairAction {
    /// The expected size in bits
    #[clap(
        long = "size_in_bits",
        short = 's',
        value_name = "SIZE_IN_BITS",
        default_value = "4096"
    )]
    key_size: usize,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl CreateKeyPairAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> Result<(), CliError> {
        let create_key_pair_request = create_rsa_key_pair_request(&self.tags, self.key_size)?;

        // Query the KMS with your kmip data and get the key pair ids
        let create_key_pair_response = kms_rest_client
            .create_key_pair(create_key_pair_request)
            .await
            .with_context(|| "failed creating a RSA key pair")?;

        let private_key_unique_identifier = &create_key_pair_response.private_key_unique_identifier;
        let public_key_unique_identifier = &create_key_pair_response.public_key_unique_identifier;

        let mut stdout =
            console::Stdout::new("The RSA key pair has been created.", Some(&self.tags));
        stdout.set_private_key_unique_identifier(&private_key_unique_identifier.to_string());
        stdout.set_public_key_unique_identifier(&public_key_unique_identifier.to_string());
        stdout.write()?;

        Ok(())
    }
}

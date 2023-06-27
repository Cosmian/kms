use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::KmsRestClient;

use crate::{
    actions::shared::utils::{import_object, read_key_from_file},
    error::CliError,
};

/// Import a key in the KMS.
///
/// The key must be in KMIP JSON TTLV format.
/// When no key unique id is specified a random UUID v4 is generated.
///
/// The key can be wrapped when imported. Wrapping using:
///  - a password or a supplied key in base64 is done locally
///  - a symmetric key id is performed server side
///
/// A password is first converted to a 256 bit key using Argon 2.
/// Wrapping is performed according to RFC 5649.
///
/// Tags can later be used to retrieve the key. Tags are optional.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct ImportKeyAction {
    /// The KMIP JSON TTLV key file
    #[clap(required = true)]
    key_file: PathBuf,

    /// The unique id of the key; a random UUID v4 is generated if not specified
    #[clap(required = false)]
    key_id: Option<String>,

    /// Unwrap the object if it is wrapped before storing it
    #[clap(
        long = "unwrap",
        short = 'u',
        required = false,
        default_value = "false"
    )]
    unwrap: bool,

    /// Replace an existing key under the same id
    #[clap(
        required = false,
        long = "replace",
        short = 'r',
        default_value = "false"
    )]
    replace_existing: bool,

    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    tags: Vec<String>,
}

impl ImportKeyAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        // read the key file
        let object = read_key_from_file(&self.key_file)?;
        let object_type = object.object_type();

        // import the key
        let unique_identifier = import_object(
            client_connector,
            self.key_id.clone(),
            object,
            self.unwrap,
            self.replace_existing,
            &self.tags,
        )
        .await?;

        // print the response
        println!(
            "The key of type {:?} in file {:?} was imported with id: {}",
            &self.key_file, object_type, unique_identifier,
        );
        if !self.tags.is_empty() {
            println!("Tags:");
            for tag in &self.tags {
                println!("    - {}", tag);
            }
        }

        Ok(())
    }
}

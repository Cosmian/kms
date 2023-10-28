use std::path::PathBuf;

use clap::Parser;
use cosmian_kmip::kmip::kmip_objects::{Object, ObjectType};
use cosmian_kms_client::KmsRestClient;

use super::utils::objects_from_pem;
use crate::{
    actions::shared::utils::{import_object, read_bytes_from_file, read_key_from_json_ttlv_bytes},
    error::CliError,
};

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum KeyFormat {
    JsonTtlv,
    Pem,
    Der,
    SymmetricKey,
    //SecretData
}

/// Import a private or public key in the KMS.
///
/// When no key unique id is specified, a random UUID v4 is generated.
///
/// Import of a private key will automatically generate the corresponding public key
/// with id `{private_key_id}-pub`.
///
/// By default, the format is expected to be JSON TTLV but
/// other formats can be specified with the option `-f`.
///   * json-ttlv (the default)
///   * pem (PKCS#1, PKCS#8, SEC1): the function will attempt to detect the PKCS format
///   * der
///   * symmetric-key
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

    /// The format of the key
    #[clap(long = "key-format", short = 'f', default_value = "json-ttlv")]
    key_format: KeyFormat,

    /// In the case of a JSON TTLV key,
    /// unwrap the key if it is wrapped before storing it
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
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // read the key file
        let bytes = read_bytes_from_file(&self.key_file)?;
        let object = match &self.key_format {
            KeyFormat::JsonTtlv => read_key_from_json_ttlv_bytes(&bytes)?,
            KeyFormat::Pem => read_key_from_pem(&bytes)?,
            x => unimplemented!("The key format {:?} is not supported yet", x),
        };
        let object_type = object.object_type();

        // import the key
        let unique_identifier = import_object(
            kms_rest_client,
            self.key_id.clone(),
            object,
            None,
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
                println!("    - {tag}");
            }
        }

        Ok(())
    }
}

fn read_key_from_pem(bytes: &[u8]) -> Result<Object, CliError> {
    let mut objects = objects_from_pem(bytes)?;
    if objects.len() > 1 {
        println!(
            "Warning: the PEM file contains multiple objects. Only the private key will be \
             imported. A corresponding public key will be generated automatically."
        );
    }
    let object = objects
        .pop()
        .ok_or_else(|| CliError::Default("The PEM file does not contain any object".to_owned()))?;
    match object.object_type() {
        ObjectType::PrivateKey | ObjectType::PublicKey => Ok(object),
        ObjectType::Certificate => Err(CliError::Default(
            "For certificates, use the `ckms certificate` sub-command".to_owned(),
        )),
        _ => Err(CliError::Default(format!(
            "The PEM file contains an object of type {:?} which is not supported",
            object.object_type()
        ))),
    }
}

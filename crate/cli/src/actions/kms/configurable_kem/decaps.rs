use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::decrypt_request},
    read_bytes_from_file,
};
use cosmian_logger::debug;

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Open a Configurable-KEM encapsulation.
///
/// Reads the encapsulation from a file and writes the decapsulated session key to an output file.
#[derive(Parser, Debug)]
pub struct DecapsAction {
    /// The encapsulation file to decrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The user key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The decrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl DecapsAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the encapsulation from the input file
        let encapsulation_bytes = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the encapsulation file")?;

        let decrypt_request = decrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            None,
            encapsulation_bytes,
            None,
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
                ..Default::default()
            }),
        );

        debug!("{decrypt_request}");

        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        let session_key = decrypt_response.data.context("The plain data are empty")?;

        // Write the session key to the output file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the session key file")?;
        buffer
            .write_all(&session_key)
            .with_context(|| "failed to write the session key file")?;

        let stdout = format!(
            "The decrypted file is available at {}",
            output_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

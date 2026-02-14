use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::encrypt_request},
};
use cosmian_logger::debug;

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};

/// Encapsulate a new symmetric key.
///
/// The encapsulation is written to a file. The session key is printed to stdout.
#[derive(Parser, Debug)]
pub struct EncapsAction {
    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encryption policy to use.
    /// Example: "`department::marketing` && `level::confidential`"
    pub(crate) encryption_policy: Option<String>,

    /// The encrypted output file path for the encapsulation
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl EncapsAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = encrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            self.encryption_policy.clone(),
            Vec::new(),
            None,
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
                ..Default::default()
            }),
        )?;

        debug!("{request}");

        let response = kms_rest_client
            .encrypt(request)
            .await
            .with_context(|| "Can't execute the request on the KMS server")?;

        let (session_key, encapsulation) =
            <(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>)>::deserialize(
                &response.data.context("The encrypted-data field is empty")?,
            )
            .map_err(|e| {
                KmsCliError::Conversion(format!(
                    "failed deserializing the key and its encapsulation from data \
                     returned by the configurable KEM: {e}"
                ))
            })?;

        // Write the encapsulation to a file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("output.enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encapsulation file")?;
        buffer
            .write_all(&encapsulation)
            .with_context(|| "failed to write the encapsulation file")?;

        // Write the session key to a companion file
        let session_key_file = output_file.with_extension("key");
        let mut key_buffer = File::create(&session_key_file)
            .with_context(|| "failed to write the session key file")?;
        key_buffer
            .write_all(&session_key)
            .with_context(|| "failed to write the session key file")?;

        let stdout = format!(
            "The encapsulation is available at {}\nThe session key is available at {}",
            output_file.display(),
            session_key_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

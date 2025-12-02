use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip_2_1::requests::sign_request;
use cosmian_kms_client::{KmsClient, read_bytes_from_file};

use crate::{
    actions::kms::{
        console,
        labels::KEY_ID,
        shared::{CDigitalSignatureAlgorithmRSA, get_key_uid},
    },
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Digital signature supported is RSASSA-PSS
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct SignAction {
    /// The file to sign
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature algorithm
    #[clap(long = "signature-algorithm", short = 's', default_value = "rsassapss")]
    pub(crate) signature_algorithm: CDigitalSignatureAlgorithmRSA,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl SignAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the file to sign
        let data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to sign")?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let sign_request = sign_request(
            &id,
            None,
            Some(data),
            Some(self.signature_algorithm.to_cryptographic_parameters()),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let sign_response = kms_rest_client
            .sign(sign_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let plaintext = sign_response
            .signature_data
            .context("Sign with RSA: the plaintext is empty")?;

        // Write the signature file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension("plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&plaintext)
            .with_context(|| "Fail to write the plain file")?;

        let stdout = format!(
            "The signature file is available at {}",
            output_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

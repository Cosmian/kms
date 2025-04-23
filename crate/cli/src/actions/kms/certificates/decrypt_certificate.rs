use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{kmip_operations::Decrypt, kmip_types::UniqueIdentifier},
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};

use crate::{
    actions::{
        console,
        kms::{labels::KEY_ID, shared::get_key_uid},
    },
    error::result::{CosmianResult, CosmianResultHelper},
};

/// Decrypt a file using the private key of a certificate.
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
pub struct DecryptCertificateAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The private key unique identifier related to certificate
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID,  short = 'k', group = "key-tags")]
    private_key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data that was supplied during encryption.
    #[clap(required = false, long, short)]
    authentication_data: Option<String>,

    /// Optional encryption algorithm.
    /// This is only available for RSA keys for now.
    /// The default for RSA is `PKCS_OAEP`.
    #[clap(long, short = 'e', verbatim_doc_comment)]
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
}

impl DecryptCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        // Read the file to decrypt
        let ciphertext = read_bytes_from_file(&self.input_file)?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.private_key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let decrypt_request = Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
            data: Some(ciphertext),
            authenticated_encryption_additional_data: self
                .authentication_data
                .clone()
                .map(|s| s.as_bytes().to_vec()),
            cryptographic_parameters: self
                .encryption_algorithm
                .map(|alg| alg.to_cryptographic_parameters(HashFn::Sha256)),
            ..Decrypt::default()
        };

        // Query the KMS with your kmip data and retrieve the cleartext
        let decrypt_response = client_connector
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let plaintext = decrypt_response
            .data
            .context("Decrypt with certificate: the plaintext is empty")?;

        // Write the decrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension("plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plaintext file")?;
        buffer
            .write_all(&plaintext)
            .with_context(|| "Fail to write the plaintext file")?;

        console::Stdout::new(&format!(
            "The decrypted file is available at {}",
            output_file.display()
        ))
        .write()?;

        Ok(())
    }
}

use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::{kmip_operations::Encrypt, kmip_types::UniqueIdentifier},
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};
use zeroize::Zeroizing;

use crate::{
    actions::{
        console,
        kms::{labels::CERTIFICATE_ID, shared::get_key_uid},
    },
    error::result::{CosmianResult, CosmianResultHelper},
};

/// Encrypt a file using the certificate public key.
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
pub struct EncryptCertificateAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The certificate unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = CERTIFICATE_ID, short = 'c', group = "key-tags")]
    certificate_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data.
    /// This data needs to be provided back for decryption.
    #[clap(required = false, long, short = 'a')]
    authentication_data: Option<String>,

    /// Optional encryption algorithm.
    /// This is only available for RSA keys for now.
    /// The default for RSA is `PKCS_OAEP`.
    #[clap(long, short = 'e', verbatim_doc_comment)]
    encryption_algorithm: Option<RsaEncryptionAlgorithm>,
}

impl EncryptCertificateAction {
    pub async fn run(&self, client_connector: &KmsClient) -> CosmianResult<()> {
        // Read the file to encrypt
        let data = Zeroizing::from(read_bytes_from_file(&self.input_file)?);

        // Recover the unique identifier or set of tags
        let id = get_key_uid(
            self.certificate_id.as_ref(),
            self.tags.as_ref(),
            CERTIFICATE_ID,
        )?;

        let authenticated_encryption_additional_data = self
            .authentication_data
            .as_ref()
            .map(|auth_data| auth_data.as_bytes().to_vec());

        let cryptographic_parameters =
            self.encryption_algorithm
                .as_ref()
                .map(|encryption_algorithm| {
                    encryption_algorithm.to_cryptographic_parameters(HashFn::Sha256)
                });

        let encrypt_request = Encrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(id.clone())),
            data: Some(data),
            authenticated_encryption_additional_data,
            cryptographic_parameters,
            ..Encrypt::default()
        };

        // Query the KMS for encryption
        let encrypt_response = client_connector
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        // Retrieve the ciphertext
        let ciphertext = encrypt_response
            .data
            .context("The encrypted data are empty")?;

        // Write the encrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encrypted file")?;
        buffer
            .write_all(&ciphertext)
            .with_context(|| "failed to write the encrypted file")?;

        console::Stdout::new(&format!(
            "The encrypted file is available at {}",
            output_file.display()
        ))
        .write()?;

        Ok(())
    }
}

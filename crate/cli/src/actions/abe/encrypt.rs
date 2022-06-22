use std::{fs::File, io::prelude::*, path::PathBuf};

use abe_gpsw::interfaces::policy::Attribute as AbeAttribute;
use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::{
    abe::kmip_requests::build_hybrid_encryption_request as abe_build_hybrid_encryption_request,
    cover_crypt::kmip_requests::build_hybrid_encryption_request as cc_build_hybrid_encryption_request,
};
use cover_crypt::policies::Attribute as CoverCryptAttribute;
use eyre::Context;

/// Encrypts a file with the given policy attributes
/// and the public key stored in the KMS.
#[derive(StructOpt, Debug)]
pub struct EncryptAction {
    /// The file to encrypt
    #[structopt(required = true, name = "FILE", parse(from_os_str))]
    input_file: PathBuf,

    /// The policy attributes to encrypt the file with
    /// Example: `-a department::marketing -a level::confidential`
    #[structopt(required = true, short, long)]
    attributes: Vec<String>,

    /// The optional output directory to output the encrypted file
    #[structopt(required = false, short, long, default_value = ".")]
    output_directory: PathBuf,

    /// The optional resource_uid. It's an extra encryption parameter to increase the security level
    #[structopt(required = false, short, long, default_value = "")]
    resource_uid: String,

    /// The public key unique identifier stored in the KMS
    #[structopt(required = true, long = "public-key-id", short = 'p')]
    public_key_id: String,
}

impl EncryptAction {
    pub async fn run(
        &self,
        client_connector: &KmsRestClient,
        is_cover_crypt: bool,
    ) -> eyre::Result<()> {
        // Read the file to encrypt
        let filename = self
            .input_file
            .file_name()
            .ok_or_else(|| eyre::eyre!("Could not get the name of the file to encrypt"))?;
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to encrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to encrypt")?;

        // Create the kmip query
        let encrypt_request = if is_cover_crypt {
            // Parse the attributes
            let attributes = self
                .attributes
                .iter()
                .map(|s| CoverCryptAttribute::try_from(s.as_str()).map_err(Into::into))
                .collect::<eyre::Result<Vec<CoverCryptAttribute>>>()?;

            cc_build_hybrid_encryption_request(
                &self.public_key_id,
                attributes,
                self.resource_uid.as_bytes().to_vec(),
                data,
            )?
        } else {
            // Parse the attributes
            let attributes = self
                .attributes
                .iter()
                .map(|s| AbeAttribute::try_from(s.as_str()).map_err(Into::into))
                .collect::<eyre::Result<Vec<AbeAttribute>>>()?;

            abe_build_hybrid_encryption_request(
                &self.public_key_id,
                attributes,
                self.resource_uid.as_bytes().to_vec(),
                data,
            )?
        };

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = client_connector
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .ok_or_else(|| eyre::eyre!("The encrypted data are empty"))?;

        let mut encrypted_file = self.output_directory.join(filename);
        encrypted_file.set_extension("enc");

        // Write the encrypted file
        let mut buffer =
            File::create(&encrypted_file).with_context(|| "Fail to write the encrypted file")?;
        buffer
            .write_all(&data)
            .with_context(|| "Fail to write the encrypted file")?;

        println!("The encryption has been properly done.");
        println!(
            "The encrypted file can be found at {}",
            &encrypted_file
                .to_str()
                .ok_or_else(|| eyre::eyre!("Could not display the name of encrypted file"))?
        );

        Ok(())
    }
}

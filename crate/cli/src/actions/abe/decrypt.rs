use std::{fs::File, io::prelude::*, path::PathBuf};

use clap::StructOpt;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::abe::kmip_requests::build_decryption_request;
use eyre::Context;

/// Decrypts a file identified by its name and
/// given a user decryption key stored in the KMS.
#[derive(StructOpt, Debug)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE", parse(from_os_str))]
    input_file: PathBuf,

    /// The optional output directory to output the file to
    #[clap(required = false, short, long, default_value = ".")]
    output_directory: PathBuf,

    /// The optional resource_uid. It's an extra encryption parameter to increase the security level
    #[clap(required = false, short, long, default_value = "")]
    resource_uid: String,

    /// The user decryption key unique identifier stored in the KMS
    #[clap(required = true, long = "user-key-id", short = 'u')]
    user_key_id: String,
}

impl DecryptAction {
    pub async fn run(&self, client_connector: &KmsRestClient) -> eyre::Result<()> {
        // Read the file to decrypt
        let filename = self
            .input_file
            .file_name()
            .ok_or_else(|| eyre::eyre!("Could not get the name of the file to decrypt"))?;
        let mut f =
            File::open(&self.input_file).with_context(|| "Can't read the file to decrypt")?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .with_context(|| "Fail to read the file to decrypt")?;

        // Create the kmip query
        let decrypt_request = build_decryption_request(
            &self.user_key_id,
            self.resource_uid.as_bytes().to_vec(),
            data,
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = client_connector
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = decrypt_response
            .data
            .ok_or_else(|| eyre::eyre!("The plain data are empty"))?;
        let mut decrypted_file = self.output_directory.join(filename);
        decrypted_file.set_extension("plain");

        // Write the decrypted file
        let mut buffer =
            File::create(&decrypted_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&data)
            .with_context(|| "Fail to write the plain file")?;

        println!("The decryption has been properly done.");
        println!(
            "The decrypted file can be found at {}",
            &decrypted_file
                .to_str()
                .ok_or_else(|| eyre::eyre!("Could not display the name of the plain file"))?
        );

        Ok(())
    }
}

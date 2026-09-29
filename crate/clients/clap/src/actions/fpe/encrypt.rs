use std::fs;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
        requests::encrypt_request,
    },
};

use super::{FpeArgs, write_output_bytes};
use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Encrypt data using AES-256 FF1 format-preserving encryption through KMIP.
#[derive(Parser, Debug, Default)]
pub struct EncryptAction {
    #[clap(flatten)]
    pub(crate) args: FpeArgs,
}

impl EncryptAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = encrypt_request(
            &self.args.key_id()?,
            None,
            self.args.input_bytes()?,
            self.args.tweak_bytes()?,
            self.args.authenticated_data()?,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::FPE_FF1),
                ..CryptographicParameters::default()
            }),
        )?;
        let response = kms_rest_client
            .encrypt(request)
            .await
            .with_context(|| "failed encrypting data with FPE")?;
        let ciphertext = response
            .data
            .with_context(|| "the ciphertext returned by KMIP Encrypt is empty")?;

        if let Some(input_file) = self.args.input_file.as_ref() {
            let output_path = self
                .args
                .output_file
                .clone()
                .unwrap_or_else(|| input_file.with_extension("enc"));
            fs::write(&output_path, &ciphertext)
                .with_context(|| "failed to write the encrypted file")?;
            console::Stdout::new(&format!(
                "The encrypted file is available at {}",
                output_path.display()
            ))
            .write()?;
        } else {
            write_output_bytes(self.args.output_file.as_ref(), &ciphertext)?;
        }

        Ok(())
    }
}

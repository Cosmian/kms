use std::fs;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
        requests::decrypt_request,
    },
};

use super::{FpeArgs, write_output_bytes};
use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Decrypt data using AES-256 FF1 format-preserving encryption through KMIP.
#[derive(Parser, Debug, Default)]
pub struct DecryptAction {
    #[clap(flatten)]
    pub(crate) args: FpeArgs,
}

impl DecryptAction {
    pub(crate) async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = decrypt_request(
            &self.args.key_id()?,
            self.args.tweak_bytes()?,
            self.args.input_bytes()?,
            None,
            self.args.authenticated_data()?,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::FPE_FF1),
                ..CryptographicParameters::default()
            }),
        );
        let response = kms_rest_client
            .decrypt(request)
            .await
            .with_context(|| "failed decrypting data with FPE")?;
        let plaintext = response
            .data
            .with_context(|| "the plaintext returned by KMIP Decrypt is empty")?;

        if let Some(input_file) = self.args.input_file.as_ref() {
            let output_path = self
                .args
                .output_file
                .clone()
                .unwrap_or_else(|| input_file.with_extension("plain"));
            fs::write(&output_path, plaintext.as_slice())
                .with_context(|| "failed to write the decrypted file")?;
            console::Stdout::new(&format!(
                "The decrypted file is available at {}",
                output_path.display()
            ))
            .write()?;
        } else {
            write_output_bytes(self.args.output_file.as_ref(), plaintext.as_slice())?;
        }

        Ok(())
    }
}

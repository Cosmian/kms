use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
        requests::decrypt_request,
    },
};

use super::{FpeArgs, write_output_bytes};
use crate::error::result::{KmsCliResult, KmsCliResultHelper};

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
        write_output_bytes(self.args.output_file.as_ref(), plaintext.as_slice())?;
        Ok(())
    }
}

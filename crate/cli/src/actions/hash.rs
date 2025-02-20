use clap::Parser;
use cosmian_kms_client::{
    kmip_2_1::{kmip_operations::Hash, kmip_types::CryptographicParameters},
    KmsClient,
};

use super::mac::CHashingAlgorithm;
use crate::{actions::console, error::result::CliResult};

#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct HashAction {
    /// Hashing algorithm (case insensitive)
    ///
    /// Running the locate sub-command with a wrong value will list all the possible values.
    /// e.g. `ckms hash --algorithm WRONG`
    #[clap(
        long = "algorithm",
        short = 'a',
        value_name = "ALGORITHM",
        verbatim_doc_comment
    )]
    pub hashing_algorithm: CHashingAlgorithm,

    /// The data to be hashed.
    #[clap(long, short = 'd')]
    pub data: Option<String>,

    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    #[clap(long, short = 'c')]
    pub correlation_value: Option<String>,

    /// Initial operation as Boolean
    #[clap(long, short = 'i')]
    pub init_indicator: bool,

    /// Final operation as Boolean
    #[clap(long, short = 'f')]
    pub final_indicator: bool,
}

impl HashAction {
    /// Processes the access action.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem running the action.
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        let cryptographic_parameters = CryptographicParameters {
            hashing_algorithm: Some(self.hashing_algorithm.clone().into()),
            ..Default::default()
        };

        let data = match self.data.clone() {
            Some(data) => Some(hex::decode(data)?),
            None => None,
        };

        let correlation_value = match self.correlation_value.clone() {
            Some(correlation_value) => Some(hex::decode(correlation_value)?),
            None => None,
        };

        let init_indicator = Some(self.init_indicator);
        let final_indicator = Some(self.final_indicator);

        let response = kms_rest_client
            .hash(Hash {
                cryptographic_parameters,
                data,
                correlation_value,
                init_indicator,
                final_indicator,
            })
            .await?;

        let hex_output = response.data.map_or_else(String::new, hex::encode);

        console::Stdout::new(&format!("Hash output: {hex_output}")).write()?;
        Ok(())
    }
}

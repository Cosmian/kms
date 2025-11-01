use clap::{Parser, Subcommand};
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::kmip_operations::{RNGRetrieve, RNGSeed},
};

use crate::{actions::kms::console, error::result::KmsCliResult};

#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
/// RNG operations: retrieve random bytes or seed the RNG.
pub struct RngAction {
    #[command(subcommand)]
    pub command: RngCommands,
}

#[derive(Subcommand, Debug)]
pub enum RngCommands {
    /// Retrieve cryptographically secure random bytes from the server RNG.
    Retrieve {
        /// Number of bytes to retrieve
        #[clap(long, short = 'l')]
        length: i32,
    },
    /// Seed the server RNG with provided hex-encoded bytes.
    Seed {
        /// Seed data as hex string
        #[clap(long, short = 'd', value_parser = |s: &str| hex::decode(s).map(|_| s.to_string()).map_err(|e| format!("Invalid hex format: {}", e)))]
        data: String,
    },
}

impl RngAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match &self.command {
            RngCommands::Retrieve { length } => {
                let resp = kms_rest_client
                    .rng_retrieve(RNGRetrieve {
                        data_length: *length,
                    })
                    .await?;
                let hex_data = hex::encode(resp.data);
                console::Stdout::new(&format!("RNG data: {hex_data}")).write()?;
            }
            RngCommands::Seed { data } => {
                let resp = kms_rest_client
                    .rng_seed(RNGSeed {
                        data: hex::decode(data)?,
                    })
                    .await?;
                console::Stdout::new(&format!(
                    "Amount of seed data accepted: {}",
                    resp.amount_of_seed_data
                ))
                .write()?;
            }
        }
        Ok(())
    }
}

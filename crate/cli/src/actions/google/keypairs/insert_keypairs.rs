use clap::Parser;

use crate::{
    error::{CliError},
};

#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct InsertKeypairsAction {
    /// The requester's primary email address
    #[clap(
        long = "user-id",
        short = 'u',
        group = "keypairs",
        required = true
    )]
    user_id: Option<String>,

    /// The identifier of the key pair to retrieve
    #[clap(long = "keypair-id", short = 'k', group = "keypairs", required = true)]
    keypairs_id: Option<String>,
}

impl InsertKeypairsAction {
    pub async fn run(&self) -> Result<(), CliError> {
        println!("Keypairs inserted.");
        Ok(())
    }
}

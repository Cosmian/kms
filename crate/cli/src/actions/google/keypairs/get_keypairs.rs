use std::path::PathBuf;

use clap::Parser;

use crate::{
    error::{CliError}, actions::google::gmail_client::{GmailClient},
};


#[derive(Parser)]
#[clap(verbatim_doc_comment)]
pub struct GetKeypairsAction {
    /// The identifier of the key pair to retrieve
    #[clap(required = true)]
    keypairs_id: String,

    /// The requester's primary email address
    #[clap(
        long = "user-id",
        short = 'u',
        group = "keypairs",
        required = true
    )]
    user_id: String
}

impl GetKeypairsAction {
    pub async fn run(&self, conf_path: &PathBuf) -> Result<(), CliError> {
        let gmail_client = GmailClient::new(conf_path, &self.user_id);
        let endpoint =  "/settings/cse/keypairs/".to_owned() + &self.keypairs_id;
        let response = gmail_client.await.unwrap().get(&endpoint).await;
        if response.status().is_success() {
            let body = response.text().await.unwrap();

            println!("{}", body);
            return Ok(());
        }
        Err(CliError::Default(("Error fetch Gmail API").to_string()))
    }
}

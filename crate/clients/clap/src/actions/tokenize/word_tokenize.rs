use clap::Parser;
use cosmian_kms_client::KmsClient;

use super::{TokenizeResponse, WordListRequest};
use crate::error::result::KmsCliResult;

/// Replace sensitive words in text with consistent random hex tokens.
#[derive(Parser, Debug)]
pub struct WordTokenizeAction {
    /// Input text.
    #[clap(long, short = 'd')]
    pub data: String,

    /// Words to tokenize. Repeat for multiple: --word foo --word bar
    #[clap(long = "word", short = 'w')]
    pub words: Vec<String>,
}

impl WordTokenizeAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let req = WordListRequest {
            data: &self.data,
            words: &self.words,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("word-tokenize", &req).await?;
        resp.print();
        Ok(())
    }
}

use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct WordPatternRequest<'a> {
    data: &'a str,
    pattern: &'a str,
    replace: &'a str,
}

/// Replace all regex-matched substrings in text with a replacement string.
#[derive(Parser, Debug)]
pub struct WordPatternMaskAction {
    /// Input text.
    #[clap(long, short = 'd')]
    pub data: String,

    /// Regular expression pattern (max 1024 chars).
    #[clap(long, short = 'p')]
    pub pattern: String,

    /// Replacement string.
    #[clap(long, short = 'r')]
    pub replace: String,
}

impl WordPatternMaskAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let req = WordPatternRequest {
            data: &self.data,
            pattern: &self.pattern,
            replace: &self.replace,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("word-pattern-mask", &req).await?;
        resp.print();
        Ok(())
    }
}

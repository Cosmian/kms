use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use cosmian_kms_client::KmsClient;
use serde::Serialize;

use super::TokenizeResponse;
use crate::error::result::KmsCliResult;

#[derive(Serialize)]
pub(super) struct HashRequest<'a> {
    data: &'a str,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

/// Hash a string using SHA2, SHA3, or Argon2.
///
/// Output is base64-encoded.
#[derive(Parser, Debug)]
pub struct HashAction {
    /// Input string to hash.
    #[clap(long, short = 'd')]
    pub data: String,

    /// Hash algorithm: sha2, sha3, or argon2.
    #[clap(long, short = 'm', default_value = "sha2")]
    pub method: String,

    /// Optional hex-encoded salt bytes.
    #[clap(long)]
    pub salt: Option<String>,
}

impl HashAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let salt = self
            .salt
            .as_deref()
            .map(|s| {
                hex::decode(s)
                    .map(|bytes| general_purpose::STANDARD.encode(&bytes))
                    .map_err(|e| {
                        crate::error::KmsCliError::Default(format!("invalid hex salt: {e}"))
                    })
            })
            .transpose()?;
        let req = HashRequest {
            data: &self.data,
            method: &self.method.to_uppercase(),
            salt,
        };
        let resp: TokenizeResponse = kms_rest_client.tokenize("hash", &req).await?;
        resp.print();
        Ok(())
    }
}

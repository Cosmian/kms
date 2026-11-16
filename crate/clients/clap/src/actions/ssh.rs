use clap::{Args, Subcommand};
use cosmian_kms_client::KmsClient;
use serde::{Deserialize, Serialize};

use crate::{
    actions::console::Stdout,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

#[derive(Subcommand, Debug)]
pub enum SshCommands {
    /// Sign an OpenSSH user certificate with a configured KMS SSH CA.
    Sign(SignAction),
}

impl SshCommands {
    pub async fn process(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Sign(action) => action.run(kms_rest_client).await,
        }
    }
}

#[derive(Args, Debug)]
pub struct SignAction {
    /// SSH signing role.
    pub role: String,

    /// OpenSSH public key to certify.
    pub public_key: String,

    /// Principals to embed in the certificate.
    #[clap(long = "principal", short = 'p', required = true, num_args = 1..)]
    pub valid_principals: Vec<String>,

    /// Certificate lifetime, such as `15m`.
    #[clap(long)]
    pub ttl: Option<String>,
}

#[derive(Serialize)]
struct SignRequest<'a> {
    public_key: &'a str,
    valid_principals: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
}

#[derive(Deserialize)]
struct SignResponse {
    data: SignedKeyData,
}

#[derive(Deserialize)]
struct SignedKeyData {
    signed_key: String,
}

impl SignAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response: SignResponse = kms_rest_client
            .post_no_ttlv(
                &format!("/v1/ssh/sign/{}", self.role),
                Some(&SignRequest {
                    public_key: &self.public_key,
                    valid_principals: &self.valid_principals,
                    ttl: self.ttl.as_deref(),
                }),
            )
            .await?;
        Stdout::new(&response.data.signed_key).write()
    }
}

/// Generate a fresh 32-character password using KMS-managed randomness.
#[derive(Args, Debug)]
pub struct PasswordAction;

#[derive(Deserialize)]
struct PasswordResponse {
    data: PasswordData,
}

#[derive(Deserialize)]
struct PasswordData {
    password: String,
}

impl PasswordAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> KmsCliResult<()> {
        let response: PasswordResponse = kms_rest_client
            .post_no_ttlv("/v1/secrets/password", Some(&serde_json::json!({})))
            .await
            .context("generating password")?;
        Stdout::new(&response.data.password).write()
    }
}

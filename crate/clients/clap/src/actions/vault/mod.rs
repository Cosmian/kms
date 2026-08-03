//! `ckms vault` sub-commands.
//!
//! Provides a Vault-compatible CLI for managing SPIRE/SPIFFE identities
//! via the Auth Verifier (`auth-verifier`) and the KMS
//! Transit / PKI engines.

pub mod approle;

use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use crate::{actions::vault::approle::AppRoleCommands, error::result::KmsCliResult};

/// Vault-compatible identity and secrets management.
///
/// Interact with the Auth Verifier's Vault-compatible API
/// for managing `AppRole` identities used by SPIRE/SPIFFE agents.
#[derive(Subcommand, Debug)]
pub enum VaultCommands {
    /// Manage Vault `AppRole` authentication roles and credentials.
    #[command(subcommand)]
    Approle(AppRoleCommands),
}

impl VaultCommands {
    /// Dispatch the selected vault sub-command.
    ///
    /// Note: vault commands communicate directly with the Authentication Server
    /// and do not use the `kms_rest_client` parameter.
    ///
    /// # Errors
    /// Returns an error if the underlying HTTP call or response parsing fails.
    pub async fn process(&self, _kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Approle(cmd) => Box::pin(cmd.process()).await,
        }
    }
}

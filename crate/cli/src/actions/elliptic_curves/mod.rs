use clap::Parser;
use cosmian_kms_client::KmsClient;

use self::keys::KeysCommands;
#[cfg(not(feature = "fips"))]
use self::{decrypt::DecryptAction, encrypt::EncryptAction};
use crate::error::result::CliResult;

#[cfg(not(feature = "fips"))]
mod decrypt;
#[cfg(not(feature = "fips"))]
mod encrypt;
mod keys;

/// Manage elliptic curve keys. Encrypt and decrypt data using ECIES.
#[derive(Parser)]
pub enum EllipticCurveCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[cfg(not(feature = "fips"))]
    Encrypt(EncryptAction),
    #[cfg(not(feature = "fips"))]
    Decrypt(DecryptAction),
}

impl EllipticCurveCommands {
    /// Runs the `EllipticCurveCommands` main commands.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to communicate with the KMS server.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution on the KMS server fails.
    ///
    pub async fn process(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            #[cfg(not(feature = "fips"))]
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            #[cfg(not(feature = "fips"))]
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
        };
        Ok(())
    }
}

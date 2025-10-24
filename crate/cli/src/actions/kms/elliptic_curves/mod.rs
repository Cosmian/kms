use clap::Parser;
use cosmian_kms_client::KmsClient;

use self::keys::KeysCommands;
#[cfg(feature = "non-fips")]
use self::{decrypt::DecryptAction, encrypt::EncryptAction};
use crate::{
    actions::kms::elliptic_curves::{sign::SignAction, signature_verify::SignatureVerifyAction},
    error::result::KmsCliResult,
};

#[cfg(feature = "non-fips")]
pub(crate) mod decrypt;
#[cfg(feature = "non-fips")]
pub(crate) mod encrypt;
pub(crate) mod keys;
pub(crate) mod sign;
pub(crate) mod signature_verify;

/// Manage elliptic curve keys. Encrypt and decrypt data using ECIES.
#[derive(Parser)]
pub enum EllipticCurveCommands {
    #[command(subcommand)]
    Keys(KeysCommands),
    #[cfg(feature = "non-fips")]
    Encrypt(EncryptAction),
    #[cfg(feature = "non-fips")]
    Decrypt(DecryptAction),
    Sign(SignAction),
    SignVerify(SignatureVerifyAction),
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
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        match self {
            Self::Keys(command) => command.process(kms_rest_client).await?,
            #[cfg(feature = "non-fips")]
            Self::Encrypt(action) => action.run(kms_rest_client).await?,
            #[cfg(feature = "non-fips")]
            Self::Decrypt(action) => action.run(kms_rest_client).await?,
            Self::Sign(action) => action.run(kms_rest_client).await?,
            Self::SignVerify(action) => action.run(kms_rest_client).await?,
        }
        Ok(())
    }
}

use clap::Subcommand;
use cosmian_kms_client::KmsClient;
#[cfg(test)]
pub(crate) use cosmian_kms_client::reexport::cosmian_kms_client_utils::certificate_utils::Algorithm;

use self::{
    certify::CertifyAction, decrypt_certificate::DecryptCertificateAction,
    destroy_certificate::DestroyCertificateAction, encrypt_certificate::EncryptCertificateAction,
    export_certificate::ExportCertificateAction, import_certificate::ImportCertificateAction,
    revoke_certificate::RevokeCertificateAction, validate_certificate::ValidateCertificatesAction,
};
use crate::error::result::KmsCliResult;

pub(crate) mod certify;
pub(crate) mod decrypt_certificate;
pub(crate) mod destroy_certificate;
pub(crate) mod encrypt_certificate;
pub(crate) mod export_certificate;
pub(crate) mod import_certificate;
pub(crate) mod revoke_certificate;
pub(crate) mod validate_certificate;

/// Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
#[derive(Subcommand)]
pub enum CertificatesCommands {
    Certify(CertifyAction),
    Decrypt(DecryptCertificateAction),
    Encrypt(EncryptCertificateAction),
    Export(ExportCertificateAction),
    Import(ImportCertificateAction),
    Revoke(RevokeCertificateAction),
    Destroy(DestroyCertificateAction),
    Validate(ValidateCertificatesAction),
}

impl CertificatesCommands {
    /// Process the `Certificates` main commands.
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
            Self::Certify(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Decrypt(action) => action.run(kms_rest_client).await,
            Self::Encrypt(action) => action.run(kms_rest_client).await,
            Self::Export(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Import(action) => {
                Box::pin(action.run(kms_rest_client)).await?;
                Ok(())
            }
            Self::Revoke(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Destroy(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::Validate(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
        }
    }
}

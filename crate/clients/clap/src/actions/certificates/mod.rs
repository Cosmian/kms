use clap::Subcommand;
use cosmian_kms_client::KmsClient;

use self::{
    certify::CertifyAction, decrypt_certificate::DecryptCertificateAction,
    destroy_certificate::DestroyCertificateAction, encrypt_certificate::EncryptCertificateAction,
    export_certificate::ExportCertificateAction, generate_crl::GenerateCrlAction,
    import_certificate::ImportCertificateAction, revoke_certificate::RevokeCertificateAction,
    validate_certificate::ValidateCertificatesAction,
};
use crate::{
    actions::shared::{ActivateKeyAction, SetRotationPolicyAction},
    error::result::KmsCliResult,
};

pub(crate) mod certify;
pub(crate) mod decrypt_certificate;
pub(crate) mod destroy_certificate;
pub(crate) mod encrypt_certificate;
pub(crate) mod export_certificate;
pub(crate) mod generate_crl;
pub(crate) mod import_certificate;
pub(crate) mod revoke_certificate;
pub(crate) mod validate_certificate;

/// Manage certificates. Create, import, destroy and revoke. Encrypt and decrypt data
#[derive(Subcommand)]
pub enum CertificatesCommands {
    Activate(ActivateKeyAction),
    Certify(CertifyAction),
    Decrypt(DecryptCertificateAction),
    Encrypt(EncryptCertificateAction),
    Export(ExportCertificateAction),
    GenerateCrl(GenerateCrlAction),
    Import(ImportCertificateAction),
    Revoke(RevokeCertificateAction),
    Destroy(DestroyCertificateAction),
    /// Set the automatic rotation policy on a certificate (interval, offset, keyset name).
    SetRotationPolicy(SetRotationPolicyAction),
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
            Self::Activate(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
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
            Self::GenerateCrl(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
            Self::SetRotationPolicy(action) => action.run(kms_rest_client).await,
            Self::Validate(action) => {
                action.run(kms_rest_client).await?;
                Ok(())
            }
        }
    }
}

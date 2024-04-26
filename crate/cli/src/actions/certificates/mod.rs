use clap::Subcommand;
use cosmian_kms_client::KmsClient;
pub use export_certificate::CertificateExportFormat;
pub use import_certificate::CertificateInputFormat;

use self::{
    certify::CertifyAction, decrypt_certificate::DecryptCertificateAction,
    destroy_certificate::DestroyCertificateAction, encrypt_certificate::EncryptCertificateAction,
    export_certificate::ExportCertificateAction, import_certificate::ImportCertificateAction,
    revoke_certificate::RevokeCertificateAction,
};
use crate::error::CliError;

mod certify;
mod decrypt_certificate;
mod destroy_certificate;
mod encrypt_certificate;
mod export_certificate;
mod import_certificate;
mod revoke_certificate;

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
}

impl CertificatesCommands {
    pub async fn process(&self, client_connector: &KmsClient) -> Result<(), CliError> {
        match self {
            Self::Certify(action) => action.run(client_connector).await,
            // Self::Create(action) => action.run(client_connector).await,
            Self::Decrypt(action) => action.run(client_connector).await,
            Self::Encrypt(action) => action.run(client_connector).await,
            Self::Export(action) => action.run(client_connector).await,
            Self::Import(action) => action.run(client_connector).await,
            Self::Revoke(action) => action.run(client_connector).await,
            Self::Destroy(action) => action.run(client_connector).await,
        }
    }
}

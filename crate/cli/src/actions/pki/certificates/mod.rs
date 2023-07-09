use clap::Subcommand;
use cosmian_kms_client::KmsRestClient;

use self::{
    create_certificate::CreateCertificateAction, destroy_certificate::DestroyCertificateAction,
    export_certificate::ExportCertificateAction, import_certificate::ImportCertificateAction,
    revoke_certificate::RevokeCertificateAction,
};
use crate::error::CliError;

mod create_certificate;
mod destroy_certificate;
mod export_certificate;
mod import_certificate;
mod revoke_certificate;

/// Create, destroy, import, and export symmetric certificates
#[derive(Subcommand)]
pub enum CertificatesCommands {
    Create(CreateCertificateAction),
    Export(ExportCertificateAction),
    Import(ImportCertificateAction),
    Revoke(RevokeCertificateAction),
    Destroy(DestroyCertificateAction),
}

impl CertificatesCommands {
    pub async fn process(&self, client_connector: &KmsRestClient) -> Result<(), CliError> {
        match self {
            Self::Create(action) => action.run(client_connector).await?,
            Self::Export(action) => action.run(client_connector).await?,
            Self::Import(action) => action.run(client_connector).await?,
            Self::Revoke(action) => action.run(client_connector).await?,
            Self::Destroy(action) => action.run(client_connector).await?,
        };

        Ok(())
    }
}

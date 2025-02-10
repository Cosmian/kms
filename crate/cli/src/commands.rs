use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use cosmian_kms_client::{KmsClient, KmsClientConfig};
use cosmian_logger::log_init;
use tracing::info;

#[cfg(not(feature = "fips"))]
use crate::actions::cover_crypt::CovercryptCommands;
use crate::{
    actions::{
        access::AccessAction, attributes::AttributesCommands, bench::BenchAction,
        certificates::CertificatesCommands, elliptic_curves::EllipticCurveCommands,
        google::GoogleCommands, login::LoginAction, logout::LogoutAction, mac::MacAction,
        new_database::NewDatabaseAction, rsa::RsaCommands, shared::LocateObjectsAction,
        symmetric::SymmetricCommands, version::ServerVersionAction,
    },
    error::result::CliResult,
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct KmsCli {
    #[command(subcommand)]
    command: KmsActions,

    #[clap(flatten)]
    pub(crate) kms_options: KmsOptions,
}

#[derive(Parser, Debug)]
pub struct KmsOptions {
    /// Configuration file location
    ///
    /// This is an alternative to the env variable `KMS_CLI_CONF`.
    /// Takes precedence over `KMS_CLI_CONF` env variable.
    #[arg(short, long)]
    conf_path: Option<PathBuf>,

    /// The URL of the KMS
    #[arg(long, action)]
    pub(crate) url: Option<String>,

    /// Allow to connect using a self-signed cert or untrusted cert chain
    ///
    /// `accept_invalid_certs` is useful if the CLI needs to connect to an HTTPS KMS server
    /// running an invalid or insecure SSL certificate
    #[arg(long)]
    pub(crate) accept_invalid_certs: bool,

    /// Output the JSON KMIP request and response.
    /// This is useful to understand JSON POST requests and responses
    /// required to programmatically call the KMS on the `/kmip/2_1` endpoint
    #[arg(long, default_value = "false")]
    pub(crate) print_json: bool,
}

impl KmsOptions {
    /// Instantiate the configuration
    /// # Errors
    /// - If the configuration file is not found or invalid
    pub fn prepare_config(&self) -> CliResult<KmsClientConfig> {
        let mut config = KmsClientConfig::load(self.conf_path.clone())?;

        // Override configuration file with command line options
        if let Some(url) = self.url.clone() {
            info!("Override URL from configuration file with: {:?}", url);
            config.http_config.server_url = url;
        }
        if self.accept_invalid_certs {
            info!(
                "Override accept_invalid_certs from configuration file with: {:?}",
                self.accept_invalid_certs
            );
            config.http_config.accept_invalid_certs = true;
        }
        if self.print_json {
            info!(
                "Override json from configuration file with: {:?}",
                self.print_json
            );
            config.print_json = Some(self.print_json);
        }

        Ok(config)
    }
}

#[derive(Subcommand)]
pub enum KmsActions {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    #[clap(hide = true)]
    Bench(BenchAction),
    #[cfg(not(feature = "fips"))]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Google(GoogleCommands),
    Locate(LocateObjectsAction),
    Login(LoginAction),
    Logout(LogoutAction),
    Mac(MacAction),
    NewDatabase(NewDatabaseAction),
    #[command(subcommand)]
    Rsa(RsaCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
}

impl KmsActions {
    /// Process the command line arguments
    ///
    /// # Errors
    /// - If the configuration file is not found or invalid
    pub async fn process(&self, kms_rest_client: &mut KmsClient) -> CliResult<()> {
        match self {
            Self::AccessRights(action) => action.process(kms_rest_client).await,
            Self::Attributes(action) => action.process(kms_rest_client).await,
            Self::Bench(action) => action.process(Arc::new(kms_rest_client.clone())).await,
            #[cfg(not(feature = "fips"))]
            Self::Cc(action) => action.process(kms_rest_client).await,
            Self::Certificates(action) => action.process(kms_rest_client).await,
            Self::Ec(action) => action.process(kms_rest_client).await,
            Self::Google(action) => action.process(kms_rest_client).await,
            Self::Locate(action) => action.process(kms_rest_client).await,
            Self::Login(action) => action.process(&mut kms_rest_client.config).await,
            Self::Logout(action) => action.process(&mut kms_rest_client.config),
            Self::Mac(action) => action.process(kms_rest_client).await,
            Self::NewDatabase(action) => action.process(kms_rest_client).await,
            Self::Rsa(action) => action.process(kms_rest_client).await,
            Self::ServerVersion(action) => action.process(kms_rest_client).await,
            Self::Sym(action) => action.process(kms_rest_client).await,
        }
    }
}

/// Main entry point for the CLI
/// # Errors
/// - If the configuration file is not found or invalid
#[allow(clippy::cognitive_complexity, clippy::print_stdout)]
pub async fn ckms_main() -> CliResult<()> {
    log_init(None);
    let cli_opts = KmsCli::parse();
    let config = cli_opts.kms_options.prepare_config()?;

    // Instantiate the KMS client
    let mut kms_rest_client = KmsClient::new(config)?;
    cli_opts.command.process(&mut kms_rest_client).await?;

    // Post-process the login/logout actions: save KMS configuration
    // The reason why it is done here is that the login/logout actions are also call by meta Cosmian CLI using its own configuration file
    match cli_opts.command {
        KmsActions::Login(_) | KmsActions::Logout(_) => {
            kms_rest_client
                .config
                .save(cli_opts.kms_options.conf_path.clone())?;
        }
        _ => {}
    }

    Ok(())
}

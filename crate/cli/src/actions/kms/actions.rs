use clap::Subcommand;
use cosmian_kms_client::{KmsClient, KmsClientConfig};

#[cfg(feature = "non-fips")]
use super::cover_crypt::CovercryptCommands;
use crate::{
    actions::kms::{
        access::AccessAction, attributes::AttributesCommands, azure::AzureCommands,
        bench::BenchAction, certificates::CertificatesCommands, derive_key::DeriveKeyAction,
        elliptic_curves::EllipticCurveCommands, google::GoogleCommands, hash::HashAction,
        login::LoginAction, mac::MacCommands, opaque_object::OpaqueObjectCommands, rng::RngAction,
        rsa::RsaCommands, secret_data::SecretDataCommands, shared::LocateObjectsAction,
        symmetric::SymmetricCommands, version::ServerVersionAction,
    },
    error::result::KmsCliResult,
};

#[derive(Subcommand)]
pub enum KmsActions {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    #[command(subcommand)]
    Azure(AzureCommands),
    #[clap(hide = true)]
    Bench(BenchAction),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[command(subcommand)]
    Certificates(CertificatesCommands),
    DeriveKey(DeriveKeyAction),
    #[command(subcommand)]
    Ec(EllipticCurveCommands),
    #[command(subcommand)]
    Google(GoogleCommands),
    Locate(LocateObjectsAction),
    Login(LoginAction),
    /// Logout from the Identity Provider.
    ///
    /// The access token will be removed from the cosmian configuration file.
    Logout,
    Hash(HashAction),
    Mac(MacCommands),
    /// RNG utilities: retrieve random bytes or seed RNG
    Rng(RngAction),
    /// Discover KMIP protocol versions supported by the server.
    DiscoverVersions,
    /// Query server capabilities and metadata (KMIP Query)
    Query,
    #[command(subcommand)]
    Rsa(RsaCommands),
    #[command(subcommand)]
    OpaqueObject(OpaqueObjectCommands),
    #[command(subcommand)]
    SecretData(SecretDataCommands),
    ServerVersion(ServerVersionAction),
    #[command(subcommand)]
    Sym(SymmetricCommands),
}

impl KmsActions {
    /// Process the command line arguments
    ///
    /// # Errors
    /// - If the configuration file is not found or invalid
    pub async fn process(&self, kms_rest_client: KmsClient) -> KmsCliResult<KmsClientConfig> {
        let mut new_config = kms_rest_client.config.clone();

        match self {
            Self::AccessRights(action) => action.process(kms_rest_client).await?,
            Self::Attributes(action) => action.process(kms_rest_client).await?,
            Self::Azure(action) => action.process(kms_rest_client).await?,
            Self::Bench(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Cc(action) => action.process(kms_rest_client).await?,
            Self::Certificates(action) => {
                Box::pin(action.process(kms_rest_client)).await?;
            }
            Self::DeriveKey(action) => {
                action.run(&kms_rest_client).await?;
            }
            Self::Ec(action) => action.process(kms_rest_client).await?,
            Self::Google(action) => action.process(kms_rest_client).await?,
            Self::Locate(action) => {
                action.run(kms_rest_client).await?;
            }
            Self::Login(action) => {
                let access_token = action.process(kms_rest_client.config).await?;
                new_config.http_config.access_token = Some(access_token);
            }
            Self::Logout => {
                new_config.http_config.access_token = None;
            }
            Self::Hash(action) => action.run(kms_rest_client).await?,
            Self::Mac(action) => action.process(kms_rest_client).await?,
            Self::Rng(action) => action.run(kms_rest_client).await?,
            Self::DiscoverVersions => {
                use cosmian_kms_client::cosmian_kmip::kmip_0::kmip_operations::DiscoverVersions;

                use crate::actions::kms::console;
                let resp = kms_rest_client
                    .discover_versions(DiscoverVersions {
                        protocol_version: None,
                    })
                    .await?;
                let versions = resp
                    .protocol_version
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| format!("{}.{}", v.protocol_version_major, v.protocol_version_minor))
                    .collect::<Vec<_>>()
                    .join(", ");
                console::Stdout::new(&format!("Supported KMIP versions: {versions}")).write()?;
            }
            Self::Query => {
                use cosmian_kms_client::kmip_2_1::kmip_operations::Query;

                use crate::actions::kms::console;
                let resp = kms_rest_client
                    .query(Query {
                        query_function: None,
                    })
                    .await?;
                let ops = resp
                    .operation
                    .unwrap_or_default()
                    .into_iter()
                    .map(|o| o.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                console::Stdout::new(&format!("Supported operations: {ops}")).write()?;
            }
            Self::Rsa(action) => action.process(kms_rest_client).await?,
            Self::OpaqueObject(action) => action.process(kms_rest_client).await?,
            Self::ServerVersion(action) => action.process(kms_rest_client).await?,
            Self::Sym(action) => action.process(kms_rest_client).await?,
            Self::SecretData(action) => action.process(kms_rest_client).await?,
        }

        Ok(new_config)
    }
}

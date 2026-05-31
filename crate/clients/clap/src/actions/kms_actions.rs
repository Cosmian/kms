use clap::Subcommand;
use cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::{kmip_operations::Query, kmip_types::QueryFunction},
};
use cosmian_kms_client::{KmsClient, KmsClientConfig};

#[cfg(feature = "non-fips")]
use super::cover_crypt::CovercryptCommands;
#[cfg(feature = "non-fips")]
use super::fpe::FpeCommands;
#[cfg(feature = "non-fips")]
use super::pqc::PqcCommands;
#[cfg(feature = "non-fips")]
use super::tokenize::TokenizeCommands;
use crate::{
    actions::{
        access::AccessAction, attributes::AttributesCommands, aws::AwsCommands,
        azure::AzureCommands, bench::BenchAction, certificates::CertificatesCommands,
        console::Stdout, derive_key::DeriveKeyAction, elliptic_curves::EllipticCurveCommands,
        google::GoogleCommands, hash::HashAction, login::LoginAction, mac::MacCommands,
        opaque_object::OpaqueObjectCommands, rng::RngAction, rsa::RsaCommands,
        secret_data::SecretDataCommands, shared::LocateObjectsAction, symmetric::SymmetricCommands,
        version::ServerVersionAction,
    },
    error::result::KmsCliResult,
};

/// Print a labeled list of items from a Query response field.
/// Does nothing if the option is `None` or the list is empty.
fn print_query_list<T: std::fmt::Display>(label: &str, items: Option<Vec<T>>) -> KmsCliResult<()> {
    if let Some(items) = items {
        let s = items
            .into_iter()
            .map(|t| t.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if !s.is_empty() {
            Stdout::new(&format!("{label}: {s}")).write()?;
        }
    }
    Ok(())
}

/// Print a labeled count of items from a Query response field.
/// Does nothing if the option is `None`.
fn print_query_count<T>(label: &str, items: Option<Vec<T>>) -> KmsCliResult<()> {
    if let Some(items) = items {
        Stdout::new(&format!("{label}: {} item(s)", items.len())).write()?;
    }
    Ok(())
}

/// Print a labeled optional scalar value from a Query response.
/// Does nothing if the option is `None`.
fn print_query_value<T: std::fmt::Display>(label: &str, value: Option<T>) -> KmsCliResult<()> {
    if let Some(v) = value {
        Stdout::new(&format!("{label}: {v}")).write()?;
    }
    Ok(())
}

#[derive(Subcommand)]
pub enum ServerCommands {
    /// Show server version information.
    Version(ServerVersionAction),
    /// Discover KMIP protocol versions supported by the server.
    DiscoverVersions,
    /// Query server capabilities and metadata (KMIP Query).
    Query,
}

#[derive(Subcommand)]
pub enum KmsActions {
    #[command(subcommand)]
    AccessRights(AccessAction),
    #[command(subcommand)]
    Attributes(AttributesCommands),
    #[command(subcommand)]
    Azure(AzureCommands),
    #[command(subcommand)]
    Aws(AwsCommands),
    Bench(BenchAction),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Fpe(FpeCommands),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Pqc(PqcCommands),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Tokenize(TokenizeCommands),
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
    /// The access token will be removed from the ckms configuration file.
    Logout,
    Hash(HashAction),
    Mac(MacCommands),
    /// RNG utilities: retrieve random bytes or seed RNG
    Rng(RngAction),
    /// Server-related commands.
    #[command(subcommand)]
    Server(ServerCommands),
    #[command(subcommand)]
    Rsa(RsaCommands),
    #[command(subcommand)]
    OpaqueObject(OpaqueObjectCommands),
    #[command(subcommand)]
    SecretData(SecretDataCommands),
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
            Self::AccessRights(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Attributes(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Aws(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Azure(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Bench(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Cc(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Fpe(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Pqc(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Tokenize(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Certificates(action) => {
                Box::pin(action.process(kms_rest_client)).await?;
            }
            Self::DeriveKey(action) => {
                Box::pin(action.run(&kms_rest_client)).await?;
            }
            Self::Ec(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Google(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Locate(action) => {
                Box::pin(action.run(kms_rest_client)).await?;
            }
            Self::Login(action) => {
                let access_token = Box::pin(action.process(kms_rest_client.config)).await?;
                new_config.http_config.access_token = Some(access_token);
            }
            Self::Logout => {
                new_config.http_config.access_token = None;
            }
            Self::Hash(action) => Box::pin(action.run(kms_rest_client)).await?,
            Self::Mac(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Rng(action) => Box::pin(action.run(kms_rest_client)).await?,
            Self::Server(server_action) => match server_action {
                ServerCommands::Version(action) => {
                    Box::pin(action.process(kms_rest_client)).await?;
                }
                ServerCommands::DiscoverVersions => {
                    Box::pin(async move {
                        let resp = kms_rest_client
                            .discover_versions(DiscoverVersions {
                                protocol_version: None,
                            })
                            .await?;
                        let versions = resp
                            .protocol_version
                            .unwrap_or_default()
                            .into_iter()
                            .map(|v| {
                                format!("{}.{}", v.protocol_version_major, v.protocol_version_minor)
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        Stdout::new(&format!("Supported KMIP versions: {versions}")).write()?;
                        Ok::<(), crate::error::KmsCliError>(())
                    })
                    .await?;
                }
                ServerCommands::Query => {
                    Box::pin(async move {
                        let all_funcs = [
                            QueryFunction::QueryOperations,
                            QueryFunction::QueryObjects,
                            QueryFunction::QueryServerInformation,
                            QueryFunction::QueryApplicationNamespaces,
                            QueryFunction::QueryExtensionList,
                            QueryFunction::QueryExtensionMap,
                            QueryFunction::QueryAttestationTypes,
                            QueryFunction::QueryRNGs,
                            QueryFunction::QueryValidations,
                            QueryFunction::QueryProfiles,
                            QueryFunction::QueryCapabilities,
                            QueryFunction::QueryClientRegistrationMethods,
                            QueryFunction::QueryDefaultsInformation,
                            QueryFunction::QueryStorageProtectionMasks,
                        ];

                        for func in all_funcs {
                            let resp = kms_rest_client
                                .query(Query {
                                    query_function: Some(vec![func]),
                                })
                                .await?;

                            match func {
                                QueryFunction::QueryOperations => {
                                    print_query_list("Supported operations", resp.operation)?;
                                }
                                QueryFunction::QueryObjects => {
                                    print_query_list("Supported object types", resp.object_type)?;
                                }
                                QueryFunction::QueryServerInformation => {
                                    print_query_value(
                                        "Vendor identification",
                                        resp.vendor_identification,
                                    )?;
                                    print_query_value(
                                        "Server information",
                                        resp.server_information,
                                    )?;
                                }
                                QueryFunction::QueryApplicationNamespaces => {
                                    print_query_list(
                                        "Application namespaces",
                                        resp.application_namespaces,
                                    )?;
                                }
                                QueryFunction::QueryExtensionList
                                | QueryFunction::QueryExtensionMap => {
                                    print_query_count("Extensions", resp.extension_information)?;
                                }
                                QueryFunction::QueryAttestationTypes => {
                                    print_query_list("Attestation types", resp.attestation_types)?;
                                }
                                QueryFunction::QueryRNGs => {
                                    print_query_count("RNG parameters", resp.rng_parameters)?;
                                }
                                QueryFunction::QueryValidations => {
                                    print_query_count(
                                        "Validation authorities",
                                        resp.validation_information,
                                    )?;
                                }
                                QueryFunction::QueryProfiles => {
                                    print_query_count("Profiles", resp.profiles_information)?;
                                }
                                QueryFunction::QueryCapabilities
                                | QueryFunction::QueryClientRegistrationMethods => {
                                    print_query_list("Capabilities", resp.capability_information)?;
                                }
                                QueryFunction::QueryDefaultsInformation => {
                                    print_query_value(
                                        "Defaults information",
                                        resp.defaults_information,
                                    )?;
                                }
                                QueryFunction::QueryStorageProtectionMasks => {
                                    print_query_value(
                                        "Protection storage masks",
                                        resp.protection_storage_masks,
                                    )?;
                                }
                            }
                        }
                        Ok::<(), crate::error::KmsCliError>(())
                    })
                    .await?;
                }
            },
            Self::Rsa(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::OpaqueObject(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Sym(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::SecretData(action) => Box::pin(action.process(kms_rest_client)).await?,
        }

        Ok(new_config)
    }
}

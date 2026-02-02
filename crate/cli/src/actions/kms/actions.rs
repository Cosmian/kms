use clap::Subcommand;
use cosmian_kmip::{
    kmip_0::kmip_operations::DiscoverVersions,
    kmip_2_1::{kmip_operations::Query, kmip_types::QueryFunction},
};
use cosmian_kms_client::{KmsClient, KmsClientConfig};

#[cfg(feature = "non-fips")]
use super::configurable_kem::ConfigurableKemCommands;
#[cfg(feature = "non-fips")]
use super::cover_crypt::CovercryptCommands;
use crate::{
    actions::kms::{
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
    #[clap(hide = true)]
    Bench(BenchAction),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Cc(CovercryptCommands),
    #[cfg(feature = "non-fips")]
    #[command(subcommand)]
    Kem(ConfigurableKemCommands),
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
            Self::AccessRights(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Attributes(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Aws(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Azure(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Bench(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Cc(action) => Box::pin(action.process(kms_rest_client)).await?,
            #[cfg(feature = "non-fips")]
            Self::Kem(action) => Box::pin(action.process(kms_rest_client)).await?,
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
            Self::DiscoverVersions => {
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
            Self::Query => {
                Box::pin(async move {
                    // If query_function is None, ask all capabilities sequentially.
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
                                let ops = resp
                                    .operation
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|o| o.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                if !ops.is_empty() {
                                    Stdout::new(&format!("Supported operations: {ops}")).write()?;
                                }
                            }
                            QueryFunction::QueryObjects => {
                                let objs = resp
                                    .object_type
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|t| t.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                if !objs.is_empty() {
                                    Stdout::new(&format!("Supported object types: {objs}"))
                                        .write()?;
                                }
                            }
                            QueryFunction::QueryServerInformation => {
                                if let Some(vendor) = resp.vendor_identification {
                                    Stdout::new(&format!("Vendor identification: {vendor}"))
                                        .write()?;
                                }
                                if let Some(info) = resp.server_information {
                                    Stdout::new(&format!("Server information: {info}")).write()?;
                                }
                            }
                            QueryFunction::QueryApplicationNamespaces => {
                                let namespaces =
                                    resp.application_namespaces.unwrap_or_default().join(", ");
                                if !namespaces.is_empty() {
                                    Stdout::new(&format!("Application namespaces: {namespaces}"))
                                        .write()?;
                                }
                            }
                            QueryFunction::QueryExtensionList
                            | QueryFunction::QueryExtensionMap => {
                                if let Some(exts) = resp.extension_information {
                                    Stdout::new(&format!("Extensions: {} item(s)", exts.len()))
                                        .write()?;
                                }
                            }
                            QueryFunction::QueryAttestationTypes => {
                                let types = resp
                                    .attestation_types
                                    .unwrap_or_default()
                                    .into_iter()
                                    .map(|t| t.to_string())
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                if !types.is_empty() {
                                    Stdout::new(&format!("Attestation types: {types}")).write()?;
                                }
                            }
                            QueryFunction::QueryRNGs => {
                                if let Some(params) = resp.rng_parameters {
                                    Stdout::new(&format!(
                                        "RNG parameters: {} item(s)",
                                        params.len()
                                    ))
                                    .write()?;
                                }
                            }
                            QueryFunction::QueryValidations => {
                                if let Some(vals) = resp.validation_information {
                                    Stdout::new(&format!(
                                        "Validation authorities: {} item(s)",
                                        vals.len()
                                    ))
                                    .write()?;
                                }
                            }
                            QueryFunction::QueryProfiles => {
                                if let Some(profiles) = resp.profiles_information {
                                    Stdout::new(&format!("Profiles: {} item(s)", profiles.len()))
                                        .write()?;
                                }
                            }
                            QueryFunction::QueryCapabilities
                            | QueryFunction::QueryClientRegistrationMethods => {
                                if let Some(caps) = resp.capability_information {
                                    let caps_str = caps
                                        .into_iter()
                                        .map(|c| c.to_string())
                                        .collect::<Vec<_>>()
                                        .join("; ");
                                    if !caps_str.is_empty() {
                                        Stdout::new(&format!("Capabilities: {caps_str}"))
                                            .write()?;
                                    }
                                }
                            }
                            QueryFunction::QueryDefaultsInformation => {
                                if let Some(defs) = resp.defaults_information {
                                    Stdout::new(&format!("Defaults information: {defs}"))
                                        .write()?;
                                }
                            }
                            QueryFunction::QueryStorageProtectionMasks => {
                                if let Some(psm) = resp.protection_storage_masks {
                                    Stdout::new(&format!("Protection storage masks: {psm}"))
                                        .write()?;
                                }
                            }
                        }
                    }
                    Ok::<(), crate::error::KmsCliError>(())
                })
                .await?;
            }
            Self::Rsa(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::OpaqueObject(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::ServerVersion(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::Sym(action) => Box::pin(action.process(kms_rest_client)).await?,
            Self::SecretData(action) => Box::pin(action.process(kms_rest_client)).await?,
        }

        Ok(new_config)
    }
}

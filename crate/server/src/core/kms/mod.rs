use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::PeriodicReader};
mod kmip;
mod other_kms_methods;
mod permissions;

use std::{collections::HashMap, sync::Arc};

use cosmian_kms_server_database::{
    Database,
    reexport::cosmian_kms_interfaces::{
        EncryptionOracle, HSM, HsmEncryptionOracle, HsmStore, ObjectsStore,
    },
};
use cosmian_logger::trace;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crypt2pay_pkcs11_loader::{CRYPT2PAY_PKCS11_LIB, Crypt2pay};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use proteccio_pkcs11_loader::{PROTECCIO_PKCS11_LIB, Proteccio};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use smartcardhsm_pkcs11_loader::{SMARTCARDHSM_PKCS11_LIB, Smartcardhsm};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use softhsm2_pkcs11_loader::{SOFTHSM2_PKCS11_LIB, Softhsm2};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use tokio::sync::OnceCell;
use tokio::sync::RwLock;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use utimaco_pkcs11_loader::{UTIMACO_PKCS11_LIB, Utimaco};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const OTHER_HSM_PKCS11_LIB: &str = "/lib/libkmshsm.so";

// Reuse a single HSM instance across multiple test servers (e.g. Utimaco) to
// avoid re-initialization failures when starting several KMS instances in the
// same process for CLI tests exercising privileged & non-privileged endpoints.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static GLOBAL_HSM: OnceCell<Arc<dyn HSM + Send + Sync>> = OnceCell::const_new();

use crate::{config::ServerParams, core::OtelMetrics, error::KmsError, kms_bail, result::KResult};

/// Macro to instantiate an HSM with support for environment variable override
/// Allows overriding PKCS#11 lib path via env for testing (falls back to default constant)
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unused_macros)]
macro_rules! instantiate_hsm_with_env {
    ($hsm_type:ty, $env_var:expr, $default_lib:expr, $hsm_name:expr, $slot_passwords:expr) => {{
        let lib_path = std::env::var($env_var).unwrap_or_else(|_| $default_lib.to_owned());
        let hsm: Arc<dyn HSM + Send + Sync> = Arc::new(
            <$hsm_type>::instantiate(&lib_path, $slot_passwords).map_err(|e| {
                KmsError::InvalidRequest(format!(
                    "Failed to instantiate the {} HSM (lib: {lib_path}): {e}",
                    $hsm_name
                ))
            })?,
        );
        GLOBAL_HSM.set(hsm.clone()).ok();
        Some(hsm)
    }};
}

/// A Key Management System that partially implements KMIP 2.1
///
/// `https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip`
/// and other operations not part of KMIP, such as Google CSE or Microsoft DKE.
pub struct KMS {
    /// The server parameters are built from the configuration file or command line arguments.
    pub(crate) params: Arc<ServerParams>,

    /// The database is made of two parts:
    /// - The objects' store that stores the cryptographic objects.
    ///   The Object store may be backed by multiple databases or HSMs
    ///   and store the cryptographic objects and their attributes.
    ///   Objects are spread across the underlying stores based on their ID prefix.
    /// - The permissions store that stores the permissions granted to users on the objects.
    pub(crate) database: Database,

    /// Encryption Oracles are used to encrypt/decrypt data using keys with specific prefixes.
    /// A typical use case is delegating encryption/decryption to an HSM.
    /// This is a map of key prefixes to encryption oracles.
    pub(crate) encryption_oracles: RwLock<HashMap<String, Box<dyn EncryptionOracle + Sync + Send>>>,

    /// OTLP metrics collector (if enabled)
    pub(crate) metrics: Option<Arc<OtelMetrics>>,

    /// Optional HSM instance for PKCS#11 operations.
    /// This is used for KMIP PKCS#11 operations like `C_Initialize`, `C_GetInfo`, `C_Finalize`.
    pub(crate) hsm: Option<Arc<dyn HSM + Send + Sync>>,
}

impl KMS {
    /// Instantiate a new KMS instance with the given server parameters.
    /// # Arguments
    /// * `server_params` - The server parameters built from the configuration file or command line arguments.
    /// # Returns
    /// A new KMS instance.
    pub(crate) async fn instantiate(server_params: Arc<ServerParams>) -> KResult<Self> {
        trace!("params: {server_params:?}");

        // Instantiate the HSM if any; the code has support for multiple concurrent HSMs
        let hsm = Self::instantiate_hsm(&server_params)?;

        // Instantiate the main database
        let main_db_params = server_params.main_db_params.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("The main database parameters are not specified".to_owned())
        })?;
        let mut object_stores: HashMap<String, Arc<dyn ObjectsStore + Sync + Send>> =
            HashMap::new();
        if let Some(hsm) = hsm.as_ref() {
            object_stores.insert(
                "hsm".to_owned(),
                Arc::new(HsmStore::new(hsm.clone(), &server_params.hsm_admin)),
            );
        }
        let database = Database::instantiate(
            main_db_params,
            server_params.clear_db_on_start,
            object_stores,
            server_params.unwrapped_cache_max_age,
        )
        .await?;

        // HSMs are also encryption oracles
        let mut encryption_oracles: HashMap<String, Box<dyn EncryptionOracle + Sync + Send>> =
            HashMap::new();
        if let Some(hsm) = hsm.clone() {
            encryption_oracles.insert(
                "hsm".to_owned(),
                Box::new(HsmEncryptionOracle::new(hsm.clone())),
            );
        }

        Ok(Self {
            params: server_params.clone(),
            database,
            encryption_oracles: RwLock::new(encryption_oracles),
            hsm: hsm.clone(),
            metrics: Self::create_otel_metrics(&server_params)?,
        })
    }

    /// Create OTLP metrics if OTLP logging is configured
    fn create_otel_metrics(server_params: &ServerParams) -> KResult<Option<Arc<OtelMetrics>>> {
        // Only create metrics if OTLP is configured in logging
        // We reuse the OTLP endpoint from the logging configuration
        if let Some(otlp_url) = &server_params
            .otel_params
            .as_ref()
            .and_then(|otel| otel.otlp_url.as_ref())
        {
            // Create OTLP metrics exporter
            let exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_tonic()
                .with_endpoint((*otlp_url).clone())
                .build()
                .map_err(|e| {
                    KmsError::ServerError(format!("Failed to create OTLP metrics exporter: {e}"))
                })?;

            // Create periodic reader that sends metrics every 30 seconds
            let reader = PeriodicReader::builder(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_interval(std::time::Duration::from_secs(30))
                .with_timeout(std::time::Duration::from_secs(10))
                .build();

            // Create meter provider
            let mut resource_kvs = vec![
                opentelemetry::KeyValue::new("service.name", "cosmian_kms"),
                opentelemetry::KeyValue::new(
                    "service.version",
                    option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
                ),
            ];
            if let Some(env) = server_params
                .otel_params
                .as_ref()
                .and_then(|otel| otel.environment.as_ref())
            {
                resource_kvs.push(opentelemetry::KeyValue::new(
                    "deployment.environment",
                    env.clone(),
                ));
            }

            let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
                .with_resource(Resource::new(resource_kvs))
                .with_reader(reader)
                .build();

            Ok(Some(Arc::new(OtelMetrics::new(meter_provider)?)))
        } else {
            Ok(None)
        }
    }

    fn instantiate_hsm(
        server_params: &ServerParams,
    ) -> Result<Option<Arc<dyn HSM + Send + Sync>>, KmsError> {
        // Instantiate the HSM if any; the code has support for multiple concurrent HSMs
        let hsm: Option<Arc<dyn HSM + Send + Sync>> = if server_params.slot_passwords.is_empty() {
            None
        } else {
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            kms_bail!("Fatal: HSMs are only supported on Linux x86_64");
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            {
                // Attempt reuse first (used by test harness to allow multiple servers sharing one physical HSM).
                if let Some(existing) = GLOBAL_HSM.get() {
                    return Ok(Some(existing.clone()));
                }
                let hsm_model = server_params.hsm_model.as_ref().ok_or_else(|| {
                    KmsError::InvalidRequest("The HSM model is not specified".to_owned())
                })?;
                match hsm_model.as_str() {
                    "crypt2pay" => instantiate_hsm_with_env!(
                        Crypt2pay,
                        "CRYPT2PAY_PKCS11_LIB",
                        CRYPT2PAY_PKCS11_LIB,
                        "Crypt2pay",
                        server_params.slot_passwords.clone()
                    ),
                    "proteccio" => instantiate_hsm_with_env!(
                        Proteccio,
                        "PROTECCIO_PKCS11_LIB",
                        PROTECCIO_PKCS11_LIB,
                        "Proteccio",
                        server_params.slot_passwords.clone()
                    ),
                    "utimaco" => instantiate_hsm_with_env!(
                        Utimaco,
                        "UTIMACO_PKCS11_LIB",
                        UTIMACO_PKCS11_LIB,
                        "Utimaco",
                        server_params.slot_passwords.clone()
                    ),
                    "softhsm2" => instantiate_hsm_with_env!(
                        Softhsm2,
                        "SOFTHSM2_PKCS11_LIB",
                        SOFTHSM2_PKCS11_LIB,
                        "Softhsm2",
                        server_params.slot_passwords.clone()
                    ),
                    "smartcardhsm" => instantiate_hsm_with_env!(
                        Smartcardhsm,
                        "SMARTCARDHSM_PKCS11_LIB",
                        SMARTCARDHSM_PKCS11_LIB,
                        "Smartcardhsm",
                        server_params.slot_passwords.clone()
                    ),
                    "other" => instantiate_hsm_with_env!(
                        Softhsm2,
                        "OTHER_HSM_PKCS11_LIB",
                        OTHER_HSM_PKCS11_LIB,
                        "Other",
                        server_params.slot_passwords.clone()
                    ),
                    _ => kms_bail!(
                        "The only supported HSM models are proteccio, crypt2pay, smartcardhsm, softhsm2, utimaco and other"
                    ),
                }
            }
        };
        Ok(hsm)
    }
}

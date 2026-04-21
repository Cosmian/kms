use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::PeriodicReader};
mod kmip;
mod other_kms_methods;
mod permissions;

use std::{collections::HashMap, sync::Arc};

use cosmian_kms_logger::{trace, warn};
use cosmian_kms_server_database::{
    Database,
    reexport::cosmian_kms_interfaces::{CryptoOracle, HSM, HsmBackend, ObjectsStore},
};
// Proprietary HSMs (Proteccio, Utimaco, Crypt2pay) ship Linux x86_64-only PKCS#11 libs.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crypt2pay_pkcs11_loader::{CRYPT2PAY_PKCS11_LIB, Crypt2pay};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use proteccio_pkcs11_loader::{PROTECCIO_PKCS11_LIB, Proteccio};
// SoftHSM2 and SmartCardHSM are cross-platform (Linux x86_64 and macOS).
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
use smartcardhsm_pkcs11_loader::{SMARTCARDHSM_PKCS11_LIB, Smartcardhsm};
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
use softhsm2_pkcs11_loader::{SOFTHSM2_PKCS11_LIB, Softhsm2};
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
use tokio::sync::OnceCell;
use tokio::sync::RwLock;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use utimaco_pkcs11_loader::{UTIMACO_PKCS11_LIB, Utimaco};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const OTHER_HSM_PKCS11_LIB: &str = "/lib/libkmshsm.so";

// Reuse HSM instances across multiple test servers (e.g. Utimaco) to
// avoid re-initialization failures when starting several KMS instances in the
// same process for CLI tests exercising privileged & non-privileged endpoints.
// Each element is `Arc<dyn HSM>` for one configured HSM instance, in the same
// order as `ServerParams::hsm_instances`.
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
static GLOBAL_HSMS: OnceCell<Vec<Arc<dyn HSM + Send + Sync>>> = OnceCell::const_new();

use crate::{
    config::{RenewalNotificationStrategy, ServerParams},
    core::OtelMetrics,
    error::KmsError,
    kms_bail,
    notifications::{EmailNotifier, SmtpParams},
    result::KResult,
};

/// Macro to instantiate an HSM with support for environment variable override.
/// Returns an `Arc<dyn HSM + Send + Sync>` without touching any global state.
#[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
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
        hsm
    }};
}

/// A Key Management System that partially implements KMIP 1.x and 2.1
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

    /// Crypto Oracles are used to encrypt/decrypt/sign data using keys with specific prefixes.
    /// A typical use case is delegating cryptographic operations to an HSM.
    /// This is a map of key prefixes to crypto oracles.
    pub(crate) crypto_oracles: RwLock<HashMap<String, Box<dyn CryptoOracle + Sync + Send>>>,

    /// OTLP metrics collector (if enabled)
    pub(crate) metrics: Option<Arc<OtelMetrics>>,

    /// Optional HSM instance for PKCS#11 operations.
    /// This is used for KMIP PKCS#11 operations like `C_Initialize`, `C_GetInfo`, `C_Finalize`.
    pub(crate) hsm: Option<Arc<dyn HSM + Send + Sync>>,

    /// Optional email notifier for rotation/renewal events.
    pub(crate) email_notifier: Option<Arc<EmailNotifier>>,

    /// Strategy governing when renewal-warning notifications are emitted.
    pub(crate) renewal_strategy: RenewalNotificationStrategy,
}

impl KMS {
    /// Returns the vendor identification string used for KMIP `VendorAttribute` operations.
    pub(crate) fn vendor_id(&self) -> &str {
        &self.params.vendor_identification
    }

    /// Instantiate a new KMS instance with the given server parameters.
    /// # Arguments
    /// * `server_params` - The server parameters built from the configuration file or command line arguments.
    /// # Returns
    /// A new KMS instance.
    pub(crate) async fn instantiate(server_params: Arc<ServerParams>) -> KResult<Self> {
        trace!("params: {server_params:?}");

        // Instantiate all configured HSMs.
        let hsm_instances = Self::instantiate_hsms(&server_params)?;

        // Build object-store and crypto-oracle maps, one entry per HSM instance.
        let mut object_stores: HashMap<String, Arc<dyn ObjectsStore + Sync + Send>> =
            HashMap::new();
        let mut crypto_oracles: HashMap<String, Box<dyn CryptoOracle + Sync + Send>> =
            HashMap::new();
        for (idx, hsm_arc) in hsm_instances.iter().enumerate() {
            let inst = server_params.hsm_instances.get(idx).ok_or_else(|| {
                KmsError::InvalidRequest(format!(
                    "HSM instance index {idx} out of range (config has {} instances)",
                    server_params.hsm_instances.len()
                ))
            })?;
            let backend = HsmBackend::new(
                hsm_arc.clone(),
                &inst.admin,
                &server_params.vendor_identification,
                &inst.prefix,
            );
            object_stores.insert(inst.prefix.clone(), Arc::new(backend.clone()));
            crypto_oracles.insert(inst.prefix.clone(), Box::new(backend));
        }

        // Instantiate the main database
        let main_db_params = server_params.main_db_params.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("The main database parameters are not specified".to_owned())
        })?;
        let database = Database::instantiate(
            main_db_params,
            server_params.clear_db_on_start,
            object_stores,
            server_params.unwrapped_cache_max_age,
        )
        .await?;

        // Set up email notifier (disabled if SMTP host not configured or transport init fails)
        let email_notifier =
            SmtpParams::from_config(&server_params.notifications.smtp).and_then(|p| {
                match EmailNotifier::new(p) {
                    Ok(n) => Some(Arc::new(n)),
                    Err(e) => {
                        warn!("Email notifier disabled — failed to initialise SMTP transport: {e}");
                        None
                    }
                }
            });
        let renewal_strategy = server_params.notifications.renewal.clone();

        Ok(Self {
            params: server_params.clone(),
            database,
            crypto_oracles: RwLock::new(crypto_oracles),
            // Keep a reference to the first HSM for PKCS#11 C_Initialize / C_GetInfo operations.
            hsm: hsm_instances.into_iter().next(),
            metrics: Self::create_otel_metrics(&server_params)?,
            email_notifier,
            renewal_strategy,
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

    /// Instantiate all configured HSM instances and return them in order.
    /// On platforms without HSM support, returns an empty Vec (or an error if HSMs were configured).
    fn instantiate_hsms(
        server_params: &ServerParams,
    ) -> Result<Vec<Arc<dyn HSM + Send + Sync>>, KmsError> {
        if server_params.hsm_instances.is_empty() {
            return Ok(vec![]);
        }

        #[cfg(not(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos")))]
        kms_bail!("Fatal: HSMs are only supported on Linux x86_64 and macOS");

        #[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
        {
            // Reuse pre-existing global instances when available (test-server reuse pattern).
            if let Some(existing) = GLOBAL_HSMS.get() {
                return Ok(existing.clone());
            }

            let mut hsm_arcs: Vec<Arc<dyn HSM + Send + Sync>> = Vec::new();
            for inst in &server_params.hsm_instances {
                let hsm = Self::instantiate_one_hsm(&inst.model, inst.slot_passwords.clone())?;
                hsm_arcs.push(hsm);
            }

            GLOBAL_HSMS.set(hsm_arcs.clone()).ok();
            Ok(hsm_arcs)
        }
    }

    /// Instantiate a single HSM by model name.
    #[cfg(any(all(target_os = "linux", target_arch = "x86_64"), target_os = "macos"))]
    fn instantiate_one_hsm(
        model: &str,
        slot_passwords: std::collections::HashMap<usize, Option<String>>,
    ) -> Result<Arc<dyn HSM + Send + Sync>, KmsError> {
        match model {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            "crypt2pay" => Ok(instantiate_hsm_with_env!(
                Crypt2pay,
                "CRYPT2PAY_PKCS11_LIB",
                CRYPT2PAY_PKCS11_LIB,
                "Crypt2pay",
                slot_passwords
            )),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            "proteccio" => Ok(instantiate_hsm_with_env!(
                Proteccio,
                "PROTECCIO_PKCS11_LIB",
                PROTECCIO_PKCS11_LIB,
                "Proteccio",
                slot_passwords
            )),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            "utimaco" => Ok(instantiate_hsm_with_env!(
                Utimaco,
                "UTIMACO_PKCS11_LIB",
                UTIMACO_PKCS11_LIB,
                "Utimaco",
                slot_passwords
            )),
            "softhsm2" => Ok(instantiate_hsm_with_env!(
                Softhsm2,
                "SOFTHSM2_PKCS11_LIB",
                SOFTHSM2_PKCS11_LIB,
                "Softhsm2",
                slot_passwords
            )),
            "smartcardhsm" => Ok(instantiate_hsm_with_env!(
                Smartcardhsm,
                "SMARTCARDHSM_PKCS11_LIB",
                SMARTCARDHSM_PKCS11_LIB,
                "Smartcardhsm",
                slot_passwords
            )),
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            "other" => Ok(instantiate_hsm_with_env!(
                Softhsm2,
                "OTHER_HSM_PKCS11_LIB",
                OTHER_HSM_PKCS11_LIB,
                "Other",
                slot_passwords
            )),
            _ => kms_bail!(
                "Unsupported HSM model: {model}. Supported values: \
                 proteccio, crypt2pay, smartcardhsm, softhsm2, utimaco, other"
            ),
        }
    }
}

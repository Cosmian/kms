use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::PeriodicReader};
mod kmip;
mod other_kms_methods;
mod permissions;

use std::{collections::HashMap, sync::Arc};

use cosmian_kms_server_database::{
    Database,
    reexport::cosmian_kms_interfaces::{
        CryptoOracle, HSM, HsmCryptoOracle, HsmStore, ObjectsStore,
    },
};
use cosmian_logger::trace;
// Proprietary HSMs (Proteccio, Utimaco, Crypt2pay) ship Linux x86_64-only PKCS#11 libs.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crypt2pay_pkcs11_loader::{CRYPT2PAY_PKCS11_LIB, Crypt2pay};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use proteccio_pkcs11_loader::{PROTECCIO_PKCS11_LIB, Proteccio};
// SoftHSM2 and SmartCardHSM are cross-platform (Linux x86_64, Linux aarch64, and macOS).
#[cfg(any(target_os = "linux", target_os = "macos"))]
use smartcardhsm_pkcs11_loader::{SMARTCARDHSM_PKCS11_LIB, Smartcardhsm};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use softhsm2_pkcs11_loader::{SOFTHSM2_PKCS11_LIB, Softhsm2};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::sync::OnceCell;
use tokio::sync::RwLock;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use utimaco_pkcs11_loader::{UTIMACO_PKCS11_LIB, Utimaco};

#[cfg(any(target_os = "linux", target_os = "macos"))]
const OTHER_HSM_PKCS11_LIB: &str = "/lib/libkmshsm.so";

// Reuse a single HSM instance across multiple test servers (e.g. Utimaco) to
// avoid re-initialization failures when starting several KMS instances in the
// same process for CLI tests exercising privileged & non-privileged endpoints.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static GLOBAL_HSM: OnceCell<Arc<dyn HSM + Send + Sync>> = OnceCell::const_new();

use crate::{
    config::{OpenTelemetryConfig, ServerParams},
    core::OtelMetrics,
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Macro to instantiate an HSM with support for environment variable override
/// Allows overriding PKCS#11 lib path via env for testing (falls back to default constant)
#[cfg(any(target_os = "linux", target_os = "macos"))]
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

    /// Crypto Oracles are used to encrypt/decrypt/sign data using keys with specific prefixes.
    /// A typical use case is delegating cryptographic operations to an HSM.
    /// This is a map of key prefixes to crypto oracles.
    pub(crate) crypto_oracles: RwLock<HashMap<String, Box<dyn CryptoOracle + Sync + Send>>>,

    /// OTLP metrics collector (if enabled)
    pub(crate) metrics: Option<Arc<OtelMetrics>>,

    /// Optional HSM instance for PKCS#11 operations.
    /// This is used for KMIP PKCS#11 operations like `C_Initialize`, `C_GetInfo`, `C_Finalize`.
    pub(crate) hsm: Option<Arc<dyn HSM + Send + Sync>>,
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
                Arc::new(HsmStore::new(
                    hsm.clone(),
                    &server_params.hsm_admin,
                    &server_params.vendor_identification,
                )),
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
        let mut crypto_oracles: HashMap<String, Box<dyn CryptoOracle + Sync + Send>> =
            HashMap::new();
        if let Some(hsm) = hsm.clone() {
            crypto_oracles.insert(
                "hsm".to_owned(),
                Box::new(HsmCryptoOracle::new(hsm.clone())),
            );
        }

        Ok(Self {
            params: server_params.clone(),
            database,
            crypto_oracles: RwLock::new(crypto_oracles),
            hsm: hsm.clone(),
            metrics: Self::create_otel_metrics(&server_params)?,
        })
    }

    /// Validate that the OTLP URL is not using plaintext HTTP unless explicitly allowed.
    /// This prevents accidental exposure of telemetry data over unencrypted channels.
    pub(crate) fn validate_otlp_url(
        otlp_url: &str,
        otel_params: &Option<OpenTelemetryConfig>,
    ) -> KResult<()> {
        let allow_insecure = otel_params
            .as_ref()
            .is_some_and(|otel| otel.otlp_allow_insecure);
        if otlp_url.starts_with("http://") && !allow_insecure {
            return Err(KmsError::InvalidRequest(
                "OTLP endpoint uses plaintext HTTP which exposes telemetry data \
                 (including encryption operation metadata) over an unencrypted channel. \
                 Use https:// or set --otlp-allow-insecure / KMS_OTLP_ALLOW_INSECURE=true \
                 if you accept this risk."
                    .to_owned(),
            ));
        }
        Ok(())
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
            // Reject plaintext HTTP unless explicitly allowed
            Self::validate_otlp_url(otlp_url, &server_params.otel_params)?;

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
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            kms_bail!("Fatal: HSMs are only supported on Linux and macOS");
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                // Attempt reuse first (used by test harness to allow multiple servers sharing one physical HSM).
                if let Some(existing) = GLOBAL_HSM.get() {
                    return Ok(Some(existing.clone()));
                }
                let hsm_model = server_params.hsm_model.as_ref().ok_or_else(|| {
                    KmsError::InvalidRequest("The HSM model is not specified".to_owned())
                })?;
                match hsm_model.as_str() {
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    "crypt2pay" => instantiate_hsm_with_env!(
                        Crypt2pay,
                        "CRYPT2PAY_PKCS11_LIB",
                        CRYPT2PAY_PKCS11_LIB,
                        "Crypt2pay",
                        server_params.slot_passwords.clone()
                    ),
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                    "proteccio" => instantiate_hsm_with_env!(
                        Proteccio,
                        "PROTECCIO_PKCS11_LIB",
                        PROTECCIO_PKCS11_LIB,
                        "Proteccio",
                        server_params.slot_passwords.clone()
                    ),
                    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
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
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
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

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic_in_result_fn,
    clippy::unnecessary_wraps,
    clippy::panic
)]
#[allow(clippy::doc_markdown)]
mod tests {
    use super::*;
    use crate::{config::OpenTelemetryConfig, error::KmsError, result::KResult};

    /// Regression test for COSMIAN-2026-004: OTLP plaintext HTTP must be rejected
    /// unless explicitly allowed via `otlp_allow_insecure`.
    #[test]
    fn test_otlp_plaintext_http_rejected() -> KResult<()> {
        let otel_params = Some(OpenTelemetryConfig {
            otlp_url: Some("http://attacker.example.com:4317".to_owned()),
            otlp_allow_insecure: false,
            enable_metering: true,
            environment: Some("test".to_owned()),
        });

        let result = KMS::validate_otlp_url("http://attacker.example.com:4317", &otel_params);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match &err {
            KmsError::InvalidRequest(msg) => {
                assert!(
                    msg.contains("plaintext HTTP"),
                    "Error should mention plaintext HTTP, got: {msg}"
                );
                assert!(
                    msg.contains("otlp-allow-insecure"),
                    "Error should mention the flag, got: {msg}"
                );
            }
            _ => panic!("Expected InvalidRequest error, got: {err:?}"),
        }
        Ok(())
    }

    /// Regression test: OTLP with https:// should not be rejected.
    #[test]
    fn test_otlp_https_accepted() -> KResult<()> {
        let otel_params = Some(OpenTelemetryConfig {
            otlp_url: Some("https://collector.example.com:4317".to_owned()),
            otlp_allow_insecure: false,
            enable_metering: true,
            environment: Some("test".to_owned()),
        });

        let result = KMS::validate_otlp_url("https://collector.example.com:4317", &otel_params);
        assert!(result.is_ok(), "https OTLP should be accepted");
        Ok(())
    }

    /// Regression test: OTLP plaintext HTTP is accepted when allow_insecure is true.
    #[test]
    fn test_otlp_plaintext_http_accepted_when_allowed() -> KResult<()> {
        let otel_params = Some(OpenTelemetryConfig {
            otlp_url: Some("http://localhost:4317".to_owned()),
            otlp_allow_insecure: true,
            enable_metering: true,
            environment: Some("test".to_owned()),
        });

        let result = KMS::validate_otlp_url("http://localhost:4317", &otel_params);
        assert!(
            result.is_ok(),
            "http OTLP with allow_insecure=true should be accepted"
        );
        Ok(())
    }

    /// Regression test: no OTLP params means no OTLP validation error.
    #[test]
    fn test_otlp_no_params_accepts_any_url() -> KResult<()> {
        // With None otel_params, allow_insecure defaults to false
        let result = KMS::validate_otlp_url("http://localhost:4317", &None);
        assert!(
            result.is_err(),
            "http without otel_params should be rejected"
        );
        Ok(())
    }
}

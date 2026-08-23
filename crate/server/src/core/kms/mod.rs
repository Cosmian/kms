use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{Resource, metrics::PeriodicReader};
mod kmip;
mod other_kms_methods;
pub(crate) mod permissions;

use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, atomic::AtomicU64},
};

use cosmian_kms_server_database::{
    Database, DbMetricsRecorder,
    reexport::cosmian_kms_interfaces::{CryptoOracle, HSM, HsmStore, ObjectsStore},
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

#[cfg(target_os = "linux")]
const OTHER_HSM_PKCS11_LIB: &str = "/lib/libkmshsm.so";
#[cfg(target_os = "macos")]
const OTHER_HSM_PKCS11_LIB: &str = "/usr/local/lib/libkmshsm.dylib";

// Reuse HSM instances across multiple test servers (e.g. Utimaco) to
// avoid re-initialization failures when starting several KMS instances in the
// same process for CLI tests exercising privileged & non-privileged endpoints.
// Each element is `Arc<dyn HSM>` for one configured HSM instance, in the same
// order as `ServerParams::hsm_instances`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
static GLOBAL_HSMS: OnceCell<Vec<Arc<dyn HSM + Send + Sync>>> = OnceCell::const_new();

use crate::{
    config::{OpenTelemetryConfig, ServerParams},
    core::OtelMetrics,
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Macro to instantiate an HSM with support for environment variable override.
/// Returns an `Arc<dyn HSM + Send + Sync>` without touching any global state.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(unused_macros)] // only expanded on linux/macos targets that instantiate an HSM
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

    /// Monotonically increasing CRL sequence counter (RFC 5280 §5.2.3).
    ///
    /// Seeded on startup from `max(unix_timestamp, db_max_crl_number + 1)` so
    /// that CRL Numbers are strictly greater than any previously issued number
    /// across server restarts.  The `fetch_add` ensures uniqueness even when
    /// two CRLs are generated within the same second.
    pub(crate) crl_counter: Arc<AtomicU64>,
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
            let hsm_store = HsmStore::new(
                hsm_arc.clone(),
                &inst.admin,
                &server_params.vendor_identification,
                &inst.prefix,
            );
            object_stores.insert(inst.prefix.clone(), Arc::new(hsm_store.clone()));
            crypto_oracles.insert(inst.prefix.clone(), Box::new(hsm_store));
        }

        // Instantiate the main database
        let main_db_params = server_params.main_db_params.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("The main database parameters are not specified".to_owned())
        })?;

        let metrics = Self::create_otel_metrics(&server_params)?;
        let db_otel_recorder: Option<Arc<dyn DbMetricsRecorder>> =
            metrics.as_ref().map(|m| -> Arc<dyn DbMetricsRecorder> {
                m.clone() // Arc clones are cheap
            });

        let cache_max_size =
            NonZeroUsize::new(server_params.unwrapped_cache_max_size).ok_or_else(|| {
                KmsError::InvalidRequest(
                    "unwrapped_cache_max_size must be greater than 0".to_owned(),
                )
            })?;
        let database = Database::instantiate(
            main_db_params,
            server_params.clear_db_on_start,
            object_stores,
            server_params.unwrapped_cache_max_age,
            cache_max_size,
            server_params.unwrapped_cache_max_ttl,
            server_params.disable_unwrapped_cache,
            db_otel_recorder,
            server_params.ceremony_keys.clone(),
        )
        .await?;

        // Seed the kms.objects.total gauge from the real DB count on startup.
        //
        // This ensures the metric starts at the correct absolute value rather
        // than 0.  Without this seed, the gauge would only reach the right count
        // after the first periodic cron sync (up to 30 s later), giving a
        // misleading reading immediately after server restart.
        if let Some(ref m) = metrics {
            match database.count_all_non_destroyed_objects().await {
                Ok(count) => {
                    m.update_objects_total(i64::try_from(count).unwrap_or(i64::MAX));
                }
                Err(e) => {
                    // Non-fatal: the cron will correct the value within 30 s.
                    cosmian_logger::debug!("[kms-init] Failed to seed kms.objects.total: {e}");
                }
            }
            // Seed kms.keys.active.count from the real DB count on startup.
            match database.count_non_destroyed_key_objects().await {
                Ok(count) => {
                    m.update_active_keys_count(i64::try_from(count).unwrap_or(i64::MAX));
                }
                Err(e) => {
                    // Non-fatal: the cron will correct the value within 30 s.
                    cosmian_logger::debug!("[kms-init] Failed to seed kms.keys.active.count: {e}");
                }
            }
        }

        // Seed the CRL sequence counter (RFC 5280 §5.2.3 — monotonically increasing).
        //
        // The counter must be strictly greater than any CRL Number previously stored in the
        // DB, so that relying-party caches never see a CRL with a lower sequence number
        // after a server restart.  The seed is max(unix_timestamp, db_max + 1).
        let crl_counter = {
            let ts_seed =
                u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(1);
            let db_max = match database.get_max_crl_number().await {
                Ok(Some(max)) => max,
                Ok(None) => 0,
                Err(e) => {
                    // Non-fatal: fall back to timestamp seed only.
                    cosmian_logger::debug!(
                        "[kms-init] Failed to read max CRL number from DB: {e}; \
                         using unix timestamp as CRL counter seed"
                    );
                    0
                }
            };
            Arc::new(AtomicU64::new(ts_seed.max(db_max + 1)))
        };

        Ok(Self {
            params: server_params.clone(),
            database,
            crypto_oracles: RwLock::new(crypto_oracles),
            // Keep a reference to the first HSM for PKCS#11 C_Initialize / C_GetInfo operations.
            hsm: hsm_instances.into_iter().next(),
            metrics,
            crl_counter,
        })
    }

    /// Validate that the OTLP URL is not using plaintext HTTP unless explicitly allowed.
    /// This prevents accidental exposure of telemetry data over unencrypted channels.
    pub fn validate_otlp_url(
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

            // Create periodic reader that sends metrics every 30 seconds.
            // otel_sdk 0.29: builder takes only the exporter (no runtime arg);
            // export timeout is configured on the exporter, not the reader.
            let reader = PeriodicReader::builder(exporter)
                .with_interval(std::time::Duration::from_secs(30))
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
                .with_resource(Resource::builder().with_attributes(resource_kvs).build())
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

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        kms_bail!("Fatal: HSMs are only supported on Linux and macOS");

        #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
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

    /// Regression test: no OTLP params means allow_insecure defaults to false,
    /// so plaintext HTTP is rejected.
    #[test]
    fn test_otlp_no_params_rejects_plaintext_http() -> KResult<()> {
        // With None otel_params, allow_insecure defaults to false
        let result = KMS::validate_otlp_url("http://localhost:4317", &None);
        assert!(
            result.is_err(),
            "http without otel_params should be rejected"
        );
        Ok(())
    }
}

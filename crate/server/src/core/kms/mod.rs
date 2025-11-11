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
use tokio::sync::{OnceCell, RwLock};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use utimaco_pkcs11_loader::{UTIMACO_PKCS11_LIB, Utimaco};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const OTHER_HSM_PKCS11_LIB: &str = "/lib/libkmshsm.so";

// Reuse a single HSM instance across multiple test servers (e.g. Utimaco) to
// avoid re-initialization failures when starting several KMS instances in the
// same process for CLI tests exercising privileged & non-privileged endpoints.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static GLOBAL_HSM: OnceCell<Arc<dyn HSM + Send + Sync>> = OnceCell::const_new();

use crate::{config::ServerParams, error::KmsError, kms_bail, result::KResult};

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
        if let Some(hsm) = hsm {
            encryption_oracles.insert(
                "hsm".to_owned(),
                Box::new(HsmEncryptionOracle::new(hsm.clone())),
            );
        }

        Ok(Self {
            params: server_params,
            database,
            encryption_oracles: RwLock::new(encryption_oracles),
        })
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
                    "crypt2pay" => {
                        let crypt2pay: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Crypt2pay::instantiate(
                                CRYPT2PAY_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the Crypt2pay HSM: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(crypt2pay.clone()).ok();
                        Some(crypt2pay)
                    }
                    "proteccio" => {
                        let proteccio: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Proteccio::instantiate(
                                PROTECCIO_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the Proteccio HSM: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(proteccio.clone()).ok();
                        Some(proteccio)
                    }
                    "utimaco" => {
                        let utimaco: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Utimaco::instantiate(
                                UTIMACO_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the Utimaco HSM: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(utimaco.clone()).ok();
                        Some(utimaco)
                    }
                    "softhsm2" => {
                        let softhsm2: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Softhsm2::instantiate(
                                SOFTHSM2_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the Softhsm2: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(softhsm2.clone()).ok();
                        Some(softhsm2)
                    }
                    "smartcardhsm" => {
                        let smartcardhsm: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Smartcardhsm::instantiate(
                                SMARTCARDHSM_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the Smartcardhsm: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(smartcardhsm.clone()).ok();
                        Some(smartcardhsm)
                    }
                    "other" => {
                        // we expect the other HSM to be compatible with Softhsm2
                        let other_hsm: Arc<dyn HSM + Send + Sync> = Arc::new(
                            Softhsm2::instantiate(
                                OTHER_HSM_PKCS11_LIB,
                                server_params.slot_passwords.clone(),
                            )
                            .map_err(|e| {
                                KmsError::InvalidRequest(format!(
                                    "Failed to instantiate the HSM lib at {OTHER_HSM_PKCS11_LIB}: {e}"
                                ))
                            })?,
                        );
                        GLOBAL_HSM.set(other_hsm.clone()).ok();
                        Some(other_hsm)
                    }
                    _ => kms_bail!(
                        "The only supported HSM models are proteccio, crypt2pay, smartcardhsm, softhsm2, utimaco and other"
                    ),
                }
            }
        };
        Ok(hsm)
    }
}

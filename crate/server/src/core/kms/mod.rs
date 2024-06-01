mod kmip;
mod other_kms_methods;
mod permissions;

use std::collections::HashMap;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::sync::Arc;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use cosmian_kms_interfaces::HSM;
use cosmian_kms_interfaces::{EncryptionOracle, HsmEncryptionOracle};
use cosmian_kms_server_database::Database;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use proteccio_pkcs11_loader::Proteccio;
use tokio::sync::RwLock;

use crate::{config::ServerParams, error::KmsError, kms_bail, result::KResult};

/// A Key Management System that partially implements KMIP 2.1:
/// `https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip`
/// and other operations that are not part of KMIP such as Google CSE or Microsoft DKE.
pub struct KMS {
    /// The server parameters built from the configuration file or command line arguments.
    pub(crate) params: ServerParams,

    /// The database is made of two parts:
    /// - The objects' store that stores the cryptographic objects.
    ///    The Object store may be backed by multiple databases or HSMs
    ///    and store the cryptographic objects and their attributes.
    ///    Objects are spread across the underlying stores based on their ID prefix.
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
    pub(crate) async fn instantiate(server_params: ServerParams) -> KResult<Self> {
        //TODO once the Store traits can be move to the `Interfaces` crate, the single HSM instantiation can be
        // de-hardcoded.  The underlying code allows the ise of multiple Stores and Encryption Oracles
        // for multiple prefixes.

        let hsm = if server_params.slot_passwords.is_empty() {
            None
        } else {
            if server_params
                .hsm_model
                .as_ref()
                .map(String::from)
                .unwrap_or_default()
                != "proteccio"
            {
                kms_bail!("The only supported HSM model is Proteccio for now")
            }
            #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
            kms_bail!("Fatal: Proteccio HSM is only supported on Linux x86_64");
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            Some(Arc::new(
                Proteccio::instantiate("/lib/libnethsm.so", server_params.slot_passwords.clone())
                    .map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "Failed to instantiate the Proteccio HSM: {}",
                        e
                    ))
                })?,
            ) as Arc<dyn HSM + Send + Sync>)
        };

        // Instantiate the main database
        let main_db_params = server_params.main_db_params.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("The main database parameters are not specified".to_owned())
        })?;
        let database = Database::instantiate(
            main_db_params,
            server_params.clear_db_on_start,
            hsm.clone(),
            &server_params.hsm_admin,
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
}

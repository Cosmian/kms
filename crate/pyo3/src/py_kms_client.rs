use cloudproof::reexport::{
    cover_crypt::abe_policy::{Attribute, EncryptionHint, Policy},
    crypto_core::bytes_ser_de::Deserializer,
};
use cosmian_kmip::{
    crypto::{
        cover_crypt::{
            attributes::EditPolicyAction,
            kmip_requests::{
                build_create_master_keypair_request,
                build_create_user_decryption_private_key_request, build_destroy_key_request,
                build_import_decryption_private_key_request, build_import_private_key_request,
                build_import_public_key_request, build_rekey_keypair_request,
            },
        },
        generic::kmip_requests::{
            build_decryption_request, build_encryption_request, build_revoke_key_request,
        },
        symmetric::symmetric_key_create_request,
    },
    kmip::{
        kmip_operations::Get,
        kmip_types::{CryptographicAlgorithm, RevocationReason},
    },
    result::KmipResultHelper,
};
use cosmian_kms_client::KmsRestClient;
<<<<<<< HEAD
=======
use cosmian_kms_utils::crypto::{
    cover_crypt::{
        attributes::RekeyEditAction,
        kmip_requests::{
            build_create_master_keypair_request, build_create_user_decryption_private_key_request,
            build_destroy_key_request, build_import_decryption_private_key_request,
            build_import_private_key_request, build_import_public_key_request,
            build_rekey_keypair_request,
        },
    },
    generic::kmip_requests::{
        build_decryption_request, build_encryption_request, build_revoke_key_request,
    },
    symmetric::symmetric_key_create_request,
};
>>>>>>> c27b1648 (feat: replace attribute rotation to access policy rekey)
use openssl::x509::X509;
use pyo3::{
    exceptions::{PyException, PyTypeError},
    prelude::*,
};
use rustls::Certificate;

use crate::py_kms_object::{KmsEncryptResponse, KmsObject};

/// Create a Rekey Keypair request from `PyO3` arguments
/// Returns a `PyO3` Future
macro_rules! rekey_keypair {
    (
        $self:ident,
        $attributes:expr,
        $master_secret_key_identifier:expr,
        $policy_attributes:ident,
        $action:expr,
        $py:ident
    ) => {{
        let $policy_attributes = $attributes
            .into_iter()
            .map(Attribute::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PyTypeError::new_err(e.to_string()))?;

        let request = build_rekey_keypair_request(&$master_secret_key_identifier, $action)
            .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = $self.0.clone();
        pyo3_asyncio::tokio::future_into_py($py, async move {
            let response = client
                .rekey_keypair(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok((
                response
                    .public_key_unique_identifier
                    .to_string()
                    .context("The server did not return the public key uid as a string")?,
                response
                    .private_key_unique_identifier
                    .to_string()
                    .context("The server did not return the private key uid as a string")?,
            ))
        })
    }};
}
/// KMS Objects (e.g. keys) can either be referenced by an UID using a single string, or by a list of tags using a list of string.
pub struct ToUniqueIdentifier(String);

impl FromPyObject<'_> for ToUniqueIdentifier {
    fn extract(arg: &'_ PyAny) -> PyResult<Self> {
        if let Ok(uid) = String::extract(arg) {
            Ok(Self(uid))
        } else if let Ok(tags) = Vec::<String>::extract(arg) {
            Ok(Self(serde_json::to_string(&tags).map_err(|_e| {
                PyException::new_err("invalid tag(s) specified")
            })?))
        } else {
            Err(pyo3::exceptions::PyValueError::new_err(
                "KMS objects can only be referenced with an UID (str) or tags (List[str])",
            ))
        }
    }
}

#[pyclass(subclass)]
pub struct KmsClient(KmsRestClient);

#[pymethods]
impl KmsClient {
    /// Instantiate a KMS Client
    ///
    /// Args:
    ///     - `server_url` (str)                        : url of the KMS server
    ///     - `api_key` (Optional[str])                 : apiKey optional, to authenticate to the KMS
    ///     - `client_pkcs12_path` (Optional[str])      : optional path to client PKCS12, to authenticate to the KMS
    ///     - `client_pkcs12_password` (Optional[str])  : optional password to client PKCS12
    ///     - `database_secret` (Optional[str])         : secret to authenticate to the KMS database
    ///     - `insecure_mode` (bool)                    : accept self signed ssl cert. defaults to False
    ///     - `allowed_tee_tls_cert` (Optional[bytes])  : PEM certificate of a tee.
    ///     - `jwe_public_key` (Optional[str])          : public key for JWE
    #[new]
    #[pyo3(signature = (
        server_url,
        api_key = None,
        client_pkcs12_path = None,
        client_pkcs12_password = None,
        database_secret = None,
        insecure_mode = false,
        allowed_tee_tls_cert = None,
        jwe_public_key = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server_url: &str,
        api_key: Option<&str>,
        client_pkcs12_path: Option<&str>,
        client_pkcs12_password: Option<&str>,
        database_secret: Option<&str>,
        insecure_mode: bool,
        allowed_tee_tls_cert: Option<&str>,
        jwe_public_key: Option<&str>,
    ) -> PyResult<Self> {
        let tee_cert = match allowed_tee_tls_cert {
            Some(cert_bytes) => Some(Certificate(
                X509::from_pem(cert_bytes.as_bytes())
                    .map_err(|_| {
                        PyException::new_err("Cannot parse TEE certificate as PEM".to_string())
                    })?
                    .to_der()
                    .map_err(|_| {
                        PyException::new_err("Cannot convert TEE certificate to DER".to_string())
                    })?,
            )),
            None => None,
        };
        let kms_connector = KmsRestClient::instantiate(
            server_url,
            api_key,
            client_pkcs12_path,
            client_pkcs12_password,
            database_secret,
            insecure_mode,
            tee_cert,
            jwe_public_key,
        )
        .map_err(|_| {
            PyException::new_err(format!(
                "Can't build the query to connect to the kms server {server_url}"
            ))
        })?;
        Ok(Self(kms_connector))
    }

    /// Generate the master authority keys for supplied Policy.
    ///
    /// Args:
    ///     - `policy` (bytes): policy used to generate the keys
    ///     - `tags`: optional tags to use with the keys
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn create_cover_crypt_master_key_pair<'p>(
        &'p self,
        policy: &[u8],
        tags: Option<Vec<String>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Parse the json policy
        let policy = Policy::try_from(policy).map_err(|e| PyTypeError::new_err(e.to_string()))?;

        // Create the kmip query
        let request = build_create_master_keypair_request(&policy, tags.unwrap_or_default())
            .map_err(|e| PyException::new_err(e.to_string()))?;

        // Clone client to avoid lifetime error
        let client = self.0.clone();
        // Convert Rust future to Python
        pyo3_asyncio::tokio::future_into_py(py, async move {
            // Query the KMS with your kmip data and get the key pair ids
            let response = client
                .create_key_pair(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok((
                response
                    .public_key_unique_identifier
                    .to_string()
                    .context("The server did not return the public key uid as a string")?,
                response
                    .private_key_unique_identifier
                    .to_string()
                    .context("The server did not return the private key uid as a string")?,
            ))
        })
    }

    /// Import a Private Master Key into the KMS.
    ///
    /// Args:
    ///     - `private_key` (bytes): key bytes
    ///     - `replace_existing` (bool): set to true to replace an existing key with
    /// the same identifier
    ///     - `link_master_public_key_id` (str): id of the matching master public key
    ///     - `policy` (bytes): policy related to the key
    ///     - `tags`: optional tags to use with the keys
    ///     - `is_wrapped` (bool): whether the key is wrapped
    ///     - `wrapping_password` (Optional[str]): password used to wrap the key
    ///     - `unique_identifier` (Optional[str]): the unique identifier of the key
    ///
    ///
    /// Returns:
    ///     Future[str]: the unique identifier of the key
    #[allow(clippy::too_many_arguments)]
    pub fn import_cover_crypt_master_private_key<'p>(
        &'p self,
        private_key: &[u8],
        replace_existing: bool,
        link_master_public_key_id: &str,
        policy: &[u8],
        tags: Option<Vec<String>>,
        is_wrapped: Option<bool>,
        wrapping_password: Option<String>,
        unique_identifier: Option<String>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Convert policy from bytes
        let policy = Policy::try_from(policy).map_err(|e| PyTypeError::new_err(e.to_string()))?;

        let request = build_import_private_key_request(
            private_key,
            unique_identifier,
            replace_existing,
            link_master_public_key_id,
            &policy,
            is_wrapped.unwrap_or(false),
            wrapping_password,
            tags.unwrap_or_default(),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .context("The server did not return the key uid as a string")?)
        })
    }

    /// Import a Public Master Key into the KMS.
    ///
    /// Args:
    ///     - `public_key` (bytes): key bytes
    ///     - `replace_existing` (bool): set to true to replace an existing key with the same identifier
    ///     - `policy` (bytes): policy related to the key
    ///     - `link_master_private_key_id` (str): id of the matching master private key
    ///     - `unique_identifier` (Optional[str]): the unique identifier of the key
    ///     - `tags`: optional tags to use with the keys
    ///
    /// Returns:
    ///     Future[str]: the unique identifier of the key
    #[allow(clippy::too_many_arguments)]
    pub fn import_cover_crypt_public_key<'p>(
        &'p self,
        public_key: &[u8],
        replace_existing: bool,
        policy: &[u8],
        link_master_private_key_id: &str,
        unique_identifier: Option<String>,
        tags: Option<Vec<String>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Convert policy from bytes
        let policy = Policy::try_from(policy).map_err(|e| PyTypeError::new_err(e.to_string()))?;

        let request = build_import_public_key_request(
            public_key,
            unique_identifier,
            replace_existing,
            &policy,
            link_master_private_key_id,
            tags.unwrap_or_default(),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .context("The server did not return the public key uid as a string")?)
        })
    }

    /// Generate new keys associated to the given access policy in the master keys.
    /// This will rekey in the KMS:
    /// - the master keys
    /// - any user key associated to the access policy.
    ///
    /// Args:
    ///     - `access_policy_str` (str): describe the keys to renew
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn rekey_cover_crypt_access_policy<'p>(
        &'p self,
        access_policy_str: String,
        master_secret_key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let empty: Vec<Attribute> = vec![];
        rekey_keypair!(
            self,
            empty,
            master_secret_key_identifier.0,
            _policy_attributes,
            RekeyEditAction::RekeyAccessPolicy(access_policy_str),
            py
        )
    }

    /// Removes old keys associated to the given master keys from the master
    /// keys. This will permanently remove access to old ciphers.
    /// This will rekey in the KMS:
    /// - the master keys
    /// - any user key associated to the access policy
    ///
    /// Args:
    ///     - `access_policy_str` (str): describe the keys to renew
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn prune_cover_crypt_access_policy<'p>(
        &'p self,
        access_policy_str: String,
        master_secret_key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let empty: Vec<Attribute> = vec![];
        rekey_keypair!(
            self,
            empty,
            master_secret_key_identifier.0,
            _policy_attributes,
            RekeyEditAction::PruneAccessPolicy(access_policy_str),
            py
        )
    }

    /// Remove a specific attribute from a keypair's policy.
    ///
    /// Args:
    ///     - `attribute` (Union[Attribute, str]): attribute to remove e.g. "Department::HR"
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn remove_cover_crypt_attribute<'p>(
        &'p self,
        _attribute: &str,
        _master_secret_key_identifier: ToUniqueIdentifier,
        _py: Python<'p>,
    ) -> PyResult<&PyAny> {
        /*rekey_keypair!(
            self,
            vec![attribute],
            master_secret_key_identifier.0,
            policy_attributes,
            EditPolicyAction::RemoveAttribute(policy_attributes),
            py
        )*/
        Err(PyException::new_err("Not supported yet"))
    }

    /// Disable a specific attribute for a keypair.
    ///
    /// Args:
    ///     - `attribute` (Union[Attribute, str]): attribute to remove e.g. "Department::HR"
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn disable_cover_crypt_attribute<'p>(
        &'p self,
        attribute: &str,
        master_secret_key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        rekey_keypair!(
            self,
            vec![attribute],
            master_secret_key_identifier.0,
            policy_attributes,
            RekeyEditAction::DisableAttribute(policy_attributes),
            py
        )
    }

    /// Add a specific attribute to a keypair's policy.
    ///
    /// Args:
    ///     - `attribute` (Union[Attribute, str]): attribute to remove e.g. "Department::HR"
    ///     - `is_hybridized` (bool): hint for encryption
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn add_cover_crypt_attribute<'p>(
        &'p self,
        attribute: &str,
        is_hybridized: bool,
        master_secret_key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        rekey_keypair!(
            self,
            vec![attribute],
            master_secret_key_identifier.0,
            policy_attributes,
            RekeyEditAction::AddAttribute(
                policy_attributes
                    .into_iter()
                    .map(|attr| (attr, EncryptionHint::new(is_hybridized)))
                    .collect()
            ),
            py
        )
    }

    /// Rename a specific attribute in a keypair's policy.
    ///
    /// Args:
    ///     - `attribute` (Union[Attribute, str]): attribute to remove e.g. "Department::HR"
    ///     - `new_name` (str): the new name for the attribute
    ///     - `master_secret_key_identifier` (Union[str, List[str])): master secret key referenced by its UID or a list of tags
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn rename_cover_crypt_attribute<'p>(
        &'p self,
        _attribute: &str,
        _new_name: &str,
        _master_secret_key_identifier: ToUniqueIdentifier,
        _py: Python<'p>,
    ) -> PyResult<&PyAny> {
        /*rekey_keypair!(
            self,
            vec![attribute],
            master_secret_key_identifier.0,
            policy_attributes,
            EditPolicyAction::RenameAttribute(
                policy_attributes
                    .into_iter()
                    .map(|attr| (attr, new_name.to_string()))
                    .collect()
            ),
            py
        )*/
        Err(PyException::new_err("Not supported yet"))
    }

    /// Generate a user secret key.
    ///     A new user secret key does NOT include to old (i.e. rotated)
    /// partitions.
    ///
    /// Args:
    ///         - `access_policy_str` (str): user access policy
    ///         - `master_secret_key_identifier` (str): master secret key UID
    ///         - `tags`: optional tags to use with the keys
    ///
    ///     Returns:
    ///         Future[str]: User secret key UID
    pub fn create_cover_crypt_user_decryption_key<'p>(
        &'p self,
        access_policy_str: &str,
        master_secret_key_identifier: &str,
        tags: Option<Vec<&str>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_create_user_decryption_private_key_request(
            access_policy_str,
            master_secret_key_identifier,
            tags.unwrap_or_default()
                .into_iter()
                .map(String::from)
                .collect::<Vec<String>>()
                .as_slice(),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .create(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .expect("The server did not return the user secret key uid as a string"))
        })
    }

    /// Import a user secret key into the KMS.
    ///
    /// Args:
    ///     - `private_key` (bytes): key bytes
    ///     - `replace_existing` (bool): set to true to replace an existing key with the same identifier
    ///     - `link_master_private_key_id` (str): id of the matching master private key
    ///     - `access_policy_str` (str): user access policy
    ///     - `tags`: optional tags to use with the key
    ///     - `is_wrapped` (bool): whether the key is wrapped
    ///     - `wrapping_password` (Optional[str]): password used to wrap the key
    ///     - `unique_identifier` (Optional[str]): the unique identifier of the key
    ///
    /// Returns:
    ///     Future[str]: User secret key UID
    #[allow(clippy::too_many_arguments)]
    pub fn import_cover_crypt_user_decryption_key<'p>(
        &'p self,
        private_key: &[u8],
        replace_existing: bool,
        link_master_private_key_id: &str,
        access_policy_str: &str,
        tags: Option<Vec<String>>,
        is_wrapped: Option<bool>,
        wrapping_password: Option<String>,
        unique_identifier: Option<String>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_import_decryption_private_key_request(
            private_key,
            unique_identifier,
            replace_existing,
            link_master_private_key_id,
            access_policy_str,
            is_wrapped.unwrap_or(false),
            wrapping_password,
            tags.unwrap_or_default(),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .expect("The server did not return the user secret key uid as a string"))
        })
    }

    /// Hybrid encryption. Concatenates the encrypted header and the symmetric
    /// ciphertext.
    ///
    /// Args:
    ///     - `access_policy_str` (str): the access policy to use for encryption
    ///     - `data` (bytes): data to encrypt
    ///     - `public_key_identifier` (Union[str, List[str]]): public key unique id or associated tags
    ///     - `header_metadata` (Optional[bytes]): additional data to symmetrically encrypt in the header
    ///     - `authentication_data` (Optional[bytes]): authentication data to use in symmetric encryptions
    ///
    /// Returns:
    ///     Future[bytes]: ciphertext
    ///
    /// If tags resolve to multiple keys, an error is thrown
    #[allow(clippy::too_many_arguments)]
    pub fn cover_crypt_encryption<'p>(
        &'p self,
        encryption_policy_str: String,
        data: Vec<u8>,
        public_key_identifier: ToUniqueIdentifier,
        header_metadata: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_encryption_request(
            &public_key_identifier.0,
            Some(encryption_policy_str),
            data,
            header_metadata,
            authentication_data,
            None,
            None,
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .encrypt(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.data)
        })
    }

    /// Hybrid decryption.
    ///
    /// Args:
    ///     - `encrypted_data` (bytes): encrypted header || symmetric ciphertext
    ///     - `authentication_data` (Optional[bytes]): authentication data to use in symmetric decryption
    ///     - `user_key_identifier` (Union[str, List[str]]): user secret key unique id or associated tags
    ///
    /// Returns:
    ///     Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata
    /// bytes)
    ///
    /// If tags resolve to multiple keys, an error is thrown
    pub fn cover_crypt_decryption<'p>(
        &'p self,
        encrypted_data: Vec<u8>,
        user_key_identifier: ToUniqueIdentifier,
        authentication_data: Option<Vec<u8>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_decryption_request(
            &user_key_identifier.0,
            None,
            encrypted_data,
            None,
            authentication_data,
            None,
            None,
        );

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .decrypt(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;

            match response.data.as_deref() {
                Some(data) => {
                    let mut de = Deserializer::new(data);
                    let metadata = de
                        .read_vec()
                        .map_err(|e| PyException::new_err(e.to_string()))?;
                    let plaintext = de.finalize();

                    Ok((plaintext, metadata))
                }
                None => Ok((vec![], vec![])),
            }
        })
    }

    /// Fetch KMIP object by UID.
    ///
    /// Args:
    ///     - `unique_identifier` (Union[str, List[str]]) - object unique id or associated tags
    ///
    /// Returns:
    ///     Future[KmsObject]
    pub fn get_object<'p>(
        &'p self,
        unique_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .get(Get::from(&unique_identifier.0))
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(KmsObject(response))
        })
    }

    /// Mark a key as revoked
    ///
    /// Args:
    ///     - `revocation_reason` (str): explanation of the revocation
    ///     - `key_identifier` (Union[str, List[str]]) - key unique id or associated tags
    ///     - `tags` to use when the `key_identifier` is not provided
    ///
    /// Returns:
    ///     Future[str]: uid of the revoked key
    ///
    /// If tags resolve to multiple keys, an error is thrown
    pub fn revoke_key<'p>(
        &'p self,
        revocation_reason: &str,
        key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_revoke_key_request(
            &key_identifier.0,
            RevocationReason::TextString(revocation_reason.to_string()),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .revoke(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .context("The server did not return the revoked key uid as a string")?)
        })
    }

    /// Mark a key as destroyed
    ///
    /// Args:
    ///     - `key_identifier` (Union[str, List[str]]) - secret key unique id or associated tags
    ///
    /// Returns:
    ///     Future[str]: uid of the destroyed key
    ///
    /// If tags resolve to multiple keys, an error is thrown
    pub fn destroy_key<'p>(
        &'p self,
        key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_destroy_key_request(&key_identifier.0)
            .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .destroy(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response
                .unique_identifier
                .to_string()
                .context("The server did not return the destroyed key uid as a string")?)
        })
    }

    /// Create a symmetric key using the specified key length, cryptographic algorithm, and optional tags
    ///
    /// Args:
    ///     - `key_len_in_bits` - The length of the key in bits.
    ///     - `algorithm` (str) - The cryptographic algorithm to be used, supported values are "AES" and "ChaCha20".
    ///     - `tags` - Optional tags associated with the key.
    ///
    /// Returns:
    ///     Future[str]: uid of the created key.
    #[pyo3(signature = (
        key_len_in_bits,
        algorithm = "AES",
        tags = None,
    ))]
    pub fn create_symmetric_key<'p>(
        &'p self,
        key_len_in_bits: usize,
        algorithm: &str,
        tags: Option<Vec<String>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let cryptographic_algorithm = match algorithm {
            "AES" => Ok(CryptographicAlgorithm::AES),
            "ChaCha20" => Ok(CryptographicAlgorithm::ChaCha20),
            _ => Err(PyException::new_err("invalid algorithm")),
        }?;
        let request = symmetric_key_create_request(
            key_len_in_bits,
            cryptographic_algorithm,
            tags.unwrap_or_default(),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        // Clone client to avoid lifetime error
        let client = self.0.clone();
        // Convert Rust future to Python
        pyo3_asyncio::tokio::future_into_py(py, async move {
            // Query the KMS with your kmip data and get the key pair ids
            let response = client
                .create(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;

            Ok(response
                .unique_identifier
                .to_string()
                .context("The server did not return the key uid as a string")?)
        })
    }

    /// Encrypts the provided binary data using the specified key identifier or tags.
    ///
    /// Args:
    ///
    ///     - `data` - The binary data to be encrypted.
    ///     - `key_identifier` (Union[str, List[str]]) - secret key unique id or associated tags
    ///
    /// Returns:
    ///     Future[KmsEncryptResponse]: encryption result
    pub fn encrypt<'p>(
        &'p self,
        data: Vec<u8>,
        key_identifier: ToUniqueIdentifier,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request =
            build_encryption_request(&key_identifier.0, None, data, None, None, None, None)
                .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .encrypt(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(KmsEncryptResponse(response))
        })
    }

    /// Decrypts the given ciphertext using the specified key identifier or tags.
    ///
    /// Args:
    ///     - `encrypted_data` (bytes) - ciphertext
    ///     - `key_identifier` (Union[str, List[str]]) - secret key unique id or associated tags
    ///     - `iv_counter_nonce` (Optional[bytes]) - the initialization vector, counter or nonce to be used
    ///     - `authentication_encryption_tag` (Optional[bytes]) - Optional additional binary data used for authentication.
    ///
    /// Returns:
    ///     Future[bytes]: plaintext bytes
    pub fn decrypt<'p>(
        &'p self,
        encrypted_data: Vec<u8>,
        key_identifier: ToUniqueIdentifier,
        iv_counter_nonce: Option<Vec<u8>>,
        authentication_encryption_tag: Option<Vec<u8>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_decryption_request(
            &key_identifier.0,
            iv_counter_nonce,
            encrypted_data,
            authentication_encryption_tag,
            None,
            None,
            None,
        );

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .decrypt(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;

            if let Some(plaintext) = response.data {
                Ok(Some(plaintext.to_vec()))
            } else {
                Ok(None)
            }
        })
    }
}

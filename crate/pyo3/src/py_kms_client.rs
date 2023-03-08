use cosmian_cover_crypt::abe_policy::{AccessPolicy, Attribute, Policy};
use cosmian_kmip::kmip::{kmip_operations::Get, kmip_types::RevocationReason};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::cover_crypt::kmip_requests::{
    build_create_master_keypair_request, build_create_user_decryption_private_key_request,
    build_decryption_request, build_destroy_key_request, build_hybrid_encryption_request,
    build_import_decryption_private_key_request, build_import_private_key_request,
    build_import_public_key_request, build_rekey_keypair_request,
    build_revoke_user_decryption_key_request,
};
use pyo3::{
    exceptions::{PyException, PyTypeError},
    prelude::*,
};

use crate::py_kms_object::KmsObject;

#[pyclass(subclass)]
pub struct KmsClient(KmsRestClient);

#[pymethods]
impl KmsClient {
    /// Instantiate a KMS Client
    ///
    /// Args:
    ///     - `server_url` (str)                : url of the KMS server
    ///     - `api_key` (Optional[str])         : apiKey optional, to authenticate to the KMS
    ///     - `database_secret` (Optional[str]) : secret to authenticate to the KMS database
    ///     - `insecure_mode` (bool)            : accept invalid ssl cert. defaults to False
    #[new]
    #[pyo3(signature = (
        server_url,
        api_key = None,
        database_secret = None,
        insecure_mode = false,
    ))]
    pub fn new(
        server_url: &str,
        api_key: Option<&str>,
        database_secret: Option<&str>,
        insecure_mode: bool,
    ) -> PyResult<Self> {
        let kms_connector = KmsRestClient::instantiate(
            server_url,
            api_key.unwrap_or(""),
            database_secret,
            insecure_mode,
        )
        .map_err(|_| {
            PyException::new_err(format!(
                "Can't build the query to connect to the kms server {}",
                server_url
            ))
        })?;
        Ok(Self(kms_connector))
    }

    /// Generate the master authority keys for supplied Policy.
    ///
    /// Args:
    ///     - `policy` (bytes): policy used to generate the keys
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn create_cover_crypt_master_key_pair<'p>(
        &'p self,
        policy: &[u8],
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Parse the json policy
        let policy = Policy::try_from(policy).map_err(|e| PyTypeError::new_err(e.to_string()))?;

        // Create the kmip query
        let request = build_create_master_keypair_request(&policy)
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
                response.public_key_unique_identifier,
                response.private_key_unique_identifier,
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
    ///     - `is_wrapped` (bool): whether the key is wrapped
    ///     - `wrapping_password` (Optional[str]): password used to wrap the key
    ///     - `unique_identifier` (Optional[str]): the unique identifier of the key
    ///
    /// Returns:
    ///     Future[str]: the unique identifier of the key
    #[allow(clippy::too_many_arguments)]
    pub fn import_cover_crypt_master_private_key_request<'p>(
        &'p self,
        private_key: &[u8],
        replace_existing: bool,
        link_master_public_key_id: &str,
        policy: &[u8],
        is_wrapped: bool,
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
            is_wrapped,
            wrapping_password,
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Import a Public Master Key into the KMS.
    ///
    /// Args:
    ///     - `public_key` (bytes): key bytes
    ///     - `replace_existing` (bool): set to true to replace an existing key with the same identifier
    ///     - `policy` (bytes): policy related to the key
    ///     - `link_master_private_key_id` (str): id of the matching master private key
    ///     - ` unique_identifier` (Optional[str]): the unique identifier of the key
    ///
    /// Returns:
    ///     Future[str]: the unique identifier of the key
    pub fn import_cover_crypt_public_key_request<'p>(
        &'p self,
        public_key: &[u8],
        replace_existing: bool,
        policy: &[u8],
        link_master_private_key_id: &str,
        unique_identifier: Option<String>,
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
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Rotate the given policy attributes. This will rekey in the KMS:
    /// - the Master Keys
    /// - all User Decryption Keys that contain one of these attributes in their
    ///   policy and are not rotated.
    ///
    /// Args:
    ///     - `master_secret_key_identifier` (str): master secret key UID
    ///     - `attributes` (List[Union[Attribute, str]]): attributes to rotate e.g. ["Department::HR"]
    ///
    /// Returns:
    ///     Future[Tuple[str, str]]: (Public key UID, Master secret key UID)
    pub fn rotate_cover_crypt_attributes<'p>(
        &'p self,
        master_secret_key_identifier: &str,
        attributes: Vec<&str>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let policy_attributes = attributes
            .into_iter()
            .map(Attribute::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PyTypeError::new_err(e.to_string()))?;

        let request = build_rekey_keypair_request(master_secret_key_identifier, policy_attributes)
            .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .rekey_keypair(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok((
                response.public_key_unique_identifier,
                response.private_key_unique_identifier,
            ))
        })
    }

    /// Generate a user secret key.
    ///     A new user secret key does NOT include to old (i.e. rotated)
    /// partitions.
    ///
    /// Args:
    ///         - `access_policy_str` (str): user access policy
    ///         - `master_secret_key_identifier` (str): master secret key UID
    ///
    ///     Returns:
    ///         Future[str]: User secret key UID
    pub fn create_cover_crypt_user_decryption_key<'p>(
        &'p self,
        access_policy_str: &str,
        master_secret_key_identifier: &str,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Parse the access policy
        let _access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        let request = build_create_user_decryption_private_key_request(
            access_policy_str,
            master_secret_key_identifier,
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .create(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Import a user secret key into the KMS.
    ///
    /// Args:
    ///     - `private_key` (bytes): key bytes
    ///     - `replace_existing` (bool): set to true to replace an existing key with the same identifier
    ///     - `link_master_private_key_id` (str): id of the matching master private key
    ///     - `access_policy_str` (str): user access policy
    ///     - `is_wrapped` (bool): whether the key is wrapped
    ///     - `wrapping_password` (Optional[str]): password used to wrap the key
    ///     - `unique_identifier` (Optional[str]): the unique identifier of the key
    ///
    /// Returns:
    ///     Future[str]: User secret key UID
    #[allow(clippy::too_many_arguments)]
    pub fn import_cover_crypt_user_decryption_key_request<'p>(
        &'p self,
        private_key: &[u8],
        replace_existing: bool,
        link_master_private_key_id: &str,
        access_policy_str: &str,
        is_wrapped: bool,
        wrapping_password: Option<String>,
        unique_identifier: Option<String>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        // Parse the access policy
        let _access_policy = AccessPolicy::from_boolean_expression(access_policy_str)
            .map_err(|e| PyTypeError::new_err(format!("Access policy creation failed: {e}")))?;

        let request = build_import_decryption_private_key_request(
            private_key,
            unique_identifier,
            replace_existing,
            link_master_private_key_id,
            access_policy_str,
            is_wrapped,
            wrapping_password,
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .import(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Mark a CoverCrypt Key as revoked
    ///
    /// Args:
    ///     - `key_identifier` (str):  the key unique identifier in the KMS
    ///     - `revocation_reason` (str): explanation of the revocation
    ///
    /// Returns:
    ///     Future[str]: uid of the revoked key
    pub fn revoke_cover_crypt_key<'p>(
        &'p self,
        key_identifier: &str,
        revocation_reason: &str,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_revoke_user_decryption_key_request(
            key_identifier,
            RevocationReason::TextString(revocation_reason.to_string()),
        )
        .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .revoke(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Mark a CoverCrypt Key as destroyed
    ///
    /// Args:
    ///     - `key_identifier` (str):  the key unique identifier in the KMS
    ///
    /// Returns:
    ///     Future[str]: uid of the destroyed key
    pub fn destroy_cover_crypt_key<'p>(
        &'p self,
        key_identifier: &str,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_destroy_key_request(key_identifier)
            .map_err(|e| PyException::new_err(e.to_string()))?;

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .destroy(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(response.unique_identifier)
        })
    }

    /// Hybrid encryption. Concatenates the encrypted header and the symmetric
    /// ciphertext.
    ///
    /// Args:
    ///     - `public_key_identifier` (str): identifier of the public key
    ///     - `access_policy_str` (str): the access policy to use for encryption
    ///     - `data` (bytes): data to encrypt
    ///     - `header_metadata` (Optional[bytes]): additional data to symmetrically encrypt in the header
    ///     - `authentication_data` (Optional[bytes]): authentication data to use in symmetric encryptions
    ///
    /// Returns:
    ///     Future[bytes]: ciphertext
    pub fn cover_crypt_encryption<'p>(
        &'p self,
        public_key_identifier: &str,
        encryption_policy_str: &str,
        data: Vec<u8>,
        header_metadata: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request = build_hybrid_encryption_request(
            public_key_identifier,
            encryption_policy_str,
            data,
            header_metadata,
            authentication_data,
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
    ///     - `user_key_identifier` (str): user secret key identifier
    ///     - `encrypted_data` (bytes): encrypted header || symmetric ciphertext
    ///     - `authentication_data` (Optional[bytes]): authentication data to use in symmetric decryption
    ///
    /// Returns:
    ///     Future[Tuple[bytes, bytes]]: (plaintext bytes, header metadata
    /// bytes)
    pub fn cover_crypt_decryption<'p>(
        &'p self,
        user_key_identifier: &str,
        encrypted_data: Vec<u8>,
        authentication_data: Option<Vec<u8>>,
        py: Python<'p>,
    ) -> PyResult<&PyAny> {
        let request =
            build_decryption_request(user_key_identifier, encrypted_data, authentication_data);

        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .decrypt(request)
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;

            match response.data.as_deref() {
                Some(mut data) => {
                    let header_size = leb128::read::unsigned(&mut data)
                        .map_err(|e| PyException::new_err(e.to_string()))?
                        as usize;
                    Ok((data[header_size..].to_vec(), data[0..header_size].to_vec()))
                }
                None => Ok((vec![], vec![])),
            }
        })
    }

    /// Fetch KMIP object by UID.
    ///
    /// Args:
    ///     - `unique_identifier` (str): UID of the object on the server.
    ///
    /// Returns:
    ///     Future[KmsObject]
    pub fn get_object<'p>(&'p self, unique_identifier: String, py: Python<'p>) -> PyResult<&PyAny> {
        let client = self.0.clone();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let response = client
                .get(Get::from(unique_identifier))
                .await
                .map_err(|e| PyException::new_err(e.to_string()))?;
            Ok(KmsObject::new(response))
        })
    }
}

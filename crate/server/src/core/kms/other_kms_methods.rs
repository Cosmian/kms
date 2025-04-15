use std::{collections::HashSet, sync::Arc};

use actix_web::HttpRequest;
use base64::{
    engine::general_purpose::{self, STANDARD as b64},
    Engine as _,
};
use cosmian_cover_crypt::api::Covercrypt;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_operations::Create,
    kmip_types::{CryptographicAlgorithm, KeyFormatType},
    requests::create_symmetric_key_kmip_object,
};
use cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH;
use cosmian_kms_interfaces::{EncryptionOracle, SessionParams};
use cosmian_kms_server_database::CachedUnwrappedObject;
use openssl::rand::rand_bytes;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{cover_crypt::create_user_decryption_key, wrapping::unwrap_key, KMS},
    error::KmsError,
    result::{KResult, KResultHelper},
};

impl KMS {
    /// Unwrap the object (if need be) and return the unwrapped object.
    /// The unwrapped object is cached in memory.
    /// # Arguments
    /// * `uid` - The unique identifier of the object
    /// * `object` - The object to unwrap
    /// * `user` - The user requesting the unwrapped object
    /// * `params` - Extra parameters for the store
    /// # Errors
    /// If the object is not a key object
    pub async fn get_unwrapped(
        &self,
        uid: &str,
        object: &Object,
        user: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> KResult<Object> {
        // Is this an unwrapped key?
        if object
            .key_block()
            .context("Cannot unwrap non key object")?
            .key_wrapping_data
            .is_none()
        {
            // already an unwrapped key
            trace!("Already an unwrapped key");
            return Ok(object.clone());
        }

        // check if we have it in the cache
        match self.database.unwrapped_cache().peek(uid).await {
            Some(Ok(u)) => {
                // Note: In theory, the cache should always be in sync...
                if u.key_signature() == object.key_signature()? {
                    debug!("Unwrapped cache hit");
                    return Ok(u.unwrapped_object().clone());
                }
            }
            Some(Err(e)) => {
                return Err(e.into());
            }
            None => {
                // try unwrapping
            }
        }

        // local async future that unwraps the object
        let unwrap_local = async {
            let key_signature = object.key_signature()?;
            let mut unwrapped_object = object.clone();
            let key_block = unwrapped_object.key_block_mut()?;
            unwrap_key(key_block, self, user, params).await?;
            Ok(CachedUnwrappedObject::new(key_signature, unwrapped_object))
        };

        // cache miss, try to unwrap
        debug!("Unwrapped cache miss. Calling unwrap");
        let unwrapped_object = unwrap_local.await;
        //pre-calculating the result avoids a clone on the `CachedUnwrappedObject`
        let result = unwrapped_object
            .as_ref()
            .map(|u| u.unwrapped_object().to_owned())
            .map_err(KmsError::clone);
        // update cache is there is one
        self.database
            .unwrapped_cache()
            .insert(uid.to_owned(), unwrapped_object.map_err(Into::into))
            .await;
        //return the result
        result
    }

    /// Create a new symmetric key and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_kk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    pub(crate) fn create_symmetric_key_and_tags(
        request: &Create,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        let attributes = &request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for secret key creation".to_owned(),
            )
        })?;

        match cryptographic_algorithm {
            CryptographicAlgorithm::AES
            | CryptographicAlgorithm::ChaCha20
            | CryptographicAlgorithm::ChaCha20Poly1305
            | CryptographicAlgorithm::SHA3224
            | CryptographicAlgorithm::SHA3256
            | CryptographicAlgorithm::SHA3384
            | CryptographicAlgorithm::SHA3512
            | CryptographicAlgorithm::SHAKE128
            | CryptographicAlgorithm::SHAKE256 => match attributes.key_format_type {
                None | Some(KeyFormatType::TransparentSymmetricKey) => {
                    // create the key
                    let key_len = attributes
                        .cryptographic_length
                        .map(|len| usize::try_from(len / 8))
                        .transpose()?
                        .map_or(AES_256_GCM_KEY_LENGTH, |v| v);
                    let mut symmetric_key = Zeroizing::from(vec![0; key_len]);
                    rand_bytes(&mut symmetric_key)?;
                    let object = create_symmetric_key_kmip_object(&symmetric_key, attributes)?;
                    let attributes = object.attributes()?;
                    debug!("Created symmetric key with attributes: {:?}", attributes);
                    let tags = attributes.get_tags();
                    let uid = attributes
                        .unique_identifier
                        .as_ref()
                        .map(ToString::to_string);
                    //return the object and the tags
                    Ok((uid, object, tags))
                }
                Some(other) => Err(KmsError::InvalidRequest(format!(
                    "unable to generate a symmetric key for format: {other}"
                ))),
            },
            other => Err(KmsError::NotSupported(format!(
                "the creation of secret key for algorithm: {other:?} is not supported"
            ))),
        }
    }

    /// Create a private key and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_uk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    ///
    /// Only Covercrypt user decryption keys can be created using this function
    pub(crate) async fn create_private_key_and_tags(
        &self,
        create_request: &Create,
        owner: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for private key creation".to_owned(),
            )
        })?;

        match &cryptographic_algorithm {
            CryptographicAlgorithm::CoverCrypt => {
                let object = create_user_decryption_key(
                    self,
                    Covercrypt::default(),
                    create_request,
                    owner,
                    params,
                    create_request.attributes.sensitive,
                )
                .await?;
                let attributes = object.attributes()?;
                let tags = attributes.get_tags();
                let uid = attributes
                    .unique_identifier
                    .as_ref()
                    .map(ToString::to_string);
                Ok((uid, object, tags))
            }
            other => Err(KmsError::NotSupported(format!(
                "the creation of a private key for algorithm: {other:?} is not supported"
            ))),
        }
    }

    /// Register an encryption oracle for a given key prefix.
    /// The encryption oracle will be used to encrypt/decrypt data using keys with the given prefix.
    /// # Arguments
    /// * `prefix` - The key prefix for which the encryption oracle will be used.
    /// * `oracle` - The encryption oracle to register.
    pub async fn register_encryption_oracles(
        &self,
        prefix: &str,
        oracle: Box<dyn EncryptionOracle + Sync + Send>,
    ) {
        let mut oracles = self.encryption_oracles.write().await;
        oracles.insert(prefix.to_owned(), oracle);
    }
}

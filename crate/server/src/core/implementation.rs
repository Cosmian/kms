use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use cloudproof::reexport::{
    cover_crypt::Covercrypt,
    crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        Aes256Gcm, CsRng, FixedSizeCBytes, SymmetricKey,
    },
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Create, CreateKeyPair},
    kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve, StateEnumeration},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::{
        cover_crypt::{decryption::CovercryptDecryption, encryption::CoverCryptEncryption},
        curve_25519::operation::{create_ed25519_key_pair, create_x25519_key_pair},
        hybrid_encryption_system::{HybridDecryptionSystem, HybridEncryptionSystem},
        symmetric::{create_symmetric_key, AesGcmSystem},
    },
    tagging::{check_user_tags, get_tags},
    DecryptionSystem, EncryptionSystem, KeyPair,
};
use tracing::{debug, trace};
use zeroize::Zeroize;

use super::{cover_crypt::create_user_decryption_key, KMS};
use crate::{
    config::{DbParams, ServerParams},
    core::{certificate::verify::verify_certificate, operations::unwrap_key},
    database::{
        cached_sqlcipher::CachedSqlCipher,
        mysql::MySqlPool,
        object_with_metadata::ObjectWithMetadata,
        pgsql::PgPool,
        redis::{RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH},
        sqlite::SqlitePool,
        Database,
    },
    error::KmsError,
    kms_bail, kms_not_supported,
    result::KResult,
};

impl KMS {
    pub async fn instantiate(mut shared_config: ServerParams) -> KResult<Self> {
        let db: Box<dyn Database + Sync + Send> = if let Some(mut db_params) =
            shared_config.db_params.as_mut()
        {
            match &mut db_params {
                DbParams::SqliteEnc(db_path) => Box::new(
                    CachedSqlCipher::instantiate(db_path, shared_config.clear_db_on_start).await?,
                ),
                DbParams::Sqlite(db_path) => Box::new(
                    SqlitePool::instantiate(
                        &db_path.join("kms.db"),
                        shared_config.clear_db_on_start,
                    )
                    .await?,
                ),
                DbParams::Postgres(url) => Box::new(
                    PgPool::instantiate(url.as_str(), shared_config.clear_db_on_start).await?,
                ),
                DbParams::Mysql(url) => Box::new(
                    MySqlPool::instantiate(url.as_str(), shared_config.clear_db_on_start).await?,
                ),
                DbParams::RedisFindex(url, master_key, label) => {
                    // There is no reason to keep a copy of the key in the shared config
                    // So we are going to create a "zeroizable" copy which will be passed to Redis with Findex
                    // and zerorize the one in the shared config
                    let new_master_key =
                        SymmetricKey::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::try_from_bytes(
                            master_key.to_bytes(),
                        )?;
                    master_key.zeroize();
                    Box::new(
                        RedisWithFindex::instantiate(url.as_str(), new_master_key, label).await?,
                    )
                }
            }
        } else {
            kms_bail!("Fatal: no database configuration provided. Stopping.")
        };

        Ok(Self {
            params: shared_config,
            db,
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        })
    }

    /// Get the CS-RNG
    #[must_use]
    pub fn rng(&self) -> Arc<Mutex<CsRng>> {
        self.rng.clone()
    }

    /// Return an encryption system based on the type of key
    pub async fn get_encryption_system(
        &self,
        mut owm: ObjectWithMetadata,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Box<dyn EncryptionSystem>> {
        // the key must be active
        if owm.state != StateEnumeration::Active {
            kms_bail!(KmsError::InconsistentOperation(
                "the server can't encrypt: the key is not active".to_owned()
            ));
        }

        // unwrap if wrapped
        match &owm.object {
            Object::Certificate { .. } => {}
            _ => {
                if owm.object.key_wrapping_data().is_some() {
                    let key_block = owm.object.key_block_mut()?;
                    unwrap_key(key_block, self, &owm.owner, params).await?;
                }
            }
        }

        trace!("get_encryption_system: unwrap done (if required)");
        match &owm.object {
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    match &key_block.cryptographic_algorithm {
                        Some(CryptographicAlgorithm::AES) => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?)
                                as Box<dyn EncryptionSystem>)
                        }
                        other => {
                            kms_not_supported!(
                                "symmetric encryption with algorithm: {}",
                                other
                                    .map(|alg| alg.to_string())
                                    .unwrap_or("[N/A]".to_string())
                            )
                        }
                    }
                }
                other => kms_not_supported!("encryption with keys of format: {other}"),
            },
            Object::PublicKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::CoverCryptPublicKey => Ok(Box::new(
                    CoverCryptEncryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?,
                )
                    as Box<dyn EncryptionSystem>),
                KeyFormatType::TransparentECPublicKey => match key_block.cryptographic_algorithm {
                    Some(CryptographicAlgorithm::ECDH) => Ok(Box::new(
                        HybridEncryptionSystem::instantiate(&owm.id, &owm.object)?,
                    )
                        as Box<dyn EncryptionSystem>),
                    x => kms_not_supported!(
                        "EC public key with cryptographic algorithm {} not supported",
                        x.map(|alg| alg.to_string()).unwrap_or("[N/A]".to_string())
                    ),
                },
                KeyFormatType::TransparentRSAPublicKey => match key_block.cryptographic_algorithm {
                    Some(CryptographicAlgorithm::RSA) => Ok(Box::new(
                        HybridEncryptionSystem::instantiate(&owm.id, &owm.object)?,
                    )
                        as Box<dyn EncryptionSystem>),
                    x => kms_not_supported!(
                        "RSA public key with cryptographic algorithm {} not supported",
                        x.map(|alg| alg.to_string()).unwrap_or("[N/A]".to_string())
                    ),
                },
                other => kms_not_supported!("encryption with public keys of format: {other}"),
            },
            Object::Certificate {
                certificate_value, ..
            } => {
                debug!("Encryption with certificate: verifying certificate");

                // Check certificate validity
                verify_certificate(certificate_value, None, self, &owm.owner, params).await?;

                Ok(
                    Box::new(HybridEncryptionSystem::instantiate_with_certificate(
                        &owm.id,
                        certificate_value,
                    )?) as Box<dyn EncryptionSystem>,
                )
            }
            other => kms_not_supported!("encryption with keys of type: {}", other.object_type()),
        }
    }

    /// Return a decryption system based on the type of key
    pub(crate) async fn get_decryption_system(
        &self,
        cover_crypt: Covercrypt,
        mut owm: ObjectWithMetadata,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Box<dyn DecryptionSystem>> {
        debug!("get_decryption_system: entering");
        // unwrap if wrapped
        if owm.object.key_wrapping_data().is_some() {
            let key_block = owm.object.key_block_mut()?;
            unwrap_key(key_block, self, &owm.owner, params).await?;
        }

        trace!(
            "get_decryption_system: matching on object: {:?}",
            owm.object
        );
        match &owm.object {
            Object::PrivateKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::CoverCryptSecretKey => Ok(Box::new(
                    CovercryptDecryption::instantiate(cover_crypt, &owm.id, &owm.object)?,
                )),
                KeyFormatType::TransparentECPrivateKey => match key_block.cryptographic_algorithm {
                    Some(CryptographicAlgorithm::ECDH) => Ok(Box::new(HybridDecryptionSystem {
                        private_key: owm.object.clone(),
                        private_key_uid: Some(owm.id),
                    })
                        as Box<dyn DecryptionSystem>),
                    x => kms_not_supported!(
                        "EC public keys with cryptographic algorithm {} not supported",
                        x.map(|alg| alg.to_string()).unwrap_or("[N/A]".to_string())
                    ),
                },
                KeyFormatType::TransparentRSAPrivateKey => {
                    match key_block.cryptographic_algorithm {
                        Some(CryptographicAlgorithm::RSA) => Ok(Box::new(HybridDecryptionSystem {
                            private_key: owm.object.clone(),
                            private_key_uid: Some(owm.id),
                        })
                            as Box<dyn DecryptionSystem>),
                        x => kms_not_supported!(
                            "RSA public keys with cryptographic algorithm {} not supported",
                            x.map(|alg| alg.to_string()).unwrap_or("[N/A]".to_string())
                        ),
                    }
                }
                other => kms_not_supported!("decryption with keys of format: {other}"),
            },
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    match &key_block.cryptographic_algorithm {
                        Some(CryptographicAlgorithm::AES) => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?))
                        }
                        other => {
                            kms_not_supported!(
                                "symmetric decryption with algorithm: {}",
                                other
                                    .map(|alg| alg.to_string())
                                    .unwrap_or("[N/A]".to_string())
                            )
                        }
                    }
                }
                other => kms_not_supported!("decryption with keys of format: {other}"),
            },
            other => kms_not_supported!("decryption with keys of type: {}", other.object_type()),
        }
    }

    /// Create a new symmetric key and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_kk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    pub(crate) fn create_symmetric_key_and_tags(
        &self,
        rng: &mut CsRng,
        request: &Create,
    ) -> KResult<(Object, HashSet<String>)> {
        let attributes = &request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for secret key creation".to_string(),
            )
        })?;

        // recover tags
        let mut tags = get_tags(attributes);
        check_user_tags(&tags)?;
        //update the tags
        tags.insert("_kk".to_string());

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
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a symmetric key, the format type is not specified"
                        .to_string()
                )),
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    // create the key
                    let key_len: usize = attributes
                        .cryptographic_length
                        .map_or(Aes256Gcm::KEY_LENGTH, |v| v as usize / 8);
                    let mut symmetric_key = vec![0; key_len];
                    rng.fill_bytes(&mut symmetric_key);
                    let object = create_symmetric_key(&symmetric_key, *cryptographic_algorithm);

                    //return the object and the tags
                    Ok((object, tags))
                }
                Some(other) => kms_bail!(KmsError::InvalidRequest(format!(
                    "unable to generate a symmetric key for format: {other}"
                ))),
            },
            other => kms_not_supported!(
                "the creation of secret key for algorithm: {other:?} is not supported"
            ),
        }
    }

    /// Create a private key and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_sk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    ///
    /// Only Covercrypt user decryption keys can be created using this function
    pub(crate) async fn create_private_key_and_tags(
        &self,
        create_request: &Create,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<(Object, HashSet<String>)> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for private key creation"
                    .to_string(),
            )
        })?;

        // recover tags
        let mut tags = get_tags(attributes);
        check_user_tags(&tags)?;
        //update the tags
        tags.insert("_uk".to_string());

        match &cryptographic_algorithm {
            CryptographicAlgorithm::CoverCrypt => {
                let object = create_user_decryption_key(
                    self,
                    Covercrypt::default(),
                    create_request,
                    owner,
                    params,
                )
                .await?;
                Ok((object, tags))
            }
            other => kms_not_supported!(
                "the creation of a private key for algorithm: {other:?} is not supported"
            ),
        }
    }

    /// Create a key pair and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_sk" for the private key
    ///  - "_pk" for the public key
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    ///
    /// Only Covercrypt master keys can be created using this function
    pub(crate) fn create_key_pair_and_tags(
        &self,
        request: &CreateKeyPair,
        private_key_uid: &str,
        public_key_uid: &str,
    ) -> KResult<(KeyPair, HashSet<String>, HashSet<String>)> {
        trace!("Internal create key pair");
        let attributes = request
            .common_attributes
            .as_ref()
            .or(request.private_key_attributes.as_ref())
            .or(request.public_key_attributes.as_ref())
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "Attributes must be provided in a CreateKeyPair request".to_owned(),
                )
            })?;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for key pair creation".to_string(),
            )
        })?;

        // recover tags
        let tags = get_tags(attributes);
        check_user_tags(&tags)?;
        //update the tags
        let mut sk_tags = tags.clone();
        sk_tags.insert("_sk".to_string());
        let mut pk_tags = tags;
        pk_tags.insert("_pk".to_string());

        let key_pair = match &cryptographic_algorithm {
            CryptographicAlgorithm::ECDH => {
                let dp = attributes
                    .cryptographic_domain_parameters
                    .unwrap_or_default();
                match dp.recommended_curve.unwrap_or_default() {
                    RecommendedCurve::CURVE25519 => {
                        let mut rng = self.rng.lock().expect("RNG lock poisoned");
                        create_x25519_key_pair(&mut *rng, private_key_uid, public_key_uid)
                    }
                    RecommendedCurve::CURVEED25519 => kms_not_supported!(
                        "An Edwards Keypair on curve 25519 should not be requested to perform ECDH"
                    ),
                    other => kms_not_supported!(
                        "Generation of Key Pair for curve: {other:?}, is not supported"
                    ),
                }
            }
            CryptographicAlgorithm::Ed25519 => {
                let mut rng = self.rng.lock().expect("RNG lock poisoned");
                create_ed25519_key_pair(&mut *rng, private_key_uid, public_key_uid)
            }
            CryptographicAlgorithm::CoverCrypt => {
                cosmian_kms_utils::crypto::cover_crypt::master_keys::create_master_keypair(
                    &Covercrypt::default(),
                    request,
                    private_key_uid,
                    public_key_uid,
                )
                .map_err(Into::into)
            }
            other => kms_not_supported!(
                "The creation of a key pair for algorithm: {other:?} is not supported"
            ),
        }?;
        Ok((key_pair, sk_tags, pk_tags))
    }
}

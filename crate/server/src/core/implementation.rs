use std::sync::{Arc, Mutex};

use cloudproof::reexport::{
    cover_crypt::statics::CoverCryptX25519Aes256,
    crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        symmetric_crypto::aes_256_gcm_pure,
        CsRng,
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
        curve_25519::{
            encryption_decryption::{EciesDecryption, EciesEncryption},
            operation::create_ec_key_pair,
        },
        symmetric::{create_symmetric_key, AesGcmSystem},
    },
    DecryptionSystem, EncryptionSystem, KeyPair,
};
use tracing::trace;

use super::{cover_crypt::create_user_decryption_key, KMS};
use crate::{
    config::{DbParams, ServerConfig},
    core::operations::unwrap_key,
    database::{
        cached_sqlcipher::CachedSqlCipher, object_with_metadata::ObjectWithMetadata, pgsql::PgPool,
        sqlite::SqlitePool, Database,
    },
    error::KmsError,
    kms_bail, kms_not_supported,
    result::KResult,
};

impl KMS {
    pub async fn instantiate(shared_config: ServerConfig) -> KResult<Self> {
        let db: Box<dyn Database + Sync + Send> = match &shared_config.db_params {
            DbParams::SqliteEnc(db_path) => Box::new(CachedSqlCipher::instantiate(db_path).await?),
            DbParams::Sqlite(db_path) => {
                Box::new(SqlitePool::instantiate(&db_path.join("kms.db")).await?)
            }
            DbParams::Postgres(url) => Box::new(PgPool::instantiate(url).await?),
            // DbParams::Mysql(url) => Box::new(Sql::instantiate(url).await?),
            DbParams::Mysql(_url) => panic!("MysSQL Support removed for now"),
        };

        Ok(Self {
            config: shared_config,
            db,
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        })
    }

    /// Get the CS-RNG
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
        if owm.object.key_wrapping_data().is_some() {
            let object_type = owm.object.object_type();
            let key_block = owm.object.key_block_mut()?;
            unwrap_key(object_type, key_block, self, &owm.owner, params).await?;
        }

        match &owm.object {
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    match &key_block.cryptographic_algorithm {
                        CryptographicAlgorithm::AES => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?)
                                as Box<dyn EncryptionSystem>)
                        }
                        other => {
                            kms_not_supported!("symmetric encryption with algorithm: {other:?}")
                        }
                    }
                }
                other => kms_not_supported!("encryption with keys of format: {other}"),
            },
            Object::PublicKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::CoverCryptPublicKey => {
                    Ok(Box::new(CoverCryptEncryption::instantiate(
                        CoverCryptX25519Aes256::default(),
                        &owm.id,
                        &owm.object,
                    )?) as Box<dyn EncryptionSystem>)
                }
                KeyFormatType::TransparentECPublicKey => match key_block.cryptographic_algorithm {
                    CryptographicAlgorithm::ECDH => Ok(Box::new(EciesEncryption::instantiate(
                        &owm.id,
                        &owm.object,
                    )?)
                        as Box<dyn EncryptionSystem>),
                    x => kms_not_supported!(
                        "EC public keys with cryptographic algorithm {:?} not supported",
                        x
                    ),
                },
                other => kms_not_supported!("encryption with public keys of format: {other}"),
            },
            other => kms_not_supported!("encryption with keys of type: {}", other.object_type()),
        }
    }

    /// Return a decryption system based on the type of key
    pub(crate) async fn get_decryption_system(
        &self,
        cover_crypt: CoverCryptX25519Aes256,
        mut owm: ObjectWithMetadata,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Box<dyn DecryptionSystem>> {
        // unwrap if wrapped
        if owm.object.key_wrapping_data().is_some() {
            let object_type = owm.object.object_type();
            let key_block = owm.object.key_block_mut()?;
            unwrap_key(object_type, key_block, self, &owm.owner, params).await?;
        }

        match &owm.object {
            Object::PrivateKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::CoverCryptSecretKey => Ok(Box::new(
                    CovercryptDecryption::instantiate(cover_crypt, &owm.id, &owm.object)?,
                )),
                KeyFormatType::TransparentECPrivateKey => match key_block.cryptographic_algorithm {
                    CryptographicAlgorithm::ECDH => Ok(Box::new(EciesDecryption::instantiate(
                        &owm.id,
                        &owm.object,
                    )?)
                        as Box<dyn DecryptionSystem>),
                    x => kms_not_supported!(
                        "EC public keys with cryptographic algorithm {:?} not supported",
                        x
                    ),
                },
                other => kms_not_supported!("decryption with keys of format: {other}"),
            },
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    match &key_block.cryptographic_algorithm {
                        CryptographicAlgorithm::AES => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?))
                        }
                        other => {
                            kms_not_supported!("symmetric decryption with algorithm: {other:?}")
                        }
                    }
                }
                other => kms_not_supported!("decryption with keys of format: {other}"),
            },
            other => kms_not_supported!("decryption with keys of type: {}", other.object_type()),
        }
    }

    pub(crate) fn create_symmetric_key(
        &self,
        rng: &mut CsRng,
        request: &Create,
        _owner: &str,
    ) -> KResult<Object> {
        let attributes = &request.attributes;
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for secret key creation".to_string(),
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
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a symmetric key, the format type is not specified"
                        .to_string()
                )),
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    let key_len: usize = attributes
                        .cryptographic_length
                        .map(|v| v as usize / 8)
                        .unwrap_or(aes_256_gcm_pure::KEY_LENGTH);
                    let mut symmetric_key = vec![0; key_len];
                    rng.fill_bytes(&mut symmetric_key);
                    Ok(create_symmetric_key(
                        &symmetric_key,
                        *cryptographic_algorithm,
                    ))
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

    pub(crate) async fn create_private_key(
        &self,
        create_request: &Create,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Object> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::CoverCrypt) => {
                create_user_decryption_key(
                    self,
                    CoverCryptX25519Aes256::default(),
                    create_request,
                    owner,
                    params,
                )
                .await
            }
            Some(other) => kms_not_supported!(
                "the creation of a private key for algorithm: {other:?} is not supported"
            ),
            None => kms_bail!(KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for private key creation"
                    .to_string()
            )),
        }
    }

    pub(crate) async fn create_key_pair_(
        &self,
        request: &CreateKeyPair,
        private_key_uid: &str,
        public_key_uid: &str,
    ) -> KResult<KeyPair> {
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
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::ECDH) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a EC key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::ECPrivateKey) => {
                    let dp = attributes
                        .cryptographic_domain_parameters
                        .unwrap_or_default();
                    match dp.recommended_curve.unwrap_or_default() {
                        RecommendedCurve::CURVE25519 => {
                            let mut rng = self.rng.lock().expect("RNG lock poisoned");
                            create_ec_key_pair(&mut *rng, private_key_uid, public_key_uid)
                                .map_err(Into::into)
                        }
                        other => kms_not_supported!(
                            "Generation of Key Pair for curve: {other:?}, is not supported"
                        ),
                    }
                }
                Some(other) => {
                    kms_not_supported!("Unable to generate an DH key pair for format: {other}")
                }
            },
            Some(CryptographicAlgorithm::CoverCrypt) => {
                cosmian_kms_utils::crypto::cover_crypt::master_keys::create_master_keypair(
                    &CoverCryptX25519Aes256::default(),
                    request,
                    private_key_uid,
                    public_key_uid,
                )
                .map_err(Into::into)
            }
            Some(other) => kms_not_supported!(
                "The creation of a key pair for algorithm: {other:?} is not supported"
            ),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for key pair creation".to_string()
            )),
        }
    }
}

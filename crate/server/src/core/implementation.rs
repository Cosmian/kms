use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use cloudproof::reexport::{
    cover_crypt::Covercrypt,
    crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng, FixedSizeCBytes, SymmetricKey,
    },
};
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::operation::{
    create_x25519_key_pair, create_x448_key_pair,
};
use cosmian_kmip::{
    crypto::{
        cover_crypt::{
            decryption::CovercryptDecryption, encryption::CoverCryptEncryption,
            master_keys::create_master_keypair,
        },
        elliptic_curves::operation::{
            create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair,
        },
        hybrid_encryption::{HybridDecryptionSystem, HybridEncryptionSystem},
        rsa::operation::create_rsa_key_pair,
        symmetric::{create_symmetric_key_kmip_object, AesGcmSystem, AES_256_GCM_KEY_LENGTH},
        DecryptionSystem, EncryptionSystem, KeyPair,
    },
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Create, CreateKeyPair},
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, RecommendedCurve, StateEnumeration,
        },
    },
    openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use openssl::nid::Nid;
#[cfg(not(feature = "fips"))]
use tracing::warn;
use tracing::{debug, trace};
use zeroize::{Zeroize, Zeroizing};

use super::{cover_crypt::create_user_decryption_key, KMS};
use crate::{
    config::{DbParams, ServerParams},
    core::{extra_database_params::ExtraDatabaseParams, operations::unwrap_key},
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
        trace!("get_encryption_system: entering: object id: {}", owm.id);
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

        let encryption_system = match &owm.object {
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
                    match &key_block.cryptographic_algorithm {
                        Some(CryptographicAlgorithm::AES) => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?)
                                as Box<dyn EncryptionSystem>)
                        }
                        other => {
                            kms_not_supported!(
                                "symmetric encryption with algorithm: {}",
                                other.map_or("[N/A]".to_string(), |alg| alg.to_string())
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
                KeyFormatType::TransparentECPublicKey
                | KeyFormatType::TransparentRSAPublicKey
                | KeyFormatType::PKCS1
                | KeyFormatType::PKCS8 => {
                    trace!(
                        "get_encryption_system: matching on key format type: {:?}",
                        key_block.key_format_type
                    );
                    let public_key = kmip_public_key_to_openssl(&owm.object)?;
                    trace!(
                        "get_encryption_system: OpenSSL Public Key instantiated before encryption"
                    );
                    Ok(
                        Box::new(HybridEncryptionSystem::new(&owm.id, public_key, false))
                            as Box<dyn EncryptionSystem>,
                    )
                }
                other => kms_not_supported!("encryption with public keys of format: {other}"),
            },
            Object::Certificate {
                certificate_value, ..
            } => Ok(
                Box::new(HybridEncryptionSystem::instantiate_with_certificate(
                    &owm.id,
                    certificate_value,
                    false,
                )?) as Box<dyn EncryptionSystem>,
            ),
            other => kms_not_supported!("encryption with keys of type: {}", other.object_type()),
        };
        trace!("get_encryption_system: exiting");
        encryption_system
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
                KeyFormatType::PKCS8
                | KeyFormatType::PKCS1
                | KeyFormatType::TransparentRSAPrivateKey
                | KeyFormatType::TransparentECPrivateKey => {
                    let p_key = kmip_private_key_to_openssl(&owm.object)?;
                    Ok(
                        Box::new(HybridDecryptionSystem::new(Some(owm.id), p_key, false))
                            as Box<dyn DecryptionSystem>,
                    )
                }
                other => kms_not_supported!("decryption with keys of format: {other}"),
            },
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
                    match &key_block.cryptographic_algorithm {
                        Some(CryptographicAlgorithm::AES) => {
                            Ok(Box::new(AesGcmSystem::instantiate(&owm.id, &owm.object)?))
                        }
                        other => {
                            kms_not_supported!(
                                "symmetric decryption with algorithm: {}",
                                other.map_or("[N/A]".to_string(), |alg| alg.to_string())
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
        let mut tags = attributes.get_tags();
        Attributes::check_user_tags(&tags)?;
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
                        .map_or(AES_256_GCM_KEY_LENGTH, |v| v as usize / 8);
                    let mut symmetric_key = Zeroizing::from(vec![0; key_len]);
                    rng.fill_bytes(&mut symmetric_key);
                    let object =
                        create_symmetric_key_kmip_object(&symmetric_key, *cryptographic_algorithm);

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
        let mut tags = attributes.get_tags();
        Attributes::check_user_tags(&tags)?;
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

    /// Create a key pair and the corresponding system tags.
    /// Generate FIPS-140-3 compliant Key Pair for key agreement and digital signature.
    ///
    /// Sources:
    /// - NIST.SP.800-56Ar3 - Appendix D.
    /// - NIST.SP.800-186 - Section 3.1.2 table 2.
    ///
    /// The tags will contain the user tags and the following:
    ///  - "_sk" for the private key
    ///  - "_pk" for the public key
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    ///
    /// Only Covercrypt master keys can be created using this function
    pub(crate) fn create_key_pair_and_tags(
        &self,
        request: CreateKeyPair,
        private_key_uid: &str,
        public_key_uid: &str,
    ) -> KResult<(KeyPair, HashSet<String>, HashSet<String>)> {
        trace!("Internal create key pair");

        let mut common_attributes = request.common_attributes.unwrap_or_default();

        // recover tags and clean them up from the common attributes
        let tags = common_attributes.remove_tags().unwrap_or_default();
        Attributes::check_user_tags(&tags)?;
        // Update the tags for the private key and the public key.
        let mut sk_tags = tags.clone();
        sk_tags.insert("_sk".to_string());
        let mut pk_tags = tags;
        pk_tags.insert("_pk".to_string());

        // Grab whatever attributes were supplied on the  create request.
        let any_attributes = Some(&common_attributes)
            .or(request.private_key_attributes.as_ref())
            .or(request.public_key_attributes.as_ref())
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "Attributes must be provided in a CreateKeyPair request".to_owned(),
                )
            })?;

        // Check that the cryptographic algorithm is specified.
        let cryptographic_algorithm = &any_attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for key pair creation".to_string(),
            )
        })?;

        let key_pair = match &cryptographic_algorithm {
            CryptographicAlgorithm::ECDH => {
                let dp = any_attributes
                    .cryptographic_domain_parameters
                    .unwrap_or_default();
                match dp.recommended_curve.unwrap_or_default() {
                    // P-CURVES
                    #[cfg(not(feature = "fips"))]
                    // Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
                    // legacy-use only** as it provides less than 112 bits of security.
                    //
                    // Sources:
                    // - NIST.SP.800-186 - Section 3.2.1.1
                    RecommendedCurve::P192 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        Nid::X9_62_PRIME192V1,
                    ),
                    RecommendedCurve::P224 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        Nid::SECP224R1,
                    ),
                    RecommendedCurve::P256 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        Nid::X9_62_PRIME256V1,
                    ),
                    RecommendedCurve::P384 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        Nid::SECP384R1,
                    ),
                    RecommendedCurve::P521 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        Nid::SECP521R1,
                    ),

                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVE25519 => {
                        create_x25519_key_pair(private_key_uid, public_key_uid)
                    }
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVE448 => {
                        create_x448_key_pair(private_key_uid, public_key_uid)
                    }
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVEED25519 => {
                        warn!(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed25519_key_pair(private_key_uid, public_key_uid)
                    }

                    #[cfg(feature = "fips")]
                    // Ed25519 not allowed for ECDH.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    RecommendedCurve::CURVEED25519 => {
                        kms_not_supported!(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             ECDH in FIPS mode."
                        )
                    }
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVEED448 => {
                        warn!(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed448_key_pair(private_key_uid, public_key_uid)
                    }
                    #[cfg(feature = "fips")]
                    // Ed448 not allowed for ECDH.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    RecommendedCurve::CURVEED448 => {
                        kms_not_supported!(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             ECDH in FIPS mode."
                        )
                    }
                    other => kms_not_supported!(
                        "Generation of Key Pair for curve: {other:?}, is not supported"
                    ),
                }
            }
            CryptographicAlgorithm::RSA => {
                let key_size_in_bits = any_attributes
                    .cryptographic_length
                    .ok_or_else(|| KmsError::InvalidRequest("RSA key size: error".to_string()))?
                    as u32;
                trace!(
                    "RSA key pair generation: size in bits: {}",
                    key_size_in_bits
                );

                create_rsa_key_pair(key_size_in_bits, public_key_uid, private_key_uid)
            }
            CryptographicAlgorithm::Ed25519 => {
                create_ed25519_key_pair(private_key_uid, public_key_uid)
            }
            CryptographicAlgorithm::Ed448 => create_ed448_key_pair(private_key_uid, public_key_uid),
            CryptographicAlgorithm::CoverCrypt => create_master_keypair(
                &Covercrypt::default(),
                private_key_uid,
                public_key_uid,
                Some(common_attributes),
                request.private_key_attributes,
                request.public_key_attributes,
            )
            .map_err(Into::into),
            other => kms_not_supported!(
                "The creation of a key pair for algorithm: {other:?} is not supported"
            ),
        }?;
        Ok((key_pair, sk_tags, pk_tags))
    }
}

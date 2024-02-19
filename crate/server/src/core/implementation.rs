use std::collections::HashSet;

use cloudproof::reexport::{cover_crypt::Covercrypt, crypto_core::FixedSizeCBytes};
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::operation::{
    create_x25519_key_pair, create_x448_key_pair,
};
use cosmian_kmip::{
    crypto::{
        cover_crypt::master_keys::create_master_keypair,
        elliptic_curves::operation::{
            create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair,
        },
        rsa::operation::create_rsa_key_pair,
        secret::Secret,
        symmetric::{create_symmetric_key_kmip_object, AES_256_GCM_KEY_LENGTH},
        KeyPair,
    },
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Create, CreateKeyPair},
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
    },
};
use openssl::rand::rand_bytes;
use tracing::trace;
#[cfg(not(feature = "fips"))]
use tracing::warn;
use zeroize::Zeroizing;

use super::{
    cover_crypt::create_user_decryption_key, extra_database_params::ExtraDatabaseParams, KMS,
};
use crate::{
    config::{DbParams, ServerParams},
    database::{
        cached_sqlcipher::CachedSqlCipher,
        mysql::MySqlPool,
        pgsql::PgPool,
        redis::{RedisWithFindex, REDIS_WITH_FINDEX_MASTER_KEY_LENGTH},
        sqlite::SqlitePool,
        Database,
    },
    error::KmsError,
    kms_bail,
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
                        Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::from_unprotected_bytes(
                            &mut master_key.to_bytes(),
                        );
                    // `master_key` implements ZeroizeOnDrop so there is no need
                    // to manually zeroize.
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
        })
    }

    /// Create a new symmetric key and the corresponding system tags
    /// The tags will contain the user tags and the following:
    ///  - "_kk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    pub(crate) fn create_symmetric_key_and_tags(
        &self,
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
                None => Err(KmsError::InvalidRequest(
                    "Unable to create a symmetric key, the format type is not specified"
                        .to_string(),
                )),
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    // create the key
                    let key_len: usize = attributes
                        .cryptographic_length
                        .map_or(AES_256_GCM_KEY_LENGTH, |v| v as usize / 8);
                    let mut symmetric_key = Zeroizing::from(vec![0; key_len]);
                    rand_bytes(&mut symmetric_key)?;
                    let object =
                        create_symmetric_key_kmip_object(&symmetric_key, *cryptographic_algorithm);

                    //return the object and the tags
                    Ok((object, tags))
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
            other => Err(KmsError::NotSupported(format!(
                "the creation of a private key for algorithm: {other:?} is not supported"
            ))),
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
        let cryptographic_algorithm = any_attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for key pair creation".to_string(),
            )
        })?;

        let key_pair = match cryptographic_algorithm {
            // EC, ECDSA and ECDH posses the same FIPS restrictions for curves.
            CryptographicAlgorithm::EC
            | CryptographicAlgorithm::ECDH
            | CryptographicAlgorithm::ECDSA => {
                let domain_parameters = any_attributes
                    .cryptographic_domain_parameters
                    .unwrap_or_default();
                let curve = domain_parameters.recommended_curve.unwrap_or_default();

                match curve {
                    #[cfg(not(feature = "fips"))]
                    // Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
                    // legacy-use only** as it provides less than 112 bits of security.
                    //
                    // Sources:
                    // - NIST.SP.800-186 - Section 3.2.1.1
                    RecommendedCurve::P192 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        curve,
                        any_attributes.cryptographic_algorithm,
                        any_attributes.cryptographic_usage_mask,
                    ),
                    RecommendedCurve::P224
                    | RecommendedCurve::P256
                    | RecommendedCurve::P384
                    | RecommendedCurve::P521 => create_approved_ecc_key_pair(
                        private_key_uid,
                        public_key_uid,
                        curve,
                        any_attributes.cryptographic_algorithm,
                        any_attributes.cryptographic_usage_mask,
                    ),
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVE25519 => create_x25519_key_pair(
                        private_key_uid,
                        public_key_uid,
                        any_attributes.cryptographic_algorithm,
                        any_attributes.cryptographic_usage_mask,
                    ),
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVE448 => create_x448_key_pair(
                        private_key_uid,
                        public_key_uid,
                        any_attributes.cryptographic_algorithm,
                        any_attributes.cryptographic_usage_mask,
                    ),
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVEED25519 => {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                            || cryptographic_algorithm == CryptographicAlgorithm::EC
                        {
                            kms_bail!(KmsError::NotSupported(
                                "Edwards curve can't be created for EC or ECDSA".to_string()
                            ))
                        }
                        warn!(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed25519_key_pair(
                            private_key_uid,
                            public_key_uid,
                            any_attributes.cryptographic_algorithm,
                            any_attributes.cryptographic_usage_mask,
                        )
                    }
                    #[cfg(feature = "fips")]
                    // Ed25519 not allowed for ECDH nor ECDSA.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    RecommendedCurve::CURVEED25519 => {
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             Elliptic Curves operations in FIPS mode"
                                .to_string()
                        ))
                    }
                    #[cfg(not(feature = "fips"))]
                    RecommendedCurve::CURVEED448 => {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                            || cryptographic_algorithm == CryptographicAlgorithm::EC
                        {
                            kms_bail!(KmsError::NotSupported(
                                "Edwards curve can't be created for EC or ECDSA".to_string()
                            ))
                        }
                        warn!(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed448_key_pair(
                            private_key_uid,
                            public_key_uid,
                            any_attributes.cryptographic_algorithm,
                            any_attributes.cryptographic_usage_mask,
                        )
                    }
                    #[cfg(feature = "fips")]
                    // Ed448 not allowed for ECDH nor ECDSA.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    RecommendedCurve::CURVEED448 => {
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             ECDH in FIPS mode."
                                .to_string()
                        ))
                    }
                    other => kms_bail!(KmsError::NotSupported(format!(
                        "Generation of Key Pair for curve: {other:?}, is not supported"
                    ))),
                }
            }
            CryptographicAlgorithm::RSA => {
                let key_size_in_bits = any_attributes
                    .cryptographic_length
                    .ok_or_else(|| KmsError::InvalidRequest("RSA key size: error".to_string()))?
                    as u32;
                trace!("RSA key pair generation: size in bits: {key_size_in_bits}");

                create_rsa_key_pair(key_size_in_bits, public_key_uid, private_key_uid)
            }
            CryptographicAlgorithm::Ed25519 => create_ed25519_key_pair(
                private_key_uid,
                public_key_uid,
                any_attributes.cryptographic_algorithm,
                any_attributes.cryptographic_usage_mask,
            ),
            CryptographicAlgorithm::Ed448 => create_ed448_key_pair(
                private_key_uid,
                public_key_uid,
                any_attributes.cryptographic_algorithm,
                any_attributes.cryptographic_usage_mask,
            ),
            CryptographicAlgorithm::CoverCrypt => create_master_keypair(
                &Covercrypt::default(),
                private_key_uid,
                public_key_uid,
                Some(common_attributes),
                request.private_key_attributes,
                request.public_key_attributes,
            )
            .map_err(Into::into),
            other => {
                kms_bail!(KmsError::NotSupported(format!(
                    "The creation of a key pair for algorithm: {other:?} is not supported"
                )))
            }
        }?;
        Ok((key_pair, sk_tags, pk_tags))
    }
}

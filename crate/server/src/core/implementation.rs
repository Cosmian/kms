use std::collections::HashSet;

use cloudproof::reexport::{cover_crypt::Covercrypt, crypto_core::FixedSizeCBytes};
use cosmian_kmip::{
    crypto::{
        secret::Secret,
        symmetric::{create_symmetric_key_kmip_object, symmetric_ciphers::AES_256_GCM_KEY_LENGTH},
    },
    kmip::{
        kmip_objects::Object,
        kmip_operations::Create,
        kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType},
    },
};
use openssl::rand::rand_bytes;
use tracing::trace;
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
    pub(crate) async fn instantiate(mut shared_config: ServerParams) -> KResult<Self> {
        let db: Box<dyn Database + Sync + Send> = if let Some(mut db_params) =
            shared_config.db_params.as_mut()
        {
            match &mut db_params {
                DbParams::SqliteEnc(db_path) => Box::new(CachedSqlCipher::instantiate(
                    db_path,
                    shared_config.clear_db_on_start,
                )?),
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
                    // and zeroize the one in the shared config
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
        request: &Create,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        let attributes = &request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for secret key creation".to_owned(),
            )
        })?;

        // recover tags
        let mut tags = attributes.get_tags();
        Attributes::check_user_tags(&tags)?;
        //update the tags
        tags.insert("_kk".to_owned());

        // recover uid
        let uid = attributes
            .unique_identifier
            .as_ref()
            .map(std::string::ToString::to_string);

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
                    "Unable to create a symmetric key, the format type is not specified".to_owned(),
                )),
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    // create the key
                    let key_len = attributes
                        .cryptographic_length
                        .map(|len| usize::try_from(len / 8))
                        .transpose()?
                        .map_or(AES_256_GCM_KEY_LENGTH, |v| v);
                    let mut symmetric_key = Zeroizing::from(vec![0; key_len]);
                    rand_bytes(&mut symmetric_key)?;
                    let object =
                        create_symmetric_key_kmip_object(&symmetric_key, *cryptographic_algorithm)?;

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
    ///  - "_sk"
    ///  - the KMIP cryptographic algorithm in lower case prepended with "_"
    ///
    /// Only Covercrypt user decryption keys can be created using this function
    pub(crate) async fn create_private_key_and_tags(
        &self,
        create_request: &Create,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<(Option<String>, Object, HashSet<String>)> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;

        // check that the cryptographic algorithm is specified
        let cryptographic_algorithm = &attributes.cryptographic_algorithm.ok_or_else(|| {
            KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for private key creation".to_owned(),
            )
        })?;

        // recover tags
        let mut tags = attributes.get_tags();
        Attributes::check_user_tags(&tags)?;
        //update the tags
        tags.insert("_uk".to_owned());

        // recover uid
        let uid = attributes
            .unique_identifier
            .as_ref()
            .map(std::string::ToString::to_string);

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
                Ok((uid, object, tags))
            }
            other => Err(KmsError::NotSupported(format!(
                "the creation of a private key for algorithm: {other:?} is not supported"
            ))),
        }
    }
}

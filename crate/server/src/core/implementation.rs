//TODO Split this file in multiple implementations under their operations names

use std::convert::TryFrom;

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Create, CreateKeyPair},
    kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
};
use cosmian_kms_utils::{
    crypto::{
        abe::ciphers::{AbeHybridCipher, AbeHybridDecipher},
        aes::{create_aes_symmetric_key, AesGcmCipher},
        cover_crypt::ciphers::{CoverCryptHybridCipher, CoverCryptHybridDecipher},
        curve_25519::operation::generate_key_pair,
        fpe::{operation::FpeCipher, symmetric_key::create_fpe_ff1_symmetric_key},
        mcfe::operation::{
            mcfe_master_key_from_key_block, mcfe_setup_from_attributes,
            secret_data_from_lwe_functional_key, secret_key_from_lwe_master_secret_key,
            secret_key_from_lwe_secret_key, setup_from_secret_key, DMcfeDeCipher, DMcfeEnCipher,
            FunctionalKeyCreateRequest,
        },
        tfhe::{self, TFHEKeyCreateRequest},
    },
    types::{ExtraDatabaseParams, ObjectOperationTypes},
    DeCipher, EnCipher, KeyPair,
};
use cosmian_mcfe::lwe;
use torus_fhe::{trlwe::TRLWEKey, HasGenerator};
use tracing::trace;

use super::KMS;
use crate::{
    config::{db_params, DbParams},
    database::{
        cached_sqlcipher::CachedSqlCipher, mysql::Sql, pgsql::Pgsql, sqlite::SqlitePool, Database,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

impl KMS {
    pub async fn instantiate() -> KResult<KMS> {
        let db: Box<dyn Database + Sync + Send> = match db_params() {
            DbParams::Sqlite(db_path, encrypted) => {
                if encrypted {
                    Box::new(CachedSqlCipher::instantiate(&db_path).await?)
                } else {
                    Box::new(SqlitePool::instantiate(&db_path.join("kms.db")).await?)
                }
            }
            DbParams::Postgres(url) => Box::new(Pgsql::instantiate(&url).await?),
            DbParams::Mysql(url, user_cert) => Box::new(Sql::instantiate(&url, user_cert).await?),
        };

        Ok(KMS { db })
    }

    pub async fn get_encipher(
        &self,
        key_uid: &str,
        owner: &str,
        params: &Option<ExtraDatabaseParams>,
    ) -> KResult<Box<dyn EnCipher>> {
        let (object, _state) = self
            .db
            .retrieve(key_uid, owner, ObjectOperationTypes::Encrypt, params)
            .await?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("Object with uid: {key_uid} not found"))
            })?;

        match &object {
            Object::SymmetricKey { key_block } => {
                match &key_block.key_format_type {
                    KeyFormatType::TransparentSymmetricKey => {
                        match &key_block.cryptographic_algorithm {
                            CryptographicAlgorithm::FPEFF1 => {
                                Ok(Box::new(FpeCipher::instantiate(key_uid, &object)?)
                                    as Box<dyn EnCipher>)
                            }
                            CryptographicAlgorithm::AES => {
                                Ok(Box::new(AesGcmCipher::instantiate(key_uid, &object)?)
                                    as Box<dyn EnCipher>)
                            }
                            other => kms_bail!(KmsError::NotSupported(format!(
                                "This server does not yet support symetric encryption with \
                                 algorithm: {other:?}"
                            ))),
                        }
                    }
                    KeyFormatType::McfeSecretKey => {
                        // we need to recover the lwe::Setup parameter
                        Ok(Box::new(DMcfeEnCipher::instantiate(key_uid, &object)?)
                            as Box<dyn EnCipher>)
                    }
                    KeyFormatType::TFHE => {
                        Ok(Box::new(tfhe::Cipher::instantiate(key_uid, &object)?))
                    }
                    other => kms_bail!(KmsError::NotSupported(format!(
                        "This server does not yet support encryption with keys of format: {other}"
                    ))),
                }
            }
            Object::PublicKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::AbeMasterPublicKey => {
                    Ok(Box::new(AbeHybridCipher::instantiate(key_uid, &object)?)
                        as Box<dyn EnCipher>)
                }
                KeyFormatType::CoverCryptPublicKey => Ok(Box::new(
                    CoverCryptHybridCipher::instantiate(key_uid, &object)?,
                ) as Box<dyn EnCipher>),
                other => kms_bail!(KmsError::NotSupported(format!(
                    "This server does not yet support encryption with public keys of format: \
                     {other}"
                ))),
            },
            other => kms_bail!(KmsError::NotSupported(format!(
                "This server does not support encryption with keys of type: {}",
                other.object_type()
            ))),
        }
    }

    pub(crate) async fn get_decipher(
        &self,
        object_uid: &str,
        owner: &str,
        params: &Option<ExtraDatabaseParams>,
    ) -> KResult<Box<dyn DeCipher>> {
        let (object, _state) = self
            .db
            .retrieve(object_uid, owner, ObjectOperationTypes::Decrypt, params)
            .await?
            .ok_or_else(|| {
                KmsError::ItemNotFound(format!("Object with uid: {object_uid} not found"))
            })?;

        match &object {
            Object::SecretData {
                key_block,
                secret_data_type: _,
            } => {
                match &key_block.key_format_type {
                    KeyFormatType::McfeFunctionalKey => {
                        // we need to recover the lwe::Setup parameter
                        Ok(Box::new(DMcfeDeCipher::instantiate(object_uid, &object)?))
                    }
                    other => kms_bail!(KmsError::NotSupported(format!(
                        "This server does not yet support decryption with keys of format: {other}"
                    ))),
                }
            }
            Object::PrivateKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::AbeUserDecryptionKey => Ok(Box::new(
                    AbeHybridDecipher::instantiate(object_uid, &object)?,
                )),
                KeyFormatType::CoverCryptSecretKey => Ok(Box::new(
                    CoverCryptHybridDecipher::instantiate(object_uid, &object)?,
                )),
                other => kms_bail!(KmsError::NotSupported(format!(
                    "This server does not yet support decryption with keys of format: {other}"
                ))),
            },
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    match &key_block.cryptographic_algorithm {
                        CryptographicAlgorithm::FPEFF1 => {
                            Ok(Box::new(FpeCipher::instantiate(object_uid, &object)?))
                        }
                        CryptographicAlgorithm::AES => {
                            Ok(Box::new(AesGcmCipher::instantiate(object_uid, &object)?))
                        }
                        other => kms_bail!(KmsError::NotSupported(format!(
                            "This server does not yet support symmetric decryption with \
                             algorithm: {other:?}"
                        ))),
                    }
                }
                KeyFormatType::TFHE => {
                    Ok(Box::new(tfhe::Cipher::instantiate(object_uid, &object)?))
                }
                other => kms_bail!(KmsError::NotSupported(format!(
                    "This server does not yet support decryption with keys of format: {other}"
                ))),
            },
            other => kms_bail!(KmsError::NotSupported(format!(
                "This server does not support decryption with keys of type: {}",
                other.object_type()
            ))),
        }
    }

    pub(crate) async fn create_symmetric_key(
        &self,
        request: &Create,
        _owner: &str,
    ) -> KResult<Object> {
        let attributes = &request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::FPEFF1) => {
                create_fpe_ff1_symmetric_key(attributes.cryptographic_length.map(|v| v as usize))
                    .map_err(Into::into)
            }
            Some(CryptographicAlgorithm::AES) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a symmetric key, the format type is not specified"
                        .to_string()
                )),
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    create_aes_symmetric_key(attributes.cryptographic_length.map(|v| v as usize))
                        .map_err(Into::into)
                }
                Some(other) => kms_bail!(KmsError::InvalidRequest(format!(
                    "Unable to generate a symmetric key for format: {other}"
                ))),
            },
            Some(CryptographicAlgorithm::LWE) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a secret key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::McfeSecretKey) => {
                    let setup = mcfe_setup_from_attributes(attributes)?;
                    let sk = lwe::SecretKey::try_from(&setup)?;
                    secret_key_from_lwe_secret_key(&setup, &sk).map_err(Into::into)
                }
                Some(KeyFormatType::McfeFksSecretKey) => kms_bail!(KmsError::NotSupported(
                    "Generation of Functional Key Shares Secret Keys is not yet supported"
                        .to_string()
                )),
                Some(KeyFormatType::McfeMasterSecretKey) => {
                    let setup = mcfe_setup_from_attributes(attributes)?;
                    let msk = lwe::MasterSecretKey::try_from(&setup)?;
                    secret_key_from_lwe_master_secret_key(&setup, msk.as_slice())
                        .map_err(Into::into)
                }
                Some(other) => kms_bail!(KmsError::InvalidRequest(format!(
                    "Unable to generate an LWE secret key for format: {other}"
                ))),
            },
            Some(CryptographicAlgorithm::TFHE) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a secret key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::TFHE) => {
                    let request = TFHEKeyCreateRequest::try_from(attributes)?;
                    let key = match request.pregenerated_key {
                        None => {
                            //*** Security Parameter
                            //
                            // Vector size
                            use torus_fhe::typenum::{U1023, U512};
                            type N = U512;
                            const N: usize = 512;
                            //*** LUT Parameters
                            type D = U1023;
                            const D: usize = 1023;
                            match (request.vector_size, request.d) {
                                (N, D) => TRLWEKey::<N, D>::gen(),
                                _ => {
                                    kms_bail!(KmsError::InvalidRequest(format!(
                                        "no rule to process vector_size {}, d {}",
                                        request.vector_size, request.d
                                    )))
                                }
                            }
                        }
                        Some(key) => key,
                    };
                    let key_bytes = serde_json::to_vec(&key)?;
                    Ok(Object::SymmetricKey {
                        key_block: tfhe::array_to_key_block(
                            &key_bytes,
                            attributes.clone(),
                            KeyFormatType::TFHE,
                        ),
                    })
                }
                Some(other) => kms_bail!(KmsError::InvalidRequest(format!(
                    "Unable to generate an TFHE secret key for format: {other}"
                ))),
            },
            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The creation of secret key for algorithm: {other:?} is not supported"
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for secret key creation".to_string()
            )),
        }
    }

    pub(crate) async fn create_secret_data(
        &self,
        request: &Create,
        owner: &str,
        params: &Option<ExtraDatabaseParams>,
    ) -> KResult<Object> {
        let attributes = &request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::LWE) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a secret key, the format type is not specified".to_string()
                )),

                Some(KeyFormatType::McfeFunctionalKey) => {
                    let request = FunctionalKeyCreateRequest::try_from(attributes)?;
                    let (object, _state) = self
                        .db
                        .retrieve(
                            &request.master_secret_key_uid,
                            owner,
                            ObjectOperationTypes::Create,
                            params,
                        )
                        .await?
                        .ok_or_else(|| {
                            KmsError::ItemNotFound(format!(
                                "Object with uid: {} and owner: {owner} not found",
                                request.master_secret_key_uid
                            ))
                        })?;
                    if let Object::SymmetricKey { key_block } = &object {
                        if key_block.key_format_type == KeyFormatType::McfeMasterSecretKey {
                            let msk = mcfe_master_key_from_key_block(key_block)?;
                            let setup =
                                setup_from_secret_key(&request.master_secret_key_uid, key_block)?;
                            let parameters = lwe::Parameters::instantiate(&setup)?;
                            let fk = parameters.functional_key(&msk, &request.vectors)?;
                            secret_data_from_lwe_functional_key(&setup, &fk).map_err(Into::into)
                        } else {
                            kms_bail!(KmsError::InvalidRequest(
                                "Generation of Functional Key failed. The given uid is not that \
                                 of a Master Secret Key"
                                    .to_string()
                            ))
                        }
                    } else {
                        kms_bail!(KmsError::InvalidRequest(
                            "Generation of Functional Key failed. The given uid is not that of a \
                             Master Secret Key"
                                .to_string()
                        ))
                    }
                }
                Some(other) => kms_bail!(KmsError::NotSupported(format!(
                    "Unable to generate an LWE secret key for format: {other:?}"
                ))),
            },

            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The creation of secret data for algorithm: {other:?} is not supported"
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for secret data creation"
                    .to_string()
            )),
        }
    }

    pub(crate) async fn create_private_key(
        &self,
        create_request: &Create,
        owner: &str,
        params: &Option<ExtraDatabaseParams>,
    ) -> KResult<Object> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::ABE) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create an ABE key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::AbeUserDecryptionKey) => {
                    trace!("Creating ABE user decryption key");
                    super::abe::create_user_decryption_key(self, create_request, owner, params)
                        .await
                }
                Some(other) => kms_bail!(KmsError::NotSupported(format!(
                    "Unable to generate an ABE private key for format: {other:?}"
                ))),
            },
            Some(CryptographicAlgorithm::CoverCrypt) => {
                super::cover_crypt::create_user_decryption_key(self, create_request, owner, params)
                    .await
            }
            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The creation of a private key for algorithm: {other:?} is not supported"
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for private key creation"
                    .to_string()
            )),
        }
    }

    pub(crate) async fn create_key_pair_(
        &self,
        request: &CreateKeyPair,
        owner: &str,
        params: &Option<ExtraDatabaseParams>,
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
            Some(CryptographicAlgorithm::EC) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create a EC key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::ECPrivateKey) => {
                    let dp = attributes
                        .cryptographic_domain_parameters
                        .unwrap_or_default();
                    match dp.recommended_curve.unwrap_or_default() {
                        RecommendedCurve::CURVE25519 => generate_key_pair().map_err(Into::into),
                        other => kms_bail!(KmsError::NotSupported(format!(
                            "Generation of Key Pair for curve: {other:?}, is not supported"
                        ))),
                    }
                }
                Some(other) => kms_bail!(KmsError::NotSupported(format!(
                    "Unable to generate an DH keypair for format: {other}"
                ))),
            },
            Some(CryptographicAlgorithm::ABE) => match attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to create an ABE key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::AbeMasterSecretKey) => {
                    cosmian_kms_utils::crypto::abe::master_keys::create_master_keypair(request)
                        .map_err(Into::into)
                }
                Some(KeyFormatType::AbeUserDecryptionKey) => {
                    super::abe::create_user_decryption_key_pair(self, request, owner, params).await
                }
                Some(other) => kms_bail!(KmsError::NotSupported(format!(
                    "Unable to generate an ABE keypair for format: {other:?}"
                ))),
            },
            Some(CryptographicAlgorithm::CoverCrypt) => {
                cosmian_kms_utils::crypto::cover_crypt::master_keys::create_master_keypair(request)
                    .map_err(Into::into)
                // TODO: cannot create a user key pair: does it matter ?
                // super::cover_crypt::create_user_decryption_key_pair(self, request, owner).await
            }
            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The creation of a key pair for algorithm: {other:?} is not supported"
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for key pair creation".to_string()
            )),
        }
    }
}

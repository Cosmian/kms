//TODO Split this file in multiple implementations under their operations names

use std::convert::TryFrom;

use cosmian_kmip::kmip::{
    access::ObjectOperationTypes,
    kmip_key_utils::WrappedSymmetricKey,
    kmip_objects::Object,
    kmip_operations::{Create, CreateKeyPair, ErrorReason, Get, GetResponse},
    kmip_types::{Attributes, CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
};
use cosmian_kms_utils::{
    crypto::{
        abe::{
            attributes::{access_policy_from_attributes, header_uid_from_attributes},
            ciphers::{AbeHybridCipher, AbeHybridDecipher},
            locate::compare_abe_attributes,
            master_keys::create_master_keypair,
            secret_key::wrapped_secret_key,
        },
        aes::{create_aes_symmetric_key, AesGcmCipher},
        curve_25519::{self},
        fpe::FpeCipher,
        mcfe::{
            mcfe_master_key_from_key_block, mcfe_setup_from_attributes,
            secret_data_from_lwe_functional_key, secret_key_from_lwe_master_secret_key,
            secret_key_from_lwe_secret_key, setup_from_secret_key, DMcfeDeCipher, DMcfeEnCipher,
            FunctionalKeyCreateRequest,
        },
        tfhe::{self, TFHEKeyCreateRequest},
    },
    DeCipher, EnCipher, KeyPair,
};
use cosmian_mcfe::lwe;
use torus_fhe::{trlwe::TRLWEKey, HasGenerator};
use tracing::{debug, trace};

use super::KMS;
#[cfg(feature = "pgsql")]
use crate::kmip::kmip_server::pgsql::Pgsql;
use crate::{
    config::{db_params, DbParams},
    error::KmsError,
    kmip::kmip_server::{
        abe::{create_user_decryption_key, create_user_decryption_key_pair},
        database::Database,
        mysql::Sql,
        pgsql::Pgsql,
        server::kmip_server::KmipServer,
        sqlite::SqlitePool,
    },
    kms_error,
    result::{KResult, KResultHelper},
};

impl KMS {
    pub async fn instantiate() -> KResult<KMS> {
        let db: Box<dyn Database + Sync + Send> = match db_params() {
            DbParams::Sqlite(db_path) => Box::new(SqlitePool::instantiate(&db_path).await?),
            DbParams::Postgres(url) => Box::new(Pgsql::instantiate(&url).await?),
            DbParams::Mysql(url) => Box::new(Sql::instantiate(&url).await?),
        };

        Ok(KMS { db })
    }

    pub async fn encipher(&self, key_uid: &str, owner: &str) -> KResult<Box<dyn EnCipher>> {
        let (object, _state) = self
            .db
            .retrieve(key_uid, owner, ObjectOperationTypes::Encrypt)
            .await?
            .with_context(|| format!("Object with uid: {key_uid} not found"))
            .reason(ErrorReason::Item_Not_Found)?;

        match &object {
            Object::SymmetricKey { key_block } => {
                match &key_block.key_format_type {
                    KeyFormatType::AbeSymmetricKey => {
                        Ok(Box::new(AesGcmCipher::instantiate(key_uid, &object)?)
                            as Box<dyn EnCipher>)
                    }
                    KeyFormatType::TransparentSymmetricKey => {
                        Ok(Box::new(FpeCipher::instantiate(key_uid, &object)?)
                            as Box<dyn EnCipher>)
                    }
                    KeyFormatType::McfeSecretKey => {
                        // we need to recover the lwe::Setup parameter
                        Ok(Box::new(DMcfeEnCipher::instantiate(key_uid, &object)?)
                            as Box<dyn EnCipher>)
                    }
                    KeyFormatType::TFHE => {
                        Ok(Box::new(tfhe::Cipher::instantiate(key_uid, &object)?))
                    }
                    other => Err(kms_error!(
                        "This server does not yet support decryption with keys of format: {}",
                        other
                    )
                    .reason(ErrorReason::Operation_Not_Supported)),
                }
            }
            Object::PublicKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::AbeMasterPublicKey => {
                    Ok(Box::new(AbeHybridCipher::instantiate(key_uid, &object)?)
                        as Box<dyn EnCipher>)
                }
                other => Err(kms_error!(
                    "This server does not yet support decryption with public keys of format: {}",
                    other
                )
                .reason(ErrorReason::Operation_Not_Supported)),
            },
            other => Err(kms_error!(
                "This server does not support encryption with keys of type: {}",
                other.object_type()
            )
            .reason(ErrorReason::Operation_Not_Supported)),
        }
    }

    pub(crate) async fn decipher(
        &self,
        object_uid: &str,
        owner: &str,
    ) -> KResult<Box<dyn DeCipher>> {
        let (object, _state) = self
            .db
            .retrieve(object_uid, owner, ObjectOperationTypes::Decrypt)
            .await?
            .with_context(|| format!("Object with uid: {object_uid} not found"))
            .reason(ErrorReason::Item_Not_Found)?;

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
                    other => Err(kms_error!(
                        "This server does not yet support decryption with keys of format: {}",
                        other
                    )
                    .reason(ErrorReason::Operation_Not_Supported)),
                }
            }
            Object::PrivateKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::AbeUserDecryptionKey => Ok(Box::new(
                    AbeHybridDecipher::instantiate(object_uid, &object)?,
                )),
                other => Err(kms_error!(
                    "This server does not yet support decryption with keys of format: {}",
                    other
                )
                .reason(ErrorReason::Operation_Not_Supported)),
            },
            Object::SymmetricKey { key_block } => match &key_block.key_format_type {
                KeyFormatType::AbeSymmetricKey => {
                    Ok(Box::new(AesGcmCipher::instantiate(object_uid, &object)?))
                }
                KeyFormatType::TransparentSymmetricKey => {
                    Ok(Box::new(FpeCipher::instantiate(object_uid, &object)?))
                }
                KeyFormatType::TFHE => {
                    Ok(Box::new(tfhe::Cipher::instantiate(object_uid, &object)?))
                }
                other => Err(kms_error!(
                    "This server does not yet support decryption with keys of format: {}",
                    other
                )
                .reason(ErrorReason::Operation_Not_Supported)),
            },
            other => Err(kms_error!(
                "This server does not support decryption with keys of type: {}",
                other.object_type()
            )
            .reason(ErrorReason::Operation_Not_Supported)),
        }
    }

    pub(crate) async fn create_symmetric_key(
        &self,
        request: &Create,
        owner: &str,
    ) -> KResult<Object> {
        let attributes = &request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::AES) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create a symmetric key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
                Some(KeyFormatType::AbeSymmetricKey) => {
                    debug!("Creating ABE symmetric key: {:?}", attributes);
                    // AB encryption requires master public key.
                    let abe_master_public_key_id = attributes.get_parent_id().context(
                        "the attributes must contain the reference to the ABE master public key \
                         ID when creating a linked symmetric key",
                    )?;

                    let public_key_response = self
                        .get(
                            Get {
                                unique_identifier: Some(abe_master_public_key_id.to_string()),
                                ..Get::default()
                            },
                            owner,
                        )
                        .await?;

                    let access_policy = access_policy_from_attributes(attributes)?;
                    let abe_header_uid = header_uid_from_attributes(attributes)?;

                    wrapped_secret_key(&public_key_response, &access_policy, abe_header_uid)
                        .map_err(Into::into)
                }
                Some(KeyFormatType::TransparentSymmetricKey) => {
                    create_aes_symmetric_key(attributes.cryptographic_length.map(|v| v as usize))
                        .map_err(Into::into)
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an ABE symmetric key for format: {}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(CryptographicAlgorithm::LWE) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create a secret key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
                Some(KeyFormatType::McfeSecretKey) => {
                    let setup = mcfe_setup_from_attributes(attributes)?;
                    let sk = lwe::SecretKey::try_from(&setup)?;
                    secret_key_from_lwe_secret_key(&setup, &sk).map_err(Into::into)
                }
                Some(KeyFormatType::McfeFksSecretKey) => Err(kms_error!(
                    "Generation of Functional Key Shares Secret Keys is not yet supported"
                ))
                .reason(ErrorReason::Feature_Not_Supported),
                Some(KeyFormatType::McfeMasterSecretKey) => {
                    let setup = mcfe_setup_from_attributes(attributes)?;
                    let msk = lwe::MasterSecretKey::try_from(&setup)?;
                    secret_key_from_lwe_master_secret_key(&setup, msk.as_slice())
                        .map_err(Into::into)
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an LWE secret key for format: {}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(CryptographicAlgorithm::TFHE) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create a secret key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
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
                                    return Err(kms_error!(
                                        "cosmian server has no rules to process vector_size \
                                         {request.vector_size}, d {request.d}"
                                    )
                                    .reason(ErrorReason::Invalid_Message))
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
                Some(other) => Err(kms_error!(
                    "Unable to generate an LWE secret key for format: {:?}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(other) => Err(kms_error!(
                "The creation of secret key for algorithm: {:?} is not supported",
                other
            )
            .reason(ErrorReason::Operation_Not_Supported)),
            None => Err(kms_error!(
                "The cryptographic algorithm must be specified for secret key creation"
            ))
            .reason(ErrorReason::Feature_Not_Supported),
        }
    }

    pub(crate) async fn create_secret_data(
        &self,
        request: &Create,
        owner: &str,
    ) -> KResult<Object> {
        let attributes = &request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::LWE) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create a secret key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),

                Some(KeyFormatType::McfeFunctionalKey) => {
                    let request = FunctionalKeyCreateRequest::try_from(attributes)?;
                    let (object, _state) = self
                        .db
                        .retrieve(
                            &request.master_secret_key_uid,
                            owner,
                            ObjectOperationTypes::Create,
                        )
                        .await?
                        .with_context(|| {
                            format!(
                                "Object with uid: {} and owner: {owner} not found",
                                request.master_secret_key_uid
                            )
                        })
                        .reason(ErrorReason::Item_Not_Found)?;
                    if let Object::SymmetricKey { key_block } = &object {
                        if key_block.key_format_type == KeyFormatType::McfeMasterSecretKey {
                            let msk = mcfe_master_key_from_key_block(key_block)?;
                            let setup =
                                setup_from_secret_key(&request.master_secret_key_uid, key_block)?;
                            let parameters = lwe::Parameters::instantiate(&setup)?;
                            let fk = parameters.functional_key(&msk, &request.vectors)?;
                            secret_data_from_lwe_functional_key(&setup, &fk).map_err(Into::into)
                        } else {
                            Err(kms_error!(
                                "Generation of Functional Key failed. The given uid is not that \
                                 of a Master Secret Key"
                            ))
                            .reason(ErrorReason::Invalid_Message)
                        }
                    } else {
                        Err(kms_error!(
                            "Generation of Functional Key failed. The given uid is not that of a \
                             Master Secret Key"
                        ))
                        .reason(ErrorReason::Invalid_Object_Type)
                    }
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an LWE secret key for format: {:?}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },

            Some(other) => Err(kms_error!(
                "The creation of secret data for algorithm: {:?} is not supported",
                other
            )
            .reason(ErrorReason::Operation_Not_Supported)),
            None => Err(kms_error!(
                "The cryptographic algorithm must be specified for secret data creation"
            ))
            .reason(ErrorReason::Feature_Not_Supported),
        }
    }

    pub(crate) async fn create_private_key(
        &self,
        create_request: &Create,
        owner: &str,
    ) -> KResult<Object> {
        trace!("Internal create private key");
        let attributes = &create_request.attributes;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::ABE) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create an ABE key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
                Some(KeyFormatType::AbeUserDecryptionKey) => {
                    trace!("Creating ABE user decryption key");
                    create_user_decryption_key(self, create_request, owner).await
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an ABE private key for format: {:?}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(other) => Err(kms_error!(
                "The creation of a private key for algorithm: {:?} is not supported",
                other
            ))
            .reason(ErrorReason::Operation_Not_Supported),
            None => Err(kms_error!(
                "The cryptographic algorithm must be specified for private key creation"
            ))
            .reason(ErrorReason::Feature_Not_Supported),
        }
    }

    pub(crate) async fn create_key_pair_(
        &self,
        request: &CreateKeyPair,
        owner: &str,
    ) -> KResult<KeyPair> {
        trace!("Internal create key pair");
        let attributes = request
            .common_attributes
            .as_ref()
            .or(request.private_key_attributes.as_ref())
            .or(request.public_key_attributes.as_ref())
            .ok_or_else(|| {
                KmsError::ServerError(
                    "Attributes must be provided in a CreateKeyPair request".to_owned(),
                )
            })?;
        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::EC) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create a EC key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
                Some(KeyFormatType::ECPrivateKey) => {
                    let dp = attributes
                        .cryptographic_domain_parameters
                        .unwrap_or_default();
                    match dp.recommended_curve.unwrap_or_default() {
                        RecommendedCurve::CURVE25519 => {
                            curve_25519::generate_key_pair().map_err(Into::into)
                        }
                        other => Err(kms_error!(
                            "Generation of Key Pair for curve: {:?}, is not supported",
                            other
                        ))
                        .reason(ErrorReason::Operation_Not_Supported),
                    }
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an DH keypair for format: {}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(CryptographicAlgorithm::ABE) => match attributes.key_format_type {
                None => Err(kms_error!(
                    "Unable to create an ABE key, the format type is not specified"
                ))
                .reason(ErrorReason::Invalid_Message),
                Some(KeyFormatType::AbeMasterSecretKey) => {
                    create_master_keypair(request).map_err(Into::into)
                }
                Some(KeyFormatType::AbeUserDecryptionKey) => {
                    create_user_decryption_key_pair(self, request, owner).await
                }
                Some(other) => Err(kms_error!(
                    "Unable to generate an ABE keypair for format: {:?}",
                    other
                ))
                .reason(ErrorReason::Invalid_Message),
            },
            Some(other) => Err(kms_error!(
                "The creation of a key pair for algorithm: {:?} is not supported",
                other
            ))
            .reason(ErrorReason::Operation_Not_Supported),
            None => Err(kms_error!(
                "The cryptographic algorithm must be specified for key pair creation"
            ))
            .reason(ErrorReason::Feature_Not_Supported),
        }
    }
}

pub(crate) fn contains_attributes(
    researched_attributes: &Attributes,
    kmip_response: &GetResponse,
) -> KResult<bool> {
    let key_block = kmip_response.object.key_block()?;
    let object_attributes = match &key_block.key_wrapping_data {
        Some(_) => {
            let wrapped_symmetric_key =
                WrappedSymmetricKey::try_from(&key_block.key_value.raw_bytes()?)?;
            wrapped_symmetric_key.attributes()
        }
        None => key_block.key_value.attributes()?.clone(),
    };

    match &researched_attributes.cryptographic_algorithm {
        Some(CryptographicAlgorithm::ABE) => match researched_attributes.key_format_type {
            None => Err(kms_error!(
                "Unable to locate an ABE key, the format type is not specified"
            ))
            .reason(ErrorReason::Invalid_Message),
            Some(KeyFormatType::AbeUserDecryptionKey) => {
                compare_abe_attributes(&object_attributes, researched_attributes)
                    .map_err(Into::into)
            }
            Some(other) => Err(kms_error!(
                "Unable to locate an ABE keypair for format: {:?}",
                other
            ))
            .reason(ErrorReason::Invalid_Message),
        },
        Some(other) => Err(kms_error!(
            "The locate of an object for algorithm: {:?} is not yet supported",
            other
        ))
        .reason(ErrorReason::Operation_Not_Supported),
        None => Err(kms_error!(
            "The cryptographic algorithm must be specified for object location"
        ))
        .reason(ErrorReason::Feature_Not_Supported),
    }
}

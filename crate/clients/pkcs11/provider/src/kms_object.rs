use std::vec;

use ckms::{
    config::ClientConfig,
    reexport::cosmian_kms_cli::reexport::{
        cosmian_kmip::{
            self,
            kmip_0::kmip_types::{
                BlockCipherMode, CryptographicUsageMask, PaddingMethod, RevocationReason,
                RevocationReasonCode, SecretDataType,
            },
            kmip_2_1::{
                kmip_attributes::Attributes,
                kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
                kmip_objects::{Object, ObjectType, SecretData, SymmetricKey},
                kmip_operations::{
                    Decrypt, Destroy, Encrypt, GetAttributes, Import, Locate, Revoke,
                },
                kmip_types::{
                    CryptographicAlgorithm, CryptographicParameters, KeyFormatType,
                    RecommendedCurve, UniqueIdentifier,
                },
            },
        },
        cosmian_kms_client::{ExportObjectParams, KmsClient, batch_export_objects, export_object},
        cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng,
            reexport::rand_core::{RngCore, SeedableRng},
        },
    },
};
use cosmian_logger::{debug, error, trace};
use cosmian_pkcs11_module::traits::{
    DecryptContext, EncryptContext, EncryptionAlgorithm, KeyAlgorithm,
};
use zeroize::Zeroizing;

use crate::error::{Pkcs11Error, result::Pkcs11Result};

/// A wrapper around a KMS KMIP object.
#[allow(dead_code)]
pub(crate) struct KmsObject {
    pub remote_id: String,
    pub object: Object,
    pub attributes: Attributes,
    pub other_tags: Vec<String>,
}

pub(crate) fn get_kms_client() -> Pkcs11Result<KmsClient> {
    let config = ClientConfig::load(None)?;
    Ok(KmsClient::new_with_config(config.kms_config)?)
}

pub(crate) fn locate_kms_objects(
    kms_rest_client: &KmsClient,
    tags: &[String],
) -> Pkcs11Result<Vec<String>> {
    tokio::runtime::Runtime::new()?.block_on(locate_kms_objects_async(kms_rest_client, tags))
}

pub(crate) async fn locate_kms_objects_async(
    kms_rest_client: &KmsClient,
    tags: &[String],
) -> Pkcs11Result<Vec<String>> {
    locate_objects(kms_rest_client, tags).await
}

pub(crate) fn get_kms_objects(
    kms_rest_client: &KmsClient,
    tags: &[String],
    key_format_type: Option<KeyFormatType>,
) -> Pkcs11Result<Vec<KmsObject>> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_objects_async(
        kms_rest_client,
        tags,
        key_format_type,
    ))
}

pub(crate) async fn get_kms_objects_async(
    kms_rest_client: &KmsClient,
    tags: &[String],
    key_format_type: Option<KeyFormatType>,
) -> Pkcs11Result<Vec<KmsObject>> {
    let key_ids = locate_objects(kms_rest_client, tags).await?;
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type,
        ..Default::default()
    };
    if key_ids.is_empty() {
        trace!(
            "get_kms_objects_async: no objects found for tags: {:?}",
            tags
        );
        return Ok(vec![]);
    }

    let responses = batch_export_objects(kms_rest_client, key_ids, export_object_params).await?;
    trace!("Found {} objects", responses.len());

    let mut results = vec![];
    for (id, object, attributes) in responses {
        let other_tags = attributes
            .get_tags()
            .into_iter()
            .filter(|t| !t.is_empty() && !tags.contains(t) && !t.starts_with('_'))
            .collect::<Vec<String>>();
        results.push(KmsObject {
            remote_id: id.to_string(),
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

pub(crate) fn get_kms_object(
    kms_client: &KmsClient,
    object_id_or_tags: &str,
    key_format_type: KeyFormatType,
) -> Pkcs11Result<KmsObject> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_object_async(
        kms_client,
        object_id_or_tags,
        key_format_type,
    ))
}

pub(crate) async fn get_kms_object_async(
    kms_client: &KmsClient,
    object_id_or_tags: &str,
    key_format_type: KeyFormatType,
) -> Pkcs11Result<KmsObject> {
    let (id, object, _) = export_object(
        kms_client,
        object_id_or_tags,
        ExportObjectParams {
            unwrap: true,
            key_format_type: Some(key_format_type),
            ..Default::default()
        },
    )
    .await?;

    // Get request does not return attributes, try to get them form the object
    let attributes = object.attributes().cloned().unwrap_or_default();
    let other_tags = attributes
        .get_tags()
        .into_iter()
        .filter(|t| !t.is_empty() && !t.starts_with('_'))
        .collect::<Vec<String>>();
    Ok(KmsObject {
        remote_id: id.to_string(),
        object,
        attributes,
        other_tags,
    })
}

async fn locate_objects(kms_rest_client: &KmsClient, tags: &[String]) -> Pkcs11Result<Vec<String>> {
    let mut attributes = Attributes::default();
    attributes.set_tags(tags)?;

    let locate = Locate {
        attributes,
        ..Default::default()
    };
    let response = kms_rest_client.locate(locate).await?;
    debug!("Locate response: ids: {:?}", response.unique_identifier);
    let uniques_identifiers = response
        .unique_identifier
        .unwrap_or_default()
        .iter()
        .map(std::string::ToString::to_string)
        .filter(|id| !id.is_empty())
        .collect();
    debug!("Located objects: tags: {tags:?} => {uniques_identifiers:?}");
    Ok(uniques_identifiers)
}

pub(crate) fn kms_import_symmetric_key(
    kms_rest_client: &KmsClient,
    algorithm: KeyAlgorithm,
    key_length: usize,
    sensitive: bool,
    label: Option<&str>,
) -> Pkcs11Result<KmsObject> {
    tokio::runtime::Runtime::new()?.block_on(kms_import_symmetric_key_async(
        kms_rest_client,
        algorithm,
        key_length,
        sensitive,
        label,
    ))
}

/// Creates a new KMS key.
/// At first, the key is locally created and then imported to the KMS. There are 2 reasons why:
/// - 1/ a key with `sensitive` flag cannot be extracted and then cannot be exported afterwards
/// - 2/ is that the content of the key must be kept in cache to be reused later.
pub(crate) async fn kms_import_symmetric_key_async(
    kms_rest_client: &KmsClient,
    algorithm: KeyAlgorithm,
    key_length: usize,
    sensitive: bool,
    label: Option<&str>,
) -> Pkcs11Result<KmsObject> {
    let cryptographic_algorithm = if algorithm == KeyAlgorithm::Aes256 {
        CryptographicAlgorithm::AES
    } else {
        error!("Unsupported key algorithm: {:?}", algorithm);
        return Err(Pkcs11Error::Default(format!(
            "unsupported key algorithm: {algorithm:?}"
        )));
    };
    let tags = label.map(|l| vec![l.to_owned()]).unwrap_or_default();

    let mut rng = CsRng::from_entropy();
    let mut key = vec![0_u8; key_length];
    rng.fill_bytes(&mut key);

    let cryptographic_length = Some(i32::try_from(key_length * 8)?);

    let mut attributes = Attributes {
        cryptographic_algorithm: Some(cryptographic_algorithm),
        cryptographic_length,
        cryptographic_parameters: None,
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        unique_identifier: label.map(|l| UniqueIdentifier::TextString(l.to_owned())),
        sensitive: if sensitive { Some(true) } else { None },
        ..Attributes::default()
    };
    attributes.set_tags(tags.clone())?;
    let object = Object::SymmetricKey(SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(cryptographic_algorithm),
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::TransparentSymmetricKey {
                    key: Zeroizing::new(key),
                },
                attributes: Some(attributes.clone()),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    });
    let response = kms_rest_client
        .import(Import {
            unique_identifier: label
                .map(|l| UniqueIdentifier::TextString(l.to_owned()))
                .unwrap_or_default(),
            object_type: cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: attributes.clone(),
            object: object.clone(),
        })
        .await?;

    let res = KmsObject {
        remote_id: response.unique_identifier.to_string(),
        object,
        attributes,
        other_tags: tags,
    };

    Ok(res)
}

pub(crate) fn kms_import_object(
    kms_rest_client: &KmsClient,
    label: &str,
    data: &[u8],
) -> Pkcs11Result<KmsObject> {
    tokio::runtime::Runtime::new()?.block_on(kms_import_object_async(kms_rest_client, label, data))
}

pub(crate) async fn kms_import_object_async(
    kms_rest_client: &KmsClient,
    label: &str,
    data: &[u8],
) -> Pkcs11Result<KmsObject> {
    debug!(
        "kms_import_object_async: label: {label}, data (length): {}",
        data.len()
    );
    let tags = vec![label.to_owned()];
    let unique_identifier = UniqueIdentifier::TextString(label.to_owned());

    let secret_data_value = data.to_vec();

    let cryptographic_length = Some(i32::try_from(secret_data_value.len() * 8)?);

    let mut attributes = Attributes::default();
    attributes.set_tags(tags.clone())?;

    let object = Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Password,
        key_block: KeyBlock {
            cryptographic_length,
            key_format_type: KeyFormatType::Raw,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(secret_data_value)),
                attributes: Some(attributes.clone()),
            }),
            key_compression_type: None,
            cryptographic_algorithm: None,
            key_wrapping_data: None,
        },
    });

    let response = kms_rest_client
        .import(Import {
            unique_identifier,
            object_type: ObjectType::SecretData,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: attributes.clone(),
            object: object.clone(),
        })
        .await?;

    let res = KmsObject {
        remote_id: response.unique_identifier.to_string(),
        object,
        attributes,
        other_tags: tags,
    };

    Ok(res)
}

pub(crate) fn kms_revoke_object(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    tokio::runtime::Runtime::new()?
        .block_on(kms_revoke_object_async(kms_rest_client, unique_identifier))
}

pub(crate) async fn kms_revoke_object_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    kms_rest_client
        .revoke(Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        })
        .await?;

    Ok(())
}

pub(crate) fn kms_destroy_object(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    tokio::runtime::Runtime::new()?
        .block_on(kms_destroy_object_async(kms_rest_client, unique_identifier))
}

pub(crate) async fn kms_destroy_object_async(
    kms_rest_client: &KmsClient,
    unique_identifier: &str,
) -> Pkcs11Result<()> {
    kms_rest_client
        .destroy(Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(unique_identifier.to_owned())),
            remove: false,
            cascade: true,
        })
        .await?;

    Ok(())
}

pub(crate) fn kms_encrypt(
    kms_rest_client: &KmsClient,
    encrypt_ctx: &EncryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Vec<u8>> {
    tokio::runtime::Runtime::new()?.block_on(kms_encrypt_async(kms_rest_client, encrypt_ctx, data))
}

pub(crate) async fn kms_encrypt_async(
    kms_rest_client: &KmsClient,
    encrypt_ctx: &EncryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Vec<u8>> {
    let cryptographic_parameters = match encrypt_ctx.algorithm {
        EncryptionAlgorithm::AesCbcPad => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::PKCS5),
            ..Default::default()
        },
        EncryptionAlgorithm::AesCbc => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::None),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaPkcs1v15 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..Default::default()
        },
    };
    let encryption_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            encrypt_ctx.remote_object_id.clone(),
        )),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(Zeroizing::new(data)),
        i_v_counter_nonce: encrypt_ctx.iv.clone(),
        ..Default::default()
    };
    let response = kms_rest_client.encrypt(encryption_request).await?;
    let ciphertext = response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Encryption response does not contain data".to_owned())
    })?;

    debug!(
        "kms_encrypt_async: ciphertext: {}",
        hex::encode(ciphertext.clone())
    );
    Ok(ciphertext)
}

pub(crate) fn kms_decrypt(
    kms_rest_client: &KmsClient,
    decrypt_ctx: &DecryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Zeroizing<Vec<u8>>> {
    tokio::runtime::Runtime::new()?.block_on(kms_decrypt_async(kms_rest_client, decrypt_ctx, data))
}

pub(crate) async fn kms_decrypt_async(
    kms_rest_client: &KmsClient,
    decrypt_ctx: &DecryptContext,
    data: Vec<u8>,
) -> Pkcs11Result<Zeroizing<Vec<u8>>> {
    let cryptographic_parameters = match decrypt_ctx.algorithm {
        EncryptionAlgorithm::AesCbcPad => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::PKCS5),
            ..Default::default()
        },
        EncryptionAlgorithm::AesCbc => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::CBC),
            padding_method: Some(PaddingMethod::None),
            ..Default::default()
        },
        EncryptionAlgorithm::RsaPkcs1v15 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..Default::default()
        },
    };
    let decryption_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(
            decrypt_ctx.remote_object_id.clone(),
        )),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(data),
        i_v_counter_nonce: decrypt_ctx.iv.clone(),
        ..Default::default()
    };
    let response = kms_rest_client.decrypt(decryption_request).await?;
    response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Decryption response does not contain data".to_owned())
    })
}

pub(crate) fn get_kms_object_attributes(
    kms_client: &KmsClient,
    object_id: &str,
) -> Pkcs11Result<Attributes> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_object_attributes_async(kms_client, object_id))
}

pub(crate) async fn get_kms_object_attributes_async(
    kms_client: &KmsClient,
    object_id: &str,
) -> Pkcs11Result<Attributes> {
    let response = kms_client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(object_id.to_owned())),
            attribute_reference: None,
        })
        .await?;
    Ok(response.attributes)
}

pub(crate) fn key_algorithm_from_attributes(attributes: &Attributes) -> Pkcs11Result<KeyAlgorithm> {
    let algorithm = match attributes.cryptographic_algorithm.ok_or_else(|| {
        Pkcs11Error::Default("missing cryptographic algorithm in attributes".to_owned())
    })? {
        CryptographicAlgorithm::AES => KeyAlgorithm::Aes256,
        CryptographicAlgorithm::RSA => KeyAlgorithm::Rsa,
        CryptographicAlgorithm::ECDH | CryptographicAlgorithm::EC => {
            let curve = attributes
                .cryptographic_domain_parameters
                .ok_or_else(|| {
                    Pkcs11Error::Default(
                        "missing cryptographic domain parameters in attributes".to_owned(),
                    )
                })?
                .recommended_curve
                .ok_or_else(|| {
                    Pkcs11Error::Default("missing recommended curve in attributes".to_owned())
                })?;
            match curve {
                RecommendedCurve::P256 => KeyAlgorithm::EccP256,
                RecommendedCurve::P384 => KeyAlgorithm::EccP384,
                RecommendedCurve::P521 => KeyAlgorithm::EccP521,
                RecommendedCurve::CURVE448 => KeyAlgorithm::X448,
                RecommendedCurve::CURVEED448 => KeyAlgorithm::Ed448,
                RecommendedCurve::CURVE25519 => KeyAlgorithm::X25519,
                RecommendedCurve::CURVEED25519 => KeyAlgorithm::Ed25519,
                RecommendedCurve::SECP224K1 => KeyAlgorithm::Secp224k1,
                RecommendedCurve::SECP256K1 => KeyAlgorithm::Secp256k1,
                _ => {
                    return Err(Pkcs11Error::Default(format!(
                        "unsupported curve for EC key: {curve}"
                    )));
                }
            }
        }
        x => {
            error!("Unsupported cryptographic algorithm: {:?}", x);
            return Err(Pkcs11Error::Default(format!(
                "unsupported cryptographic algorithm: {x:?}"
            )));
        }
    };
    Ok(algorithm)
}

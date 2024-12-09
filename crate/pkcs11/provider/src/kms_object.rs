use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, GetAttributes, Locate},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, KeyFormatType, PaddingMethod,
        RecommendedCurve, UniqueIdentifier,
    },
};
use cosmian_kms_client::{
    batch_export_objects, export_object, ExportObjectParams, KmsClient, KmsClientConfig,
};
use cosmian_pkcs11_module::traits::{EncryptionAlgorithm, KeyAlgorithm};
use tracing::{debug, error, trace};
use zeroize::Zeroizing;

use crate::error::Pkcs11Error;

/// A wrapper around a KMS KMIP object.
#[allow(dead_code)]
pub(crate) struct KmsObject {
    pub remote_id: String,
    pub object: Object,
    pub attributes: Attributes,
    pub other_tags: Vec<String>,
}

pub(crate) fn get_kms_client() -> Result<KmsClient, Pkcs11Error> {
    let conf_path = KmsClientConfig::location(None)?;
    let conf = KmsClientConfig::load(&conf_path)?;
    let kms_rest_client = KmsClient::new(conf)?;
    Ok(kms_rest_client)
}

pub(crate) fn locate_kms_objects(
    kms_rest_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(locate_kms_objects_async(kms_rest_client, tags))
}

pub(crate) async fn locate_kms_objects_async(
    kms_rest_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    locate_objects(kms_rest_client, tags).await
}

pub(crate) fn get_kms_objects(
    kms_rest_client: &KmsClient,
    tags: &[String],
    key_format_type: KeyFormatType,
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_objects_async(
        kms_rest_client,
        tags,
        key_format_type,
    ))
}

pub(crate) async fn get_kms_objects_async(
    kms_rest_client: &KmsClient,
    tags: &[String],
    key_format_type: KeyFormatType,
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    let key_ids = locate_objects(kms_rest_client, tags).await?;
    let export_object_params = ExportObjectParams {
        unwrap: true,
        key_format_type: Some(key_format_type),
        ..Default::default()
    };
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
) -> Result<KmsObject, Pkcs11Error> {
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
) -> Result<KmsObject, Pkcs11Error> {
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

async fn locate_objects(
    kms_rest_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    let mut attributes = Attributes::default();
    attributes.set_tags(tags)?;

    let locate = Locate {
        attributes,
        ..Default::default()
    };
    let response = kms_rest_client.locate(locate).await?;
    let uniques_identifiers = response
        .unique_identifiers
        .unwrap_or_default()
        .iter()
        .map(std::string::ToString::to_string)
        .filter(|id| !id.is_empty())
        .collect();
    debug!(
        "Located objects: tags: {:?} => {:?}",
        tags, uniques_identifiers
    );
    Ok(uniques_identifiers)
}

pub(crate) fn kms_decrypt(
    kms_rest_client: &KmsClient,
    key_id: String,
    encryption_algorithm: EncryptionAlgorithm,
    data: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(kms_decrypt_async(
        kms_rest_client,
        key_id,
        encryption_algorithm,
        data,
    ))
}

pub(crate) async fn kms_decrypt_async(
    kms_rest_client: &KmsClient,
    key_id: String,
    encryption_algorithm: EncryptionAlgorithm,
    data: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, Pkcs11Error> {
    let cryptographic_parameters = match encryption_algorithm {
        EncryptionAlgorithm::RsaPkcs1v15 => CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            ..Default::default()
        },
    };
    let decryption_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_id)),
        cryptographic_parameters: Some(cryptographic_parameters),
        data: Some(data),
        ..Default::default()
    };
    let response = kms_rest_client.decrypt(decryption_request).await?;
    response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Decryption response does not contain data".to_string())
    })
}

pub(crate) fn get_kms_object_attributes(
    kms_client: &KmsClient,
    object_id: &str,
) -> Result<Attributes, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_object_attributes_async(kms_client, object_id))
}

pub(crate) async fn get_kms_object_attributes_async(
    kms_client: &KmsClient,
    object_id: &str,
) -> Result<Attributes, Pkcs11Error> {
    let response = kms_client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(object_id.to_string())),
            attribute_references: None,
        })
        .await?;
    Ok(response.attributes)
}

pub(crate) fn key_algorithm_from_attributes(
    attributes: &Attributes,
) -> Result<KeyAlgorithm, Pkcs11Error> {
    let algorithm = match attributes.cryptographic_algorithm.ok_or_else(|| {
        Pkcs11Error::Default("missing cryptographic algorithm in attributes".to_string())
    })? {
        CryptographicAlgorithm::RSA => KeyAlgorithm::Rsa,
        CryptographicAlgorithm::ECDH | CryptographicAlgorithm::EC => {
            let curve = attributes
                .cryptographic_domain_parameters
                .ok_or_else(|| {
                    Pkcs11Error::Default(
                        "missing cryptographic domain parameters in attributes".to_string(),
                    )
                })?
                .recommended_curve
                .ok_or_else(|| {
                    Pkcs11Error::Default("missing recommended curve in attributes".to_string())
                })?;
            match curve {
                RecommendedCurve::P256 => KeyAlgorithm::EccP256,
                RecommendedCurve::P384 => KeyAlgorithm::EccP384,
                RecommendedCurve::P521 => KeyAlgorithm::EccP521,
                RecommendedCurve::CURVE448 => KeyAlgorithm::X448,
                RecommendedCurve::CURVEED448 => KeyAlgorithm::Ed448,
                RecommendedCurve::CURVE25519 => KeyAlgorithm::X25519,
                RecommendedCurve::CURVEED25519 => KeyAlgorithm::Ed25519,
                _ => {
                    error!("Unsupported curve for EC key");
                    return Err(Pkcs11Error::Default(
                        "unsupported curve for EC key".to_string(),
                    ));
                }
            }
        }
        x => {
            error!("Unsupported cryptographic algorithm: {:?}", x);
            return Err(Pkcs11Error::Default(format!(
                "unsupported cryptographic algorithm: {:?}",
                x
            )));
        }
    };
    Ok(algorithm)
}

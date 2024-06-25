use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, Get, Locate},
    kmip_types::{
        Attributes, CryptographicAlgorithm, CryptographicParameters, KeyFormatType, PaddingMethod,
        UniqueIdentifier,
    },
};
use cosmian_kms_client::{batch_export_objects, export_object, ClientConf, KmsClient};
use cosmian_pkcs11_module::traits::EncryptionAlgorithm;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::error::Pkcs11Error;

/// A wrapper around a KMS KMIP object.
#[allow(dead_code)]
#[derive(Debug)]
pub struct KmsObject {
    pub tags_or_id: String,
    pub object: Object,
    pub attributes: Attributes,
    pub other_tags: Vec<String>,
}

pub fn get_kms_client() -> Result<KmsClient, Pkcs11Error> {
    let conf_path = ClientConf::location(None)?;
    let conf = ClientConf::load(&conf_path)?;
    let kms_client = conf.initialize_kms_client(None, None)?;
    Ok(kms_client)
}

pub fn locate_kms_objects(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(locate_kms_objects_async(kms_client, tags))
}

pub(crate) async fn locate_kms_objects_async(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    locate_objects(kms_client, tags).await
}

pub fn get_kms_objects(
    kms_client: &KmsClient,
    tags: &[String],
    key_format_type: KeyFormatType,
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_objects_async(
        kms_client,
        tags,
        key_format_type,
    ))
}

pub(crate) async fn get_kms_objects_async(
    kms_client: &KmsClient,
    tags: &[String],
    key_format_type: KeyFormatType,
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    let key_ids = locate_objects(kms_client, tags).await?;
    let responses =
        batch_export_objects(kms_client, key_ids, true, None, true, Some(key_format_type)).await?;
    trace!("Found objects: {:?}", responses);
    let mut results = vec![];
    for response in responses {
        let (object, attributes) = response.map_err(|e| Pkcs11Error::ServerError(e.to_string()))?;
        let other_tags = attributes
            .get_tags()
            .into_iter()
            .filter(|t| !t.is_empty() && !tags.contains(t) && !t.starts_with('_'))
            .collect::<Vec<String>>();
        results.push(KmsObject {
            object,
            attributes,
            other_tags,
        });
    }
    Ok(results)
}

pub fn get_kms_object(
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
    let (object, attributes) = export_object(
        kms_client,
        object_id_or_tags,
        true,
        None,
        false,
        Some(key_format_type),
    )
    .await?;

    let attributes = attributes.unwrap_or_default();
    let other_tags = attributes
        .get_tags()
        .into_iter()
        .filter(|t| !t.is_empty() && !t.starts_with('_'))
        .collect::<Vec<String>>();
    Ok(KmsObject {
        object,
        attributes,
        other_tags,
    })
}

async fn locate_objects(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    let mut attributes = Attributes::default();
    attributes.set_tags(tags)?;

    let locate = Locate {
        attributes,
        ..Default::default()
    };
    let response = kms_client.locate(locate).await?;
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

pub fn kms_decrypt(
    kms_client: &KmsClient,
    key_id: String,
    encryption_algorithm: EncryptionAlgorithm,
    data: Vec<u8>,
) -> Result<Zeroizing<Vec<u8>>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(kms_decrypt_async(
        kms_client,
        key_id,
        encryption_algorithm,
        data,
    ))
}

pub(crate) async fn kms_decrypt_async(
    kms_client: &KmsClient,
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
    let response = kms_client.decrypt(decryption_request).await?;
    response.data.ok_or_else(|| {
        Pkcs11Error::ServerError("Decryption response does not contain data".to_string())
    })
}

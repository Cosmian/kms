use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::Locate,
    kmip_types::{Attributes, KeyFormatType},
};
use cosmian_kms_client::{batch_export_objects, ClientConf, KmsClient};

use crate::error::Pkcs11Error;

#[derive(Debug)]
pub struct KmsObject {
    pub object: Object,
    pub attributes: Attributes,
    pub other_tags: Vec<String>,
}

pub fn get_kms_client() -> Result<KmsClient, Pkcs11Error> {
    let conf_path = ClientConf::location(None)?;
    let conf = ClientConf::load(&conf_path)?;
    let kms_client = conf.initialize_kms_client()?;
    Ok(kms_client)
}

pub fn get_kms_objects(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(get_kms_objects_async(kms_client, tags))
}

pub(crate) async fn get_kms_objects_async(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<KmsObject>, Pkcs11Error> {
    let key_ids = locate_objects(kms_client, tags).await?;
    let responses = batch_export_objects(
        kms_client,
        key_ids,
        true,
        None,
        true,
        Some(KeyFormatType::Raw),
    )
    .await?;
    let mut results = vec![];
    for response in responses {
        match response {
            Ok((object, attributes)) => {
                let other_tags = attributes
                    .get_tags()
                    .into_iter()
                    .filter(|t| !(t.is_empty() || tags.contains(t) || t.starts_with('_')))
                    .collect::<Vec<String>>();
                results.push(KmsObject {
                    object: object.clone(),
                    attributes: attributes.clone(),
                    other_tags,
                });
            }
            Err(e) => {
                return Err(Pkcs11Error::ServerError(e.to_string()));
            }
        }
    }
    Ok(results)
}

async fn locate_objects(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    let mut attributes = Attributes::default();
    attributes.set_tags(tags)?;

    let locate = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes,
    };
    let keys = kms_client.locate(locate).await?;
    Ok(keys
        .unique_identifiers
        .unwrap_or(vec![])
        .iter()
        .map(|id| id.to_string().unwrap_or_default())
        .filter(|id| !id.is_empty())
        .collect())
}

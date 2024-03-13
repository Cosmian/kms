use zeroize::Zeroizing;

use cosmian_kmip::kmip::{
    kmip_operations::Locate,
    kmip_types::{Attributes, KeyFormatType},
};
use cosmian_kms_client::{ClientConf, export_object, KmsRestClient};

use crate::error::Pkcs11Error;

pub fn get_kms_client() -> Result<KmsRestClient, Pkcs11Error> {
    let conf_path = ClientConf::location(None)?;
    let conf = ClientConf::load(&conf_path)?;
    let kms_client = conf.initialize_kms_client()?;
    Ok(kms_client)
}

pub fn get_pkcs11_keys(
    kms_client: &KmsRestClient,
    tags: &[String],
) -> Result<Vec<String>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(locate_keys(kms_client, tags))
}

async fn get_pkcs11_keys_async(
    kms_client: &KmsRestClient,
    tags: &[String],
) -> Result<Vec<Pkcs11Key>, Pkcs11Error> {
    let key_ids = locate_keys(kms_client, tags).await?;
    let mut keys = Vec::new();
    for keyid in key_ids {
        let key = export_key(kms_client, &[keyid.clone()]).await?;
        keys.push(key);
    }
    Ok(keys)
}

struct Pkcs11Key {
    value: Zeroizing<Vec<u8>>,
    label: String,
}

async fn export_key(kms_client: &KmsRestClient, tags: &[String]) -> Result<Pkcs11Key, Pkcs11Error> {
    let id = serde_json::to_string(&tags)?;
    let unwrap = true;
    let wrapping_key_id = None;
    let allow_revoked = false;
    let (object, attributes) = export_object(
        kms_client,
        &id,
        unwrap,
        wrapping_key_id,
        allow_revoked,
        Some(KeyFormatType::Raw),
    )
    .await?;

    let key_bytes = object.key_block()?.key_bytes()?;

    let other_tags = attributes
        .unwrap_or_default()
        .get_tags()
        .into_iter()
        .filter(|t| !(t.is_empty() || tags.contains(t) || t.starts_with('_')))
        .collect::<Vec<String>>()
        .join(",");

    Ok(Pkcs11Key {
        value: key_bytes,
        label: other_tags,
    })
}

async fn locate_keys(
    kms_client: &KmsRestClient,
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

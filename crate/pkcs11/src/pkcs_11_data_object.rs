use std::{ffi::CString, sync::RwLock};

use cosmian_kmip::kmip::{
    kmip_operations::Locate,
    kmip_types::{Attributes, KeyFormatType},
};
use cosmian_kms_client::{batch_export_objects, ClientConf, KmsClient};
use native_pkcs11_traits::DataObject;
use sha3::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Pkcs11Error;

#[derive(Debug)]
pub struct Pkcs11DataObject {
    pub value: RwLock<Zeroizing<Vec<u8>>>,
    pub label: String,
}

impl Zeroize for Pkcs11DataObject {
    fn zeroize(&mut self) {
        self.value
            .write()
            .expect("failed locking the Data Object value")
            .zeroize();
    }
}

impl DataObject for Pkcs11DataObject {
    fn value(&self) -> Zeroizing<Vec<u8>> {
        self.value
            .read()
            .expect("failed locking the Data Object value")
            .clone()
    }

    fn application(&self) -> CString {
        CString::new(b"Cosmian KMS PKCS11 provider").unwrap_or_default()
    }

    fn data_hash(&self) -> Vec<u8> {
        // This is a hash of key material which may be leaked by the application
        // We need pre-image and collision resistance.
        // => use a cryptographic SHA3-256 hash
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(
            self.value
                .read()
                .expect("failed locking the Data Object value")
                .as_slice(),
        );
        let result = hasher.finalize();
        result.to_vec()
    }

    fn label(&self) -> String {
        self.label.clone()
    }

    fn delete(&self) {
        self.value
            .write()
            .expect("failed locking the Data Object value")
            .zeroize();
    }
}

pub fn get_kms_client() -> Result<KmsClient, Pkcs11Error> {
    let conf_path = ClientConf::location(None)?;
    let conf = ClientConf::load(&conf_path)?;
    let kms_client = conf.initialize_kms_client()?;
    Ok(kms_client)
}

pub fn get_pkcs11_keys(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<Pkcs11DataObject>, Pkcs11Error> {
    tokio::runtime::Runtime::new()?.block_on(get_pkcs11_keys_async(kms_client, tags))
}

pub(crate) async fn get_pkcs11_keys_async(
    kms_client: &KmsClient,
    tags: &[String],
) -> Result<Vec<Pkcs11DataObject>, Pkcs11Error> {
    let key_ids = locate_keys(kms_client, tags).await?;
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
    for response in &responses {
        match response {
            Ok((object, attributes)) => {
                let key_bytes = object.key_block()?.key_bytes()?;
                let other_tags = attributes
                    .get_tags()
                    .into_iter()
                    .filter(|t| !(t.is_empty() || tags.contains(t) || t.starts_with('_')))
                    .collect::<Vec<String>>()
                    .join(",");
                results.push(Pkcs11DataObject {
                    value: RwLock::from(key_bytes),
                    label: other_tags,
                });
            }
            Err(e) => {
                return Err(Pkcs11Error::ServerError(e.to_string()));
            }
        }
    }
    Ok(results)
}

// async fn export_key(
//     kms_client: &KmsClient,
//     tags: &[String],
// ) -> Result<Pkcs11DataObject, Pkcs11Error> {
//     let id = serde_json::to_string(&tags)?;
//     let unwrap = true;
//     let wrapping_key_id = None;
//     let allow_revoked = false;
//     let (object, attributes) = export_object(
//         kms_client,
//         &id,
//         unwrap,
//         wrapping_key_id,
//         allow_revoked,
//         Some(KeyFormatType::Raw),
//     )
//     .await?;
//
//     let key_bytes = object.key_block()?.key_bytes()?;
//
//     let other_tags = attributes
//         .unwrap_or_default()
//         .get_tags()
//         .into_iter()
//         .filter(|t| !(t.is_empty() || tags.contains(t) || t.starts_with('_')))
//         .collect::<Vec<String>>()
//         .join(",");
//
//     Ok(Pkcs11DataObject {
//         value: RwLock::from(key_bytes),
//         label: other_tags,
//     })
// }

async fn locate_keys(kms_client: &KmsClient, tags: &[String]) -> Result<Vec<String>, Pkcs11Error> {
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

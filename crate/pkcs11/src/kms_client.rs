use cosmian_kmip::kmip::kmip_types::KeyFormatType;
use cosmian_kms_client::{export_object, ClientConf, KmsRestClient};
use zeroize::Zeroizing;

use crate::error::Pkcs11Error;

pub fn get_kms_client() -> Result<KmsRestClient, Pkcs11Error> {
    let conf_path = ClientConf::location(None)?;
    let conf = ClientConf::load(&conf_path)?;
    let kms_client = conf.initialize_kms_client()?;
    Ok(kms_client)
}

pub async fn export_symmetric_key(
    kms_client: &KmsRestClient,
    tags: &[String],
) -> Result<Zeroizing<Vec<u8>>, Pkcs11Error> {
    let id = serde_json::to_string(&tags)?;
    let unwrap = true;
    let wrapping_key_id = None;
    let allow_revoked = false;
    let (object, _attributes) = export_object(
        kms_client,
        &id,
        unwrap,
        wrapping_key_id,
        allow_revoked,
        Some(KeyFormatType::Raw),
    )
    .await?;
    Ok(object.key_block()?.key_bytes()?)
}

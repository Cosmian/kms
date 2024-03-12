use cosmian_kmip::kmip::kmip_types::KeyFormatType;
use cosmian_kms_cli::config::CliConf;
use cosmian_kms_cli::error::CliError;
use cosmian_kms_client::KmsRestClient;
use zeroize::Zeroizing;
use crate::export_object::export_object;

pub fn get_kms_client() -> Result<KmsRestClient, CliError> {
    let conf_path = CliConf::location(None)?;
    let conf = CliConf::load(&conf_path)?;
    conf.initialize_kms_client()
}

pub async fn export_symmetric_key(kms_client: &KmsRestClient, tags:&[String]) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let kms_client = get_kms_client()?;
    let id = serde_json::to_string(&tags)?;
    let unwrap = true;
    let wrapping_key_id = None;
    let allow_revoked = false;
    let (object, _attributes) = export_object(
        &kms_client,
        &id,
        unwrap,
        wrapping_key_id,
        allow_revoked,
        Some(KeyFormatType::Raw),
    ).await?;
    Ok(object.key_block()?.key_bytes()?)
}
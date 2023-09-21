use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Get, Locate},
    kmip_types::Attributes,
};
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::tagging::set_tags;
use tracing::{debug, trace};

use crate::{cli_bail, error::CliError};

pub async fn locate_key<const LENGTH: usize>(
    client_connector: &KmsRestClient,
    certificate_uid: &str,
    search_attributes: &Attributes,
) -> Result<String, CliError> {
    let mut search_attributes = search_attributes.clone();
    set_tags(
        &mut search_attributes,
        [&format!("_cert_uid={certificate_uid}")],
    )?;

    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response = client_connector.locate(locate_request).await?;
    let uids = locate_response
        .unique_identifiers
        .ok_or(CliError::ItemNotFound(
            "Searching related certificate private/public key failed".to_string(),
        ))?;
    if uids.len() > 1 {
        cli_bail!(
            "Internal error: Multiple keys found for certificate {certificate_uid}: {uids:?}"
        );
    }
    let key_uid = uids.first().ok_or(CliError::ItemNotFound(
        "Cannot get first key unique identifier".to_string(),
    ))?;

    trace!("key_uid: {key_uid}");

    Ok(key_uid.clone())
}

pub(crate) async fn locate_ca_cert(
    client_connector: &KmsRestClient,
    issuer_name: &str,
    search_attributes: &Attributes,
) -> Result<Vec<u8>, CliError> {
    let mut my_search_attributes = search_attributes.clone();

    set_tags(
        &mut my_search_attributes,
        [&format!("_cert_ca={issuer_name}")],
    )?;

    debug!("my_search_attributes: {:?}", my_search_attributes);
    let locate_request = Locate {
        attributes: my_search_attributes,
        ..Locate::default()
    };
    let locate_response = client_connector.locate(locate_request).await?;
    let uids = locate_response
        .unique_identifiers
        .ok_or(CliError::ItemNotFound(
            "Searching related certificate CA key failed".to_string(),
        ))?;

    if uids.len() > 1 {
        cli_bail!("Internal error: Multiple certificates found for issuer {issuer_name}: {uids:?}");
    }
    let cert_uid = uids.first().ok_or(CliError::ItemNotFound(
        "Cannot get first key unique identifier".to_string(),
    ))?;

    trace!("cert_uid: {cert_uid}");

    let get_response = client_connector.get(Get::from(cert_uid)).await?;
    let certificate_bytes = match get_response.object {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => {
            cli_bail!(
                "The object {} is not a certificate but a {}",
                &cert_uid,
                get_response.object.object_type()
            );
        }
    };

    Ok(certificate_bytes)
}

pub async fn locate_and_get_key_bytes<const LENGTH: usize>(
    client_connector: &KmsRestClient,
    certificate_uid: &str,
    search_attributes: &Attributes,
) -> Result<[u8; LENGTH], CliError> {
    let key_uid =
        locate_key::<LENGTH>(client_connector, certificate_uid, search_attributes).await?;
    let get_response = client_connector.get(Get::from(key_uid)).await?;
    let key_bytes = &get_response.object.key_block()?.key_bytes()?;
    let key_array: [u8; LENGTH] = key_bytes[..].try_into()?;
    Ok(key_array)
}

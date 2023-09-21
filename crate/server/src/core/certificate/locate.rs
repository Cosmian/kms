use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Get, Locate},
    kmip_types::Attributes,
};
use cosmian_kms_utils::{access::ExtraDatabaseParams, tagging::set_tags};
use tracing::debug;

use super::KMS;
use crate::{error::KmsError, result::KResult};

async fn locate_by_tags(
    object_type: ObjectType,
    tags: &[&str],
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    debug!("locate_by_tags: tags: {tags:?}");
    // Search key matching this vendor attributes
    let mut search_attributes = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
    set_tags(&mut search_attributes, tags)?;

    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response = kms.locate(locate_request, owner, params).await?;
    match locate_response.unique_identifiers {
        Some(uids) => match uids.len() {
            0 => Err(KmsError::ItemNotFound(format!(
                "locate_by_tags: {object_type:?} with tags '{tags:?}' not found"
            ))),
            1 => {
                let uid = uids[0].clone();
                debug!(
                    "locate_by_tags: Found {object_type:?} matching tags '{tags:?}' with unique \
                     identifier: {uid}",
                );
                Ok(uid)
            }
            _ => Err(KmsError::InvalidRequest(format!(
                "locate_by_tags: More than one object {object_type:?} found for tags '{tags:?}'"
            ))),
        },

        None => Err(KmsError::ItemNotFound(format!(
            "locate_by_tags: {object_type:?} with tags '{tags:?}' not found (None)"
        ))),
    }
}

pub(crate) async fn locate_ca_private_key(
    ca_subject_common_name: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_by_tags(
        ObjectType::PrivateKey,
        &[&format!("_ca={ca_subject_common_name}")],
        kms,
        owner,
        params,
    )
    .await
}

pub(crate) async fn locate_by_spki(
    spki: &str,
    object_type: ObjectType,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    let tags = &[&format!("_cert_spki={spki}")];
    debug!("locate_by_spki: tags: {tags:?}");
    // Search key matching this vendor attributes
    let mut search_attributes = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
    set_tags(&mut search_attributes, tags)?;

    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response = kms.locate(locate_request, owner, params).await?;
    match locate_response.unique_identifiers {
        Some(uids) => match uids.len() {
            0 => Err(KmsError::ItemNotFound(format!(
                "locate_by_spki: {object_type:?} with tags '{tags:?}' not found"
            ))),
            _ => {
                let uid = uids[0].clone();
                debug!(
                    "locate_by_spki: Found {object_type:?} matching tags '{tags:?}' with unique \
                     identifier: {uid}",
                );
                Ok(uid)
            }
        },

        None => Err(KmsError::ItemNotFound(format!(
            "locate_by_spki: {object_type:?} with tags '{tags:?}' not found (None)"
        ))),
    }
}

pub(crate) async fn locate_ca_certificate(
    ca_subject_common_name: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_by_tags(
        ObjectType::Certificate,
        &[&format!("_ca={ca_subject_common_name}")],
        kms,
        owner,
        params,
    )
    .await
}

/// The function `locate_ca_certificate_by_spki` is used to locate a CA certificate
/// by its subject common name and SPKI (Subject Public Key Info). In particular, it avoids retrieving more than 1 CA certificate when multiple CA certificates cohabit.
///
/// Arguments:
///
/// * `ca_subject_common_name`: The `ca_subject_common_name` parameter is a string
/// that represents the common name of the CA (Certificate Authority) certificate.
/// * `ca_spki`: The `ca_spki` parameter is the Subject Public Key Info (SPKI) of
/// the CA certificate. It is a string representation of the public key used by the
/// CA to sign certificates.
/// * `kms`: The `kms` parameter is of type `KMS` and is used for key management
/// operations. It is likely a dependency that provides functionality related to
/// encryption, decryption, and key generation.
/// * `owner`: The `owner` parameter is a string that represents the owner of the CA
/// certificate. It is used to identify the specific owner or entity that the
/// certificate belongs to.
/// * `params`: The `params` parameter is an optional reference to an
/// `ExtraDatabaseParams` struct. It contains additional parameters that can be used
/// for locating the CA certificate.
///
/// Returns:
///
/// a result of type `KResult<String>`.
pub(crate) async fn locate_ca_certificate_by_spki(
    ca_subject_common_name: &str,
    ca_spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_by_tags(
        ObjectType::Certificate,
        &[
            &format!("_ca={ca_subject_common_name}"),
            &format!("_cert_spki={ca_spki}"),
        ],
        kms,
        owner,
        params,
    )
    .await
}

pub(crate) async fn locate_certificate_by_spki(
    spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_by_tags(
        ObjectType::Certificate,
        &[&format!("_cert_spki={spki}")],
        kms,
        owner,
        params,
    )
    .await
}

pub(crate) async fn locate_certificate_by_common_name_and_get_bytes(
    ca: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    // From the issuer name, recover the KMIP certificate object
    let certificate_id = locate_ca_certificate(ca, kms, owner, params).await?;
    get_certificate_bytes(&certificate_id, kms, owner, params).await
}

pub(crate) async fn locate_certificate_by_spki_and_get_bytes(
    ca_subject_name: &str,
    spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    // From the issuer name, recover the KMIP certificate object
    let certificate_id =
        locate_ca_certificate_by_spki(ca_subject_name, spki, kms, owner, params).await?;
    get_certificate_bytes(&certificate_id, kms, owner, params).await
}

pub(crate) async fn get_certificate_bytes(
    certificate_id: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    debug!("Certificate identifier: {}", certificate_id);
    let get_response = kms.get(Get::from(certificate_id), owner, params).await?;
    match get_response.object {
        Object::Certificate {
            certificate_value, ..
        } => Ok(certificate_value),
        _ => Err(KmsError::Certificate(
            "Invalid object type: Expected Certificate".to_string(),
        )),
    }
}

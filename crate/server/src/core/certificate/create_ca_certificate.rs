use std::{collections::HashSet, str::FromStr};

use cosmian_crypto_core::{
    reexport::x509_cert::{builder::Profile, name::Name},
    Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType, kmip_operations::Locate, kmip_types::Attributes,
};
use cosmian_kms_utils::{access::ExtraDatabaseParams, tagging::set_tags};
use tracing::debug;

use super::{ca_signing_key::CASigningKey, create_key_pair_and_certificate};
use crate::{core::KMS, error::KmsError, result::KResult};

async fn locate_ca(
    ca_subject_common_name: &str,
    object_type: ObjectType,
    tags: &[&str],
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    debug!(
        "locate_ca_key: ca: {ca_subject_common_name} object_type: {object_type:?} owner: {owner}"
    );
    // Search key matching this vendor attributes
    let mut search_attributes = Attributes {
        object_type: Some(object_type),
        ..Attributes::default()
    };
    set_tags(&mut search_attributes, tags)?;
    debug!("Search attributes: CA: {ca_subject_common_name}");

    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response = kms.locate(locate_request, owner, params).await?;
    match locate_response.unique_identifiers {
        Some(uids) => match uids.len() {
            0 => Err(KmsError::ItemNotFound(format!(
                "CA {object_type:?} with issuer name '{ca_subject_common_name}' not found"
            ))),
            1 => {
                let uid = uids[0].clone();
                debug!(
                    "Found {object_type:?} matching CA issuer name '{ca_subject_common_name}' \
                     with unique identifier: {uid}",
                );
                Ok(uid)
            }
            _ => Err(KmsError::InvalidRequest(format!(
                "More than one CA {object_type:?} found for issuer name '{ca_subject_common_name}'"
            ))),
        },

        None => Err(KmsError::ItemNotFound(format!(
            "CA {object_type:?} with issuer name '{ca_subject_common_name}' not found (None)"
        ))),
    }
}

async fn locate_ca_private_key(
    ca_subject_common_name: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_ca(
        ca_subject_common_name,
        ObjectType::PrivateKey,
        &[&format!("_ca={ca_subject_common_name}")],
        kms,
        owner,
        params,
    )
    .await
}

pub(crate) async fn locate_ca_certificate(
    ca_subject_common_name: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    locate_ca(
        ca_subject_common_name,
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
    locate_ca(
        ca_subject_common_name,
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

async fn create_root_ca(
    ca_subject_common_name: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    let (create_key_pair_response, _) =
        create_key_pair_and_certificate::<Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH>(
            ca_subject_common_name,
            None,
            Profile::Root,
            tags,
            true,
            kms,
            owner,
            params,
        )
        .await?;

    Ok(CASigningKey::new(
        ca_subject_common_name,
        &create_key_pair_response.private_key_unique_identifier,
        &create_key_pair_response.public_key_unique_identifier,
    ))
}

async fn create_sub_ca(
    ca_signing_key: CASigningKey,
    subca_subject_common_name: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    let profile = Profile::SubCA {
        issuer: Name::from_str(&format!("CN={}", ca_signing_key.ca_subject_common_name)).map_err(
            |e| {
                KmsError::InvalidRequest(format!(
                    "SubCA certificate error: cannot convert CA {} to Name: {e:?}",
                    ca_signing_key.ca_subject_common_name
                ))
            },
        )?,
        path_len_constraint: None,
    };
    let (create_key_pair_response, _) =
        create_key_pair_and_certificate::<Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH>(
            subca_subject_common_name,
            Some(&ca_signing_key),
            profile,
            tags,
            true,
            kms,
            owner,
            params,
        )
        .await?;

    Ok(CASigningKey::new(
        subca_subject_common_name,
        &create_key_pair_response.private_key_unique_identifier,
        &create_key_pair_response.public_key_unique_identifier,
    ))
}

pub(crate) async fn create_ca_chain(
    ca_subject_common_names: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    // Split all CA Common Name
    let cas = ca_subject_common_names.split('/').collect::<Vec<_>>();
    let mut last_ca_signing_key = CASigningKey::default();

    // in this loop the condition could be removed with the help of `Iterator::advance_by`
    // see: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.advance_by
    for (index, current_ca) in cas.iter().enumerate() {
        debug!("[{index}]: Loop: current_ca: {current_ca}");
        if index == 0 {
            let signing_keys_uid = match locate_ca_private_key(current_ca, kms, owner, params).await
            {
                Ok(uid) => {
                    debug!("[0]: Retrieving the root CA certificate: Root CA: {current_ca}");
                    CASigningKey::from_private_key_uid(current_ca, &uid, kms, owner, params).await
                }
                Err(err) => match err {
                    KmsError::ItemNotFound(_) => {
                        debug!(
                            "[0]: Creating the root CA certificate: CA: {current_ca}: Error: \
                             {err:?}"
                        );
                        create_root_ca(current_ca, tags, kms, owner, params).await
                    }
                    _ => Err(err)?,
                },
            }?;
            last_ca_signing_key = signing_keys_uid;
        } else {
            let signing_keys_uid = match locate_ca_private_key(current_ca, kms, owner, params).await
            {
                Ok(uid) => {
                    debug!(
                        "[{index}]: Retrieving the subCA certificate: subCA: {current_ca}: \
                         signing key: {last_ca_signing_key:?}"
                    );
                    CASigningKey::from_private_key_uid(current_ca, &uid, kms, owner, params).await
                }
                Err(err) => match err {
                    KmsError::ItemNotFound(_) => {
                        debug!("[{index}]: Creating the subCA certificate: {current_ca}");
                        create_sub_ca(last_ca_signing_key, current_ca, tags, kms, owner, params)
                            .await
                    }
                    _ => Err(err)?,
                },
            }?;
            last_ca_signing_key = signing_keys_uid;
        }
    }

    debug!("Return from create_ca_chain: {last_ca_signing_key:?}");

    Ok(last_ca_signing_key)
}

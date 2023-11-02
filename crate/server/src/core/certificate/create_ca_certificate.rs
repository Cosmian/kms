use std::{collections::HashSet, str::FromStr};

use cloudproof::reexport::crypto_core::{
    reexport::x509_cert::{builder::Profile, name::Name},
    Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::kmip_operations::ErrorReason;
use cosmian_kms_utils::access::ExtraDatabaseParams;
use tracing::debug;

use super::{ca_signing_key::CASigningKey, create_key_pair_and_certificate};
use crate::{
    core::{certificate::locate::locate_ca_private_key, KMS},
    error::KmsError,
    result::KResult,
};

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
                    KmsError::KmipError(ErrorReason::Item_Not_Found, _) => {
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
                    KmsError::KmipError(ErrorReason::Item_Not_Found, _) => {
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

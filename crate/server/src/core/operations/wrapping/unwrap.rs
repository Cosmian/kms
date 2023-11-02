use cosmian_kmip::kmip::{
    kmip_data_structures::KeyBlock,
    kmip_objects::{Object, ObjectType},
    kmip_types::LinkType,
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::wrap::unwrap_key_block,
};
use tracing::debug;
use x509_parser::parse_x509_certificate;

use super::get_key;
use crate::{
    core::{
        certificate::{locate::locate_by_spki, parsing::get_certificate_subject_key_identifier},
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Unwrap a key
/// This function is used to unwrap a key before storing it in the database
///
/// # Arguments
/// * `object_type` - the type of the object to unwrap
/// * `object_key_block` - the key block of the object to unwrap
/// * `kms` - the KMS
/// * `owner` - the owner of the object to unwrap
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub async fn unwrap_key(
    object_type: ObjectType,
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let unwrapping_key_uid = match &object_key_block.key_wrapping_data {
        Some(kwd) => match &kwd.encryption_key_information {
            Some(eki) => &eki.unique_identifier,
            None => kms_bail!("unwrap_key: unable to unwrap key: unwrapping key uid is missing"),
        },
        None => kms_bail!("unwrap_key: unable to unwrap key: key wrapping data is missing"),
    };

    // fetch the unwrapping key
    let unwrapping_key = get_key(
        unwrapping_key_uid,
        ObjectOperationType::Decrypt,
        kms,
        owner,
        params,
    )
    .await?;

    // in the case the key is a PublicKey or Certificate, we need to fetch the corresponding private key
    let unwrapping_key = match unwrapping_key.object_type() {
        ObjectType::PublicKey => {
            let private_key_uid = unwrapping_key
                .attributes()?
                .get_link(LinkType::PrivateKeyLink)
                .context("unable to unwrap key: public key does not have a private key link")?;
            // fetch the private key
            get_key(
                &private_key_uid,
                ObjectOperationType::Decrypt,
                kms,
                owner,
                params,
            )
            .await?
        }
        ObjectType::Certificate => {
            debug!("unwrap_key: certificate: locate private key from certificate uid");
            let certificate_value = match unwrapping_key {
                Object::Certificate {
                    certificate_value, ..
                } => Ok(certificate_value),
                _ => Err(KmsError::Certificate(
                    "Invalid object type: Expected Certificate".to_string(),
                )),
            }?;
            let (_, x509_cert) = parse_x509_certificate(&certificate_value)?;
            let ski = get_certificate_subject_key_identifier(&x509_cert)?;
            match ski {
                Some(ski) => {
                    let private_key_uid =
                        locate_by_spki(&ski, ObjectType::PrivateKey, kms, owner, params).await?;
                    debug!("unwrap_key: found private key uid: {private_key_uid}");
                    // fetch the private key
                    get_key(
                        &private_key_uid,
                        ObjectOperationType::Decrypt,
                        kms,
                        owner,
                        params,
                    )
                    .await?
                }
                None => {
                    return Err(KmsError::Certificate(
                        "Certificate invalid: no Subject Key Identifier found".to_string(),
                    ))
                }
            }
        }
        _ => unwrapping_key,
    };

    unwrap_key_block(object_key_block, &unwrapping_key)?;
    Ok(())
}

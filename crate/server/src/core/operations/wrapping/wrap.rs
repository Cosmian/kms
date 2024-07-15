use cosmian_kmip::{
    crypto::wrap::wrap_key_block,
    kmip::{
        kmip_data_structures::{KeyBlock, KeyWrappingSpecification},
        kmip_objects::ObjectType,
        kmip_types::LinkType,
    },
};
use cosmian_kms_client::access::ObjectOperationType;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::retrieve_object_for_operation,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Wrap a key with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// * `kms` - the kms
/// * `user` - the user performing the call
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub(crate) async fn wrap_key(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    // recover the wrapping key uid
    let wrapping_key_uid = match &key_wrapping_specification.encryption_key_information {
        Some(eki) => eki
            .unique_identifier
            .as_str()
            .context("unable to unwrap key: unwrapping key uid is not a string")?,
        None => kms_bail!("unable to unwrap key: unwrapping key uid is missing"),
    };

    // fetch the wrapping key
    let wrapping_key = retrieve_object_for_operation(
        wrapping_key_uid,
        ObjectOperationType::Encrypt,
        kms,
        user,
        params,
    )
    .await?;

    // in the case the key is a Private Key, we need to fetch the corresponding private key or certificate
    let object_type = wrapping_key.object.object_type();
    let wrapping_key = match object_type {
        ObjectType::PublicKey | ObjectType::Certificate | ObjectType::SymmetricKey => wrapping_key,
        ObjectType::PrivateKey => {
            let attributes = wrapping_key.attributes;
            let public_key_uid = attributes
                .get_link(LinkType::PublicKeyLink)
                .or_else(|| attributes.get_link(LinkType::CertificateLink))
                .context("unable to find a certificate or public key for the private key")?;
            // fetch the private key
            retrieve_object_for_operation(
                &public_key_uid.to_string(),
                ObjectOperationType::Decrypt,
                kms,
                user,
                params,
            )
            .await?
        }
        _ => kms_bail!("wrap_key: unsupported object type: {}", object_type),
    };

    // Check on key CryptographicUsageMask is done inside `wrap_key_block`.
    wrap_key_block(
        object_key_block,
        &wrapping_key.object,
        key_wrapping_specification,
    )?;

    Ok(())
}

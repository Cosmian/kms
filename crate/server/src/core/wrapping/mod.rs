use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::{SYSTEM_TAG_PUBLIC_KEY, VENDOR_ID_COSMIAN},
    kmip_attributes::Attributes,
    kmip_data_structures::KeyValue,
    kmip_objects::Object,
    kmip_types::VendorAttributeValue,
};

pub(crate) use unwrap::{
    authorize_stored_unwrap, authorize_unwrap_with, unwrap_object, unwrap_stored_object,
};
pub(crate) use wrap::{
    LocalWrappingKey, bind_stored_objects, ensure_kek_wrapping, wrap_and_cache, wrap_object,
    wrap_with_local_key,
};

use crate::{core::KMS, error::KmsError, result::KResult};

mod unwrap;
mod wrap;

/// Vendor attribute, inside the KEK-wrapped plaintext, holding the UID of the database row the
/// object is stored in. The wrapping authenticates it, so a ciphertext moved to another row (or
/// owner) is refused on read.
pub(crate) const STORED_UID_ATTR: &str = "x-cosmian-stored-uid";

/// Is `uid`, the wrapping key UID of a stored key block, the server `key_encryption_key` or its
/// `_pk` public key? Literal match only: the key a UID resolves to through a link never counts.
pub(crate) fn is_server_kek(kms: &KMS, uid: &str) -> bool {
    kms.params
        .key_wrapping_key
        .as_deref()
        .is_some_and(|kek| uid.strip_suffix(SYSTEM_TAG_PUBLIC_KEY).unwrap_or(uid) == kek)
}

/// Is `object` wrapped by the server `key_encryption_key`?
pub(crate) fn is_wrapped_by_server_kek(kms: &KMS, object: &Object) -> bool {
    object
        .wrapping_key_uid()
        .is_some_and(|uid| is_server_kek(kms, &uid))
}

/// Record the database row `uid` in the (unwrapped) key value attributes of `object`, before it
/// is wrapped with TTLV encoding.
pub(crate) fn bind_to_row(object: &mut Object, uid: &str) -> KResult<()> {
    let Some(KeyValue::Structure { attributes, .. }) = &mut object.key_block_mut()?.key_value
    else {
        return Err(KmsError::ServerError(format!(
            "object {uid}: cannot bind to its row, the key value is not in clear"
        )));
    };
    attributes
        .get_or_insert_with(Box::default)
        .set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            STORED_UID_ATTR,
            VendorAttributeValue::TextString(uid.to_owned()),
        );
    Ok(())
}

/// Remove and return the row UID recorded by [`bind_to_row`] from an unwrapped `object`. Key
/// value attributes that held nothing else are dropped, as before binding.
pub(crate) fn take_row_binding(object: &mut Object) -> Option<String> {
    let Some(KeyValue::Structure { attributes, .. }) = &mut object.key_block_mut().ok()?.key_value
    else {
        return None;
    };
    let attrs = attributes.as_mut()?;
    let bound = attrs.remove_vendor_attribute(VENDOR_ID_COSMIAN, STORED_UID_ATTR);
    if **attrs == Attributes::default() {
        *attributes = None;
    }
    match bound? {
        VendorAttributeValue::TextString(uid) => Some(uid),
        _ => None,
    }
}

use std::collections::HashSet;

use crate::{HError, HResult};

const TAGGED_LABEL_MARKER: &str = "cosmian-kms-tags-v1";

pub(crate) fn serialize_tagged_label(
    id: &[u8],
    tags: Option<&HashSet<String>>,
) -> HResult<Option<Vec<u8>>> {
    tags.filter(|tags| !tags.is_empty())
        .map(|tags| serde_json::to_vec(&(TAGGED_LABEL_MARKER, tags, id)))
        .transpose()
        .map_err(|error| HError::Default(format!("Failed serializing HSM key tags: {error}")))
}

pub(crate) fn deserialize_tagged_label(bytes: Vec<u8>) -> HResult<(String, HashSet<String>)> {
    if let Ok((marker, tags, id)) =
        serde_json::from_slice::<(String, HashSet<String>, Vec<u8>)>(&bytes)
        && marker == TAGGED_LABEL_MARKER
    {
        return String::from_utf8(id)
            .map(|id| (id, tags))
            .map_err(|error| HError::Default(format!("Failed decoding HSM key label: {error}")));
    }
    String::from_utf8(bytes)
        .map(|label| (label, HashSet::new()))
        .map_err(|error| HError::Default(format!("Failed decoding HSM key label: {error}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{deserialize_tagged_label, serialize_tagged_label};

    #[test]
    fn tagged_label_round_trip() {
        let tags = HashSet::from(["bench".to_owned(), "disk".to_owned()]);
        let encoded = serialize_tagged_label(b"key-id", Some(&tags));
        assert!(encoded.is_ok());
        let Ok(Some(encoded)) = encoded else {
            return;
        };
        assert_eq!(
            deserialize_tagged_label(encoded).ok(),
            Some(("key-id".to_owned(), tags))
        );
    }

    #[test]
    fn plain_label_remains_compatible() {
        assert_eq!(
            deserialize_tagged_label(b"key-id".to_vec()).ok(),
            Some(("key-id".to_owned(), HashSet::new()))
        );
    }
}

mod aes;
mod ec;
mod eddsa;
mod message_aead;
mod rsa;

mod session_impl;
pub(crate) use ec::{curve_byte_size, curve_from_der_oid};
pub use rsa::RsaOaepDigest;
pub use session_impl::{
    AesKeySize, HsmEncryptionAlgorithm, HsmSigningAlgorithm, RsaKeySize, Session,
};

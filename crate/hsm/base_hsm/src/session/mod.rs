use std::collections::HashSet;

use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializer};

use crate::{HError, HResult};

const TAGGED_LABEL_MARKER: &str = "cosmian-kms-tags-v1";
/// LEB128 binary tag marker prefix to differentiate from JSON or raw strings
const TAGGED_LABEL_LEB128_MAGIC: &[u8] = b"CKTAG1";

pub(crate) fn serialize_tagged_label(
    id: &[u8],
    tags: Option<&HashSet<String>>,
    max_len: Option<usize>,
) -> HResult<Option<Vec<u8>>> {
    let Some(tags) = tags.filter(|tags| !tags.is_empty()) else {
        return Ok(None);
    };

    let mut ser = Serializer::new();
    ser.write_array(TAGGED_LABEL_LEB128_MAGIC)
        .map_err(|e| HError::Default(format!("Failed serializing magic: {e}")))?;
    ser.write_vec(id)
        .map_err(|e| HError::Default(format!("Failed serializing id: {e}")))?;
    ser.write_leb128_u64(u64::try_from(tags.len())?)
        .map_err(|e| HError::Default(format!("Failed serializing tag count: {e}")))?;
    for tag in tags {
        ser.write_vec(tag.as_bytes())
            .map_err(|e| HError::Default(format!("Failed serializing tag: {e}")))?;
    }

    let bytes = ser.finalize().to_vec();
    if let Some(max) = max_len {
        if bytes.len() > max {
            return Ok(None);
        }
    }
    Ok(Some(bytes))
}

pub(crate) fn deserialize_tagged_label(bytes: Vec<u8>) -> HResult<(String, HashSet<String>)> {
    // 1. Try LEB128 binary format first
    if bytes.starts_with(TAGGED_LABEL_LEB128_MAGIC) {
        if let Some(payload) = bytes.get(TAGGED_LABEL_LEB128_MAGIC.len()..) {
            let mut de = Deserializer::new(payload);
            if let Ok(id_bytes) = de.read_vec() {
                if let Ok(num_tags) = de.read_leb128_u64() {
                    if let Ok(cap) = usize::try_from(num_tags) {
                        let mut tags = HashSet::with_capacity(cap);
                        let mut ok = true;
                        for _ in 0..num_tags {
                            if let Ok(tag_bytes) = de.read_vec() {
                                if let Ok(tag) = String::from_utf8(tag_bytes) {
                                    tags.insert(tag);
                                } else {
                                    ok = false;
                                    break;
                                }
                            } else {
                                ok = false;
                                break;
                            }
                        }
                        if ok {
                            if let Ok(id) = String::from_utf8(id_bytes) {
                                return Ok((id, tags));
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Backward compatibility with legacy JSON format
    if let Ok((marker, tags, id_str)) =
        serde_json::from_slice::<(String, HashSet<String>, String)>(&bytes)
        && marker == TAGGED_LABEL_MARKER
    {
        return Ok((id_str, tags));
    }
    if let Ok((marker, tags, id_bytes)) =
        serde_json::from_slice::<(String, HashSet<String>, Vec<u8>)>(&bytes)
        && marker == TAGGED_LABEL_MARKER
    {
        return String::from_utf8(id_bytes)
            .map(|id| (id, tags))
            .map_err(|error| HError::Default(format!("Failed decoding HSM key label: {error}")));
    }

    // 3. Fallback: plain untagged label
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
        let encoded = serialize_tagged_label(b"key-id", Some(&tags), None);
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
    fn tagged_label_exceeding_max_len_falls_back_to_none() {
        let tags = HashSet::from(["bench".to_owned(), "disk".to_owned()]);
        let encoded = serialize_tagged_label(b"key-id", Some(&tags), Some(10));
        assert_eq!(encoded.ok(), Some(None));
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

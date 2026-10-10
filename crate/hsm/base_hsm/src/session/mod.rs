use std::collections::HashSet;

use cosmian_crypto_core::bytes_ser_de::Deserializer;

use crate::{HError, HResult};

const TAGGED_LABEL_MARKER: &str = "cosmian-kms-tags-v1";
/// UTF-8-safe prefix for encoded tagged labels stored in `CKA_LABEL`.
const TAGGED_LABEL_HEX_PREFIX: &[u8] = b"CKTAG1:";
/// LEB128 binary tag marker prefix used inside the UTF-8-safe representation.
const TAGGED_LABEL_LEB128_MAGIC: &[u8] = b"CKTAG1";

const fn nibble_to_hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + nibble - 10,
        _ => b'?',
    }
}

fn encode_hex(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        encoded.push(nibble_to_hex(byte >> 4));
        encoded.push(nibble_to_hex(byte & 0x0F));
    }
    encoded
}

pub(crate) fn utf8_label(id: &[u8]) -> Vec<u8> {
    String::from_utf8(id.to_vec()).map_or_else(|_| encode_hex(id), String::into_bytes)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair.first().copied()?)?;
            let low = hex_value(pair.get(1).copied()?)?;
            Some((high << 4) | low)
        })
        .collect()
}

pub(crate) fn serialize_tagged_label(
    id: &[u8],
    tags: Option<&HashSet<String>>,
    max_len: Option<usize>,
) -> HResult<Option<Vec<u8>>> {
    let Some(tags) = tags.filter(|tags| !tags.is_empty()) else {
        return Ok(None);
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(TAGGED_LABEL_LEB128_MAGIC);
    let mut ser = cosmian_crypto_core::bytes_ser_de::Serializer::new();
    ser.write_vec(id)
        .map_err(|e| HError::Default(format!("Failed serializing id: {e}")))?;
    ser.write_leb128_u64(u64::try_from(tags.len())?)
        .map_err(|e| HError::Default(format!("Failed serializing tag count: {e}")))?;
    for tag in tags {
        ser.write_vec(tag.as_bytes())
            .map_err(|e| HError::Default(format!("Failed serializing tag: {e}")))?;
    }
    bytes.extend_from_slice(&ser.finalize());

    let mut encoded = TAGGED_LABEL_HEX_PREFIX.to_vec();
    encoded.extend(encode_hex(&bytes));
    if let Some(max) = max_len {
        if encoded.len() <= max {
            return Ok(Some(encoded));
        }
        // The hex form doubles the payload size and can exceed short HSM label
        // limits (Proteccio caps CKA_LABEL at 128 bytes). Fall back to the
        // compact LEB128 binary form when it still fits and is valid UTF-8
        // (the case for the ASCII ids KMS normally produces), so tags survive
        // instead of being silently dropped.
        if bytes.len() <= max && std::str::from_utf8(&bytes).is_ok() {
            return Ok(Some(bytes));
        }
        return Ok(None);
    }
    Ok(Some(encoded))
}

fn deserialize_tagged_payload(payload: &[u8]) -> Option<(String, HashSet<String>)> {
    let mut de = Deserializer::new(payload);
    let id_bytes = de.read_vec().ok()?;
    let num_tags = de.read_leb128_u64().ok()?;
    let capacity = usize::try_from(num_tags).ok()?;
    let mut tags = HashSet::with_capacity(capacity);
    for _ in 0..num_tags {
        let tag = String::from_utf8(de.read_vec().ok()?).ok()?;
        tags.insert(tag);
    }
    Some((String::from_utf8(id_bytes).ok()?, tags))
}

pub(crate) fn deserialize_tagged_label(bytes: Vec<u8>) -> HResult<(String, HashSet<String>)> {
    if let Some(encoded) = bytes.strip_prefix(TAGGED_LABEL_HEX_PREFIX)
        && let Some(decoded) = decode_hex(encoded)
        && let Some(payload) = decoded.strip_prefix(TAGGED_LABEL_LEB128_MAGIC)
        && let Some(result) = deserialize_tagged_payload(payload)
    {
        return Ok(result);
    }

    if let Some(payload) = bytes.strip_prefix(TAGGED_LABEL_LEB128_MAGIC)
        && let Some(result) = deserialize_tagged_payload(payload)
    {
        return Ok(result);
    }

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

    String::from_utf8(bytes)
        .map(|label| (label, HashSet::new()))
        .map_err(|error| HError::Default(format!("Failed decoding HSM key label: {error}")))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{deserialize_tagged_label, serialize_tagged_label, utf8_label};

    #[test]
    fn tagged_label_round_trip() {
        let tags = HashSet::from(["bench".to_owned(), "disk".to_owned()]);
        let encoded = serialize_tagged_label(b"key-id", Some(&tags), None);
        assert!(encoded.is_ok());
        let Ok(Some(encoded)) = encoded else {
            return;
        };
        assert!(encoded.iter().all(u8::is_ascii));
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
    fn tagged_label_falls_back_to_binary_when_hex_exceeds_limit() -> crate::HResult<()> {
        // Mirrors the delegated-benchmark key UID + tag set: the hex form is
        // ~190 bytes (over Proteccio's 128-byte CKA_LABEL cap) while the compact
        // LEB128 binary form is ~92 bytes and must be selected so tags survive.
        let id = b"pkcs11_ec_01234567-89ab-cdef-0123-456789abcdef";
        let tags = HashSet::from([
            "pkcs11-bench".to_owned(),
            "disk-encryption".to_owned(),
            "_sk".to_owned(),
            "_pk".to_owned(),
        ]);
        let encoded = serialize_tagged_label(id, Some(&tags), Some(128))?.ok_or_else(|| {
            crate::HError::Default("binary form must fit within 128 bytes".to_owned())
        })?;
        if encoded.len() > 128 {
            return Err(crate::HError::Default(format!(
                "binary label exceeds the HSM limit: {} bytes",
                encoded.len()
            )));
        }
        let (roundtrip_id, roundtrip_tags) = deserialize_tagged_label(encoded)?;
        if roundtrip_id.as_bytes() != id.as_slice() {
            return Err(crate::HError::Default("id did not round-trip".to_owned()));
        }
        if roundtrip_tags != tags {
            return Err(crate::HError::Default("tags did not round-trip".to_owned()));
        }
        Ok(())
    }

    #[test]
    fn plain_label_remains_compatible() {
        assert_eq!(
            deserialize_tagged_label(b"key-id".to_vec()).ok(),
            Some(("key-id".to_owned(), HashSet::new()))
        );
    }

    #[test]
    fn binary_identifier_falls_back_to_utf8_hex_label() {
        assert_eq!(utf8_label(&[0x00, 0xFF]), b"00ff");
    }
}

mod aes;
mod ec;
mod eddsa;
mod message_aead;
mod message_sign;
mod rsa;

mod session_impl;
pub(crate) use ec::{curve_byte_size, curve_from_der_oid};
pub use rsa::RsaOaepDigest;
pub use session_impl::{
    AesKeySize, DerivedKeySpec, HkdfParams, HsmEncryptionAlgorithm, HsmSigningAlgorithm,
    RsaKeySize, Session,
};

//! This is the replacement for the deprecated structs that used to be within `cloudproof_findex`.
use cosmian_findex::KEY_LENGTH;

pub const FINDEX_KEY_LENGTH: usize = KEY_LENGTH; // Keep consistent name with KMS code.
pub const CUSTOM_WORD_LENGTH: usize = 200; // Findex's KMS specialization. Can be tuned.

/// Implements the needed functionalities out of a byte-vector.
///
/// # Parameters
///
/// - `type_name`   : name of the byte-vector type
macro_rules! impl_byte_vector {
    ($type_name:ty) => {
        impl AsRef<[u8]> for $type_name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<'a> From<&'a [u8]> for $type_name {
            fn from(bytes: &'a [u8]) -> Self {
                Self(bytes.to_vec())
            }
        }

        impl From<Vec<u8>> for $type_name {
            fn from(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
        }

        impl From<&str> for $type_name {
            fn from(bytes: &str) -> Self {
                bytes.as_bytes().into()
            }
        }

        impl From<$type_name> for Vec<u8> {
            fn from(var: $type_name) -> Self {
                var.0
            }
        }
    };
}

/// A [`Keyword`] is a byte vector used to index other values.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Keyword(Vec<u8>);

impl_byte_vector!(Keyword);

// An [`IndexedValue`] is a byte vector that is indexed by a [`Keyword`]
// with a [`Findex`] instance.
// Please note :
// - Do not confuse this struct with the `cloudproof_findex::IndexedValue` which is deprecated.
// The only thing they share is the name. This type wasn't renamed this way not to refer to the previous implementation, but rather to
// avoid confusion with `redis::Value`, `serde_json::Value`, etc.
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct IndexedValue(Vec<u8>);
impl_byte_vector!(IndexedValue);

// Iterating over the contained bytes is needed for findex operations.
// This implementations allows performing a single-element operations.
impl IntoIterator for IndexedValue {
    type IntoIter = std::iter::Once<IndexedValue>;
    type Item = IndexedValue;

    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self)
    }
}

//! This module provides the necessary structures needed to use Findex with Redis on the KMS.

use std::ops::Deref;

use cosmian_findex::{Findex, KEY_LENGTH, MemoryEncryptionLayer};
use cosmian_sse_memories::{ADDRESS_LENGTH, Address, RedisMemory};
use tiny_keccak::{Hasher, Sha3};
pub(crate) const FINDEX_KEY_LENGTH: usize = KEY_LENGTH; // Keep consistent name with KMS code.
pub(crate) const CUSTOM_WORD_LENGTH: usize = 200; // Findex's KMS specialization. Can be tuned.

// IMPORTANT: below is the length of the master key used to derive the findex and db keys. IT'S NOT THE FINDEX KEY LENGTH.
pub(crate) const REDIS_WITH_FINDEX_MASTER_KEY_LENGTH: usize = 32;

/// Findex implementation using Redis in the memory layer.
pub(crate) type FindexRedis = Findex<
    CUSTOM_WORD_LENGTH,
    IndexedValue,
    String,
    MemoryEncryptionLayer<
        CUSTOM_WORD_LENGTH,
        RedisMemory<Address<ADDRESS_LENGTH>, [u8; CUSTOM_WORD_LENGTH]>,
    >,
>;

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

        impl Deref for $type_name {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
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

// Legacy hashing function kept for compatibility with existing indexes.
impl Keyword {
    /// Number of bytes used to hash keywords.
    pub const HASH_LENGTH: usize = 32;

    /// Hash this keyword using SHA3-256.
    #[must_use]
    pub fn hash(&self) -> [u8; Self::HASH_LENGTH] {
        let mut hasher = Sha3::v256();
        hasher.update(self);
        let mut bytes = [0; Self::HASH_LENGTH];
        hasher.finalize(&mut bytes);
        bytes
    }
}

/// An [`IndexedValue`] is a byte vector that is indexed by a [`Keyword`]
/// within a Findex's instance.
///
/// Do not confuse this struct with the `cloudproof_findex::IndexedValue` which is deprecated.
/// The only thing they share is the name. This type wasn't renamed this way not to refer
/// to the previous implementation, but rather to avoid confusion with `redis::Value`,
/// `serde_json::Value`, etc.
#[derive(Clone, Debug, Hash, Default, PartialEq, Eq)]
pub struct IndexedValue(Vec<u8>);

impl_byte_vector!(IndexedValue);

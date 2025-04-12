use std::ops::Deref;

use num_bigint_dig::{BigInt, BigUint, Sign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Holds a big integer secret information. Wraps around `BigInt` type which is
/// essentially a pointer on the heap. Guarantees to be zeroized on drop with
/// feature `zeroize` enabled from `num_bigint_dig` crate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafeBigInt(BigInt);

impl SafeBigInt {
    /// Creates a new `SafeBigInt` from raw bytes encoded in big endian.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(BigInt::from_bytes_be(Sign::Plus, bytes))
    }
}

impl Drop for SafeBigInt {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<BigInt> for SafeBigInt {
    fn from(value: BigInt) -> Self {
        Self(value)
    }
}

impl From<SafeBigInt> for BigInt {
    fn from(value: SafeBigInt) -> Self {
        value.0.clone()
    }
}

impl From<BigUint> for SafeBigInt {
    fn from(value: BigUint) -> Self {
        Self(value.into())
    }
}

impl Deref for SafeBigInt {
    type Target = BigInt;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

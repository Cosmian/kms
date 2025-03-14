use std::ops::Deref;

use num_bigint_dig::BigInt;
use serde::Deserialize;
use zeroize::Zeroize;

/// Holds a big integer secret information. Wraps around `BigInt` type which is
/// essentially a pointer on the heap. Guarantees to be zeroized on drop with
/// feature `zeroize` enabled from `num_bigint_dig` crate.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize)]
pub struct SafeBigInt(BigInt);

impl SafeBigInt {
    /// Creates a new `SafeBigInt` from raw bytes encoded in big endian.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(BigInt::from_signed_bytes_be(bytes))
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

impl Deref for SafeBigInt {
    type Target = BigInt;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

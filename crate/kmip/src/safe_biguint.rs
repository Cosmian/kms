use std::ops::Deref;

use num_bigint_dig::BigUint;
use serde::Deserialize;
use zeroize::Zeroize;

/// Holds a big integer secret information. Wraps around `BigUint` type which is
/// essentially a pointer on the heap. Guarantees to be zeroized on drop with
/// feature `zeroize` enabled from `num_bigint_dig` crate.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize)]
pub struct SafeBigUint(BigUint);

impl SafeBigUint {
    /// Creates a new `SafeBigUint` from raw bytes encoded in big endian.
    #[must_use]
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }
}

impl Drop for SafeBigUint {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<BigUint> for SafeBigUint {
    fn from(value: BigUint) -> Self {
        Self(value)
    }
}

impl Deref for SafeBigUint {
    type Target = BigUint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

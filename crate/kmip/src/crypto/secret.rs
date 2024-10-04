use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use num_bigint_dig::BigUint;
use openssl::rand::rand_bytes;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::KmipError;

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

/// Holds a secret information of `LENGTH` bytes.
///
/// This secret is stored on the heap and is guaranteed to be zeroized on drop.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Secret<const LENGTH: usize>(Pin<Box<[u8; LENGTH]>>);

impl<const LENGTH: usize> Secret<LENGTH> {
    /// Creates a new secret and returns it.
    ///
    /// All bytes are initially set to 0.
    #[must_use]
    #[allow(unsafe_code)]
    pub fn new() -> Self {
        // heap-allocate and turn into `Box` but looses `LENGTH`-constraint in type
        let data = vec![0_u8; LENGTH].into_boxed_slice();
        // cast the raw pointer back to our fixed-length type
        // it is considered safe because `data` is initialized in the previous line
        let data = unsafe { Box::from_raw(Box::into_raw(data).cast::<[u8; LENGTH]>()) };
        Self(Pin::new(data))
    }

    /// Creates a new random secret.
    pub fn new_random() -> Result<Self, KmipError> {
        let mut secret = Self::new();
        rand_bytes(&mut secret)?;
        Ok(secret)
    }

    /// Returns the bytes of the secret.
    ///
    /// # Safety
    ///
    /// Once returned the secret bytes are *not* protected. It is the caller's
    /// responsibility to guarantee they are not leaked in the memory.
    pub fn to_unprotected_bytes(&self, dest: &mut [u8; LENGTH]) {
        dest.copy_from_slice(self);
    }

    /// Creates a secret from the given unprotected bytes, and zeroizes the
    /// source bytes.
    ///
    /// Do not take ownership of the bytes to avoid stack copying.
    pub fn from_unprotected_bytes(bytes: &mut [u8; LENGTH]) -> Self {
        let mut secret = Self::new();
        secret.copy_from_slice(bytes.as_slice());
        bytes.zeroize();
        secret
    }
}

impl<const LENGTH: usize> Default for Secret<LENGTH> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> Deref for Secret<LENGTH> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<const LENGTH: usize> DerefMut for Secret<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl<const LENGTH: usize> Zeroize for Secret<LENGTH> {
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize();
    }
}

impl<const LENGTH: usize> Drop for Secret<LENGTH> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Secret<LENGTH> {}

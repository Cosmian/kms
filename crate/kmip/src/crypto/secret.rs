use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use num_bigint_dig::BigUint;
use openssl::rand::rand_bytes;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "ser")]
use crate::bytes_ser_de::Serializable;
use crate::error::KmipError;

/// Holds a big integer secret information. Wraps around `BigUint` type which is
/// essentially a pointer on the heap. Guarantees to be zeroized on drop with
/// feature `zeroize` enabled from `num_bigint_dig` crate.
#[derive(Debug, Eq, PartialEq, Clone, Deserialize)]
pub struct SafeBigUint(BigUint);

impl SafeBigUint {
    /// Creates a new `SafeBigUint` from raw bytes encoded in big endian.
    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }
}

impl Drop for SafeBigUint {
    fn drop(&mut self) {
        self.0.zeroize()
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
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self(Box::pin([0; LENGTH]))
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
    #[inline(always)]
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
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<const LENGTH: usize> Deref for Secret<LENGTH> {
    type Target = [u8];

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl<const LENGTH: usize> DerefMut for Secret<LENGTH> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut *self.0
    }
}

impl<const LENGTH: usize> Zeroize for Secret<LENGTH> {
    #[inline(always)]
    fn zeroize(&mut self) {
        self.0.deref_mut().zeroize();
    }
}

impl<const LENGTH: usize> Drop for Secret<LENGTH> {
    #[inline(always)]
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const LENGTH: usize> ZeroizeOnDrop for Secret<LENGTH> {}

#[cfg(feature = "ser")]
impl<const LENGTH: usize> Serializable for Secret<LENGTH> {
    type Error = CryptoCoreError;

    #[inline(always)]
    fn length(&self) -> usize {
        LENGTH
    }

    #[inline(always)]
    fn write(&self, ser: &mut crate::bytes_ser_de::Serializer) -> Result<usize, Self::Error> {
        ser.write_array(self)
    }

    #[inline(always)]
    fn read(de: &mut crate::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let mut bytes = de.read_array::<LENGTH>()?;
        Ok(Self::from_unprotected_bytes(&mut bytes))
    }
}

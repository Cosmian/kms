use std::{
    ops::{Deref, DerefMut},
    pin::Pin,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Holds secret information of `LENGTH` bytes.
///
/// This secret is stored on the heap and is guaranteed to be zeroized on drop.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Secret<const LENGTH: usize>(Pin<Box<[u8]>>);

impl<const LENGTH: usize> Secret<LENGTH> {
    /// Creates a new secret and returns it.
    ///
    /// All bytes are initially set to 0.
    #[must_use]
    pub fn new() -> Self {
        // `vec!` allocates the zeroed buffer directly on the heap; `[0; LENGTH]` would be built on
        // the stack first and overflow it for large `LENGTH`.
        Self(Pin::new(vec![0_u8; LENGTH].into_boxed_slice()))
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
        &self.0
    }
}

impl<const LENGTH: usize> DerefMut for Secret<LENGTH> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
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

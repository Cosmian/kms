// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.

use std::hash::Hash;

use zeroize::Zeroizing;

use crate::{ModuleResult, traits::KeyAlgorithm};

pub trait SymmetricKey: Send + Sync {
    /// The unique identifier of the key (in the KMS)
    fn remote_id(&self) -> String;

    /// Returns the algorithm of the key; will fail if only the remote part is known
    fn algorithm(&self) -> KeyAlgorithm;

    /// Return the key size in bits
    fn key_size(&self) -> usize;

    /// Return raw bytes
    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>>;
}

impl std::fmt::Debug for dyn SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("remote id", &self.remote_id())
            .finish_non_exhaustive()
    }
}

impl PartialEq for dyn SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.remote_id() == other.remote_id()
    }
}

impl Eq for dyn SymmetricKey {}

impl Hash for dyn SymmetricKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_id().hash(state);
    }
}

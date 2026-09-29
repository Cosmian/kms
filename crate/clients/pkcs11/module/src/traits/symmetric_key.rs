// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.

use zeroize::Zeroizing;

use crate::{ModuleResult, traits::KeyAlgorithm};

pub trait SymmetricKey: Send + Sync {
    /// The unique identifier of the key (in the KMS)
    fn remote_id(&self) -> &str;

    /// Returns the algorithm of the key; will fail if only the remote part is known
    fn algorithm(&self) -> KeyAlgorithm;

    /// Return the key size in bits
    fn key_size(&self) -> usize;

    /// Return raw bytes
    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>>;
}

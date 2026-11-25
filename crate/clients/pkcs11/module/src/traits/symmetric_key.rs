// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.

use zeroize::Zeroizing;

use crate::{
    ModuleResult,
    traits::{KeyAlgorithm, KeyProtection},
};

pub trait SymmetricKey: Send + Sync {
    /// The unique identifier of the key (in the KMS)
    fn remote_id(&self) -> &str;

    /// Returns the algorithm of the key; will fail if only the remote part is known
    fn algorithm(&self) -> KeyAlgorithm;

    /// Return the key size in bits
    fn key_size(&self) -> usize;

    /// Return raw bytes
    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>>;

    /// Sensitive/extractable attributes of the key in the KMS (drive `CKA_SENSITIVE`,
    /// `CKA_EXTRACTABLE` and whether `CKA_VALUE` may be returned).
    fn protection(&self) -> KeyProtection {
        KeyProtection::default()
    }

    /// Whether the key's KMIP usage mask allows `MACGenerate` (reported as `CKA_SIGN`).
    fn can_generate_mac(&self) -> bool {
        false
    }

    /// Whether the key's KMIP usage mask allows `MACVerify` (reported as `CKA_VERIFY`).
    fn can_verify_mac(&self) -> bool {
        false
    }
}

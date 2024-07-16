// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
//Original code:
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::hash::Hash;

use zeroize::Zeroizing;

use crate::{
    traits::{KeyAlgorithm, SignatureAlgorithm},
    MResult,
};

pub trait PrivateKey: Send + Sync {
    /// The unique identifier of the key (in the KMS)
    fn remote_id(&self) -> String;

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> MResult<Vec<u8>>;

    /// Returns the algorithm of the key; will fail if only the remote part is known
    fn algorithm(&self) -> KeyAlgorithm;

    /// Return the key size in bits
    fn key_size(&self) -> usize;

    /// Return the DER bytes of the private key
    /// This is a lazy loaded value
    fn pkcs8_der_bytes(&self) -> MResult<Zeroizing<Vec<u8>>>;

    /// Return the RSA public exponent if the key is an RSA key
    /// In big endian
    fn rsa_public_exponent(&self) -> MResult<Vec<u8>>;
}

impl std::fmt::Debug for dyn PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("remote id", &self.remote_id())
            .finish_non_exhaustive()
    }
}

impl PartialEq for dyn PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.remote_id() == other.remote_id()
    }
}

impl Eq for dyn PrivateKey {}

impl Hash for dyn PrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_id().hash(state);
    }
}

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

use std::{any::Any, hash::Hash};

use pkcs1::RsaPrivateKey;

use crate::{
    core::compoundid::Id,
    traits::{KeyAlgorithm, SignatureAlgorithm},
    MResult,
};

pub trait PrivateKey: Send + Sync {
    fn private_key_id(&self) -> &str;

    fn label(&self) -> String {
        "PrivateKey".to_string()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> MResult<Vec<u8>>;

    /// Returns the algorithm of the key; will fail if only the remote part is known
    fn algorithm(&self) -> KeyAlgorithm;

    /// ID used as CKA_ID when searching objects by ID
    fn id(&self) -> Id {
        Id {
            label: self.label(),
            hash: self.private_key_id().as_bytes().to_vec(),
        }
    }

    /// Return the key size in bits
    fn key_size(&self) -> usize;

    /// Return the RSA private key if the key is an RSA key
    fn rsa_private_key(&self) -> MResult<RsaPrivateKey>;

    /// Return the RSA public exponent if the key is an RSA key
    /// In big endian
    fn rsa_public_exponent(&self) -> MResult<Vec<u8>>;

    /// Return the EC P256 private key if the key is an EC key
    fn ec_p256_private_key(&self) -> MResult<p256::SecretKey>;
}

impl std::fmt::Debug for dyn PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("label", &self.label())
            .finish_non_exhaustive()
    }
}

impl PartialEq for dyn PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.private_key_id() == other.private_key_id() && self.label() == other.label()
    }
}

impl Eq for dyn PrivateKey {}

impl Hash for dyn PrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.private_key_id().hash(state);
        self.label().hash(state);
    }
}

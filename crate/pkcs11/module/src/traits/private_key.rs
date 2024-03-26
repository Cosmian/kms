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

use std::{any::Any, hash::Hash, sync::Arc};

use crate::{
    traits::{Backend, Digest, KeyAlgorithm, PublicKey, SearchOptions, SignatureAlgorithm},
    Result,
};

pub trait PrivateKey: Send + Sync {
    fn public_key_hash(&self) -> Vec<u8>;
    fn label(&self) -> String;
    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> Result<Vec<u8>>;
    fn delete(&self);
    fn algorithm(&self) -> KeyAlgorithm;
    fn find_public_key(&self, backend: &dyn Backend) -> Result<Option<Arc<dyn PublicKey>>> {
        let pubkey_hash: Digest = self.public_key_hash().as_slice().try_into()?;
        backend.find_public_key(SearchOptions::Hash(pubkey_hash))
    }
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
        self.public_key_hash() == other.public_key_hash() && self.label() == other.label()
    }
}

impl Eq for dyn PrivateKey {}

impl Hash for dyn PrivateKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.public_key_hash().hash(state);
        self.label().hash(state);
    }
}

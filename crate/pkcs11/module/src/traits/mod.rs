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

pub use backend::{backend, register_backend, Backend};
pub use certificate::Certificate;
pub use data_object::DataObject;
pub use once_cell;
pub use private_key::PrivateKey;

use crate::{
    core::{
        attribute::{Attribute, AttributeType, Attributes},
        compoundid,
    },
    Error, Result,
};

mod backend;
mod certificate;
mod data_object;
mod private_key;

pub type Digest = [u8; 20];

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DigestType {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl DigestType {
    pub fn digest_len(&self) -> usize {
        match self {
            DigestType::Sha1 => 20,
            DigestType::Sha224 => 28,
            DigestType::Sha256 => 32,
            DigestType::Sha384 => 48,
            DigestType::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SignatureAlgorithm {
    Ecdsa,
    RsaRaw,
    RsaPkcs1v15Raw,
    RsaPkcs1v15Sha1,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha512,
    RsaPss {
        digest: DigestType,
        mask_generation_function: DigestType,
        salt_length: u64,
    },
}

pub trait PublicKey: Send + Sync + std::fmt::Debug {
    fn public_key_hash(&self) -> Vec<u8>;
    fn label(&self) -> String;
    fn to_der(&self) -> Vec<u8>;
    fn verify(&self, algorithm: &SignatureAlgorithm, data: &[u8], signature: &[u8]) -> Result<()>;
    fn delete(self: Arc<Self>);
    fn algorithm(&self) -> KeyAlgorithm;
}

impl PartialEq for dyn PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key_hash() == other.public_key_hash() && self.label() == other.label()
    }
}

impl Eq for dyn PublicKey {}

impl Hash for dyn PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.public_key_hash().hash(state);
        self.label().hash(state);
    }
}

#[derive(Debug)]
pub enum SearchOptions {
    All,
    Label(String),
    Hash(Digest),
}

impl TryFrom<&Attributes> for SearchOptions {
    type Error = Error;

    fn try_from(attributes: &Attributes) -> std::result::Result<Self, Self::Error> {
        if attributes.is_empty() {
            return Ok(SearchOptions::All);
        }
        if let Some(Attribute::Id(id)) = attributes.get(AttributeType::Id) {
            let id = compoundid::decode(id)?;
            Ok(SearchOptions::Hash(id.hash.as_slice().try_into()?))
        } else if let Some(Attribute::Label(label)) = attributes.get(AttributeType::Label) {
            Ok(SearchOptions::Label(label.into()))
        } else {
            Ok(SearchOptions::All)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa,
    Ecc,
}

pub struct Version {
    pub major: u8,
    pub minor: u8,
}

pub fn random_label() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    String::from("bumpkey ")
        + &rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>()
}

// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// Original code:
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

pub use backend::{
    Backend, DecryptContext, EncryptContext, SignContext, backend, clear_backend, invoke_login_fn,
    register_backend, register_login_fn, register_pin_mode, use_pin_as_access_token,
};
pub use certificate::Certificate;
pub use data_object::DataObject;
pub use encryption_algorithms::EncryptionAlgorithm;
pub use key_algorithm::KeyAlgorithm;
pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature_algorithm::SignatureAlgorithm;
pub use symmetric_key::SymmetricKey;

use crate::{
    ModuleError,
    core::attribute::{Attribute, AttributeType, Attributes},
};

mod backend;
mod certificate;
mod data_object;
mod encryption_algorithms;
mod key_algorithm;
mod private_key;
mod public_key;
mod signature_algorithm;
mod symmetric_key;

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
    #[must_use]
    pub const fn digest_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Debug)]
pub enum SearchOptions {
    All,
    /// The PKCS#11 `CKA_ID` converted to UTF-8 at the point of construction,
    /// so consumers never need to call `String::from_utf8` themselves.
    Id(String),
}

impl TryFrom<&Attributes> for SearchOptions {
    type Error = ModuleError;

    fn try_from(attributes: &Attributes) -> Result<Self, Self::Error> {
        if attributes.is_empty() {
            return Ok(Self::All);
        }
        if let Some(Attribute::Id(id)) = attributes.get(AttributeType::Id) {
            Ok(Self::Id(String::from_utf8(id.clone())?))
        } else {
            Ok(Self::All)
        }
    }
}

pub struct Version {
    pub major: u8,
    pub minor: u8,
}

pub fn random_label() -> String {
    use rand::{RngExt, distr::Alphanumeric};
    String::from("bumpkey ")
        + &rand::rng()
            .sample_iter(Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>()
}

/// Generates `PartialEq`, `Eq`, `Hash`, and `Debug` impls for a given PKCS#11 dyn trait
/// whose objects are identified by a `remote_id() -> &str` method. All five object-type
/// traits (`Certificate`, `PrivateKey`, `PublicKey`, `SymmetricKey`, `DataObject`) share
/// this identity pattern, so one macro invocation replaces ~15 lines of boilerplate each.
macro_rules! impl_remote_object_impls {
    ($trait_name:ident) => {
        impl PartialEq for dyn $trait_name {
            fn eq(&self, other: &Self) -> bool {
                self.remote_id() == other.remote_id()
            }
        }
        impl Eq for dyn $trait_name {}
        impl std::hash::Hash for dyn $trait_name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.remote_id().hash(state);
            }
        }
        impl std::fmt::Debug for dyn $trait_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($trait_name))
                    .field("remote_id", &self.remote_id())
                    .finish_non_exhaustive()
            }
        }
    };
}

impl_remote_object_impls!(Certificate);
impl_remote_object_impls!(PrivateKey);
impl_remote_object_impls!(PublicKey);
impl_remote_object_impls!(SymmetricKey);
impl_remote_object_impls!(DataObject);

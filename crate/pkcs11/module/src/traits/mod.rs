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

mod data_object;

use std::{
    any::Any,
    hash::Hash,
    sync::{Arc, RwLock},
};

pub use once_cell;
use once_cell::sync::Lazy;
use x509_cert::der::Decode;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type Digest = [u8; 20];

//  The Backend is first staged so it can be stored in a Box<dyn Backend>. This
//  allows the Backend to be reference with `&'static`.
static STAGED_BACKEND: RwLock<Option<Box<dyn Backend>>> = RwLock::new(None);
static BACKEND: Lazy<Box<dyn Backend>> =
    Lazy::new(|| STAGED_BACKEND.write().unwrap().take().unwrap());

/// Stores a backend to later be returned by all calls `crate::backend()`.
pub fn register_backend(backend: Box<dyn Backend>) {
    *STAGED_BACKEND.write().unwrap() = Some(backend);
}

pub fn backend() -> &'static dyn Backend {
    BACKEND.as_ref()
}

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

pub trait Certificate: Send + Sync + std::fmt::Debug {
    fn label(&self) -> String;
    fn to_der(&self) -> Vec<u8>;
    fn public_key(&self) -> &dyn PublicKey;
    fn delete(self: Box<Self>);
    fn algorithm(&self) -> KeyAlgorithm {
        self.public_key().algorithm()
    }
}

impl PartialEq for dyn Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.to_der() == other.to_der() && self.label() == other.label()
    }
}

impl Eq for dyn Certificate {}

impl Hash for dyn Certificate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.type_id().hash(state);
        self.to_der().hash(state);
        self.label().hash(state);
    }
}

pub trait CertificateExt: Certificate {
    fn issuer(&self) -> Vec<u8> {
        let der = self.to_der();
        let c = x509_cert::Certificate::from_der(&der).unwrap();
        x509_cert::der::Encode::to_der(&c.tbs_certificate.issuer).unwrap()
    }

    fn serial_number(&self) -> Vec<u8> {
        let der = self.to_der();
        let c = x509_cert::Certificate::from_der(&der).unwrap();
        x509_cert::der::Encode::to_der(&c.tbs_certificate.serial_number).unwrap()
    }

    fn subject(&self) -> Vec<u8> {
        let der = self.to_der();
        let c = x509_cert::Certificate::from_der(&der).unwrap();
        x509_cert::der::Encode::to_der(&c.tbs_certificate.subject).unwrap()
    }
}

impl<T: Certificate + ?Sized> CertificateExt for T {}

// The Data object Trait
pub use data_object::DataObject;

#[derive(Debug)]
pub enum SearchOptions {
    //  TODO(kcking): search keys by _both_ label and public key hash as that is how
    //  they are de-duped and referenced.
    Label(String),
    Hash(Digest),
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

pub trait Backend: Send + Sync {
    /// The token label
    /// e.g.
    /// `*b"Foo software token              "`
    fn token_label(&self) -> [u8; 32];
    /// The id of the manufacturer of the token
    fn token_manufacturer_id(&self) -> [u8; 32];
    /// The model of the token
    fn token_model(&self) -> [u8; 16];
    /// The serial number of the token
    fn token_serial_number(&self) -> [u8; 16];
    /// The description of this library
    fn library_description(&self) -> [u8; 32];
    /// The version of this library
    fn library_version(&self) -> Version;

    fn find_certificate(&self, query: SearchOptions) -> Result<Option<Arc<dyn Certificate>>>;
    fn find_all_certificates(&self) -> Result<Vec<Box<dyn Certificate>>>;
    fn find_private_key(&self, query: SearchOptions) -> Result<Option<Arc<dyn PrivateKey>>>;
    fn find_public_key(&self, query: SearchOptions) -> Result<Option<Arc<dyn PublicKey>>>;
    fn find_all_private_keys(&self) -> Result<Vec<Arc<dyn PrivateKey>>>;
    fn find_all_public_keys(&self) -> Result<Vec<Arc<dyn PublicKey>>>;
    fn find_data_object(&self, query: SearchOptions) -> Result<Option<Arc<dyn DataObject>>>;
    fn find_all_data_objects(&self) -> Result<Vec<Arc<dyn DataObject>>>;
    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> Result<Arc<dyn PrivateKey>>;
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

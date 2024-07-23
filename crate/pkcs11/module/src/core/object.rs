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

use std::{fmt::Debug, sync::Arc};

use p256::pkcs8::{
    der::{asn1::OctetString, Encode},
    AssociatedOid,
};
use pkcs1::{der::Decode, RsaPublicKey};
use pkcs11_sys::{
    CKC_X_509, CKK_EC, CKK_RSA, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PROFILE,
    CKO_PUBLIC_KEY, CK_CERTIFICATE_CATEGORY_UNSPECIFIED, CK_PROFILE_ID,
};
use tracing::debug;

use crate::{
    core::attribute::{Attribute, AttributeType, Attributes},
    traits::{
        backend, Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey, RemoteObjectId,
    },
};

// TODO(bweeks): resolve by improving the ObjectStore implementation.
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Debug, Hash, Eq, Clone)]
pub enum Object {
    Certificate(Arc<dyn Certificate>),
    PrivateKey(Arc<dyn PrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<dyn PublicKey>),
    DataObject(Arc<dyn DataObject>),
    RemoteObjectId(Arc<dyn RemoteObjectId>),
}

//  #[derive(PartialEq)] fails to compile because it tries to move the Box<_>ed
//  values.
//  https://github.com/rust-lang/rust/issues/78808#issuecomment-723304465
impl PartialEq for Object {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Certificate(l0), Self::Certificate(r0)) => l0 == r0,
            (Self::PrivateKey(l0), Self::PrivateKey(r0)) => l0 == r0,
            (Self::Profile(l0), Self::Profile(r0)) => l0 == r0,
            (Self::PublicKey(l0), Self::PublicKey(r0)) => l0 == r0,
            (Self::DataObject(l0), Self::DataObject(r0)) => l0 == r0,
            (Self::RemoteObjectId(l0), Self::RemoteObjectId(r0)) => l0 == r0,
            (
                Self::Certificate(_)
                | Self::PrivateKey(_)
                | Self::Profile(_)
                | Self::PublicKey(_)
                | Self::DataObject(_)
                | Self::RemoteObjectId(_),
                _,
            ) => false,
        }
    }
}

impl Object {
    pub fn attribute(&self, type_: AttributeType) -> Option<Attribute> {
        let attribute = match self {
            Self::Certificate(cert) => match type_ {
                AttributeType::CertificateCategory => Some(Attribute::CertificateCategory(
                    CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
                )),
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(
                    crate::core::compoundid::encode(&crate::core::compoundid::Id {
                        label: Some(cert.label()),
                        hash: cert.public_key().public_key_hash(),
                    })
                    .ok()?,
                )),
                AttributeType::Issuer => cert.issuer().map(Attribute::Issuer).ok(),
                AttributeType::Label => Some(Attribute::Label(cert.label())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Trusted => Some(Attribute::Trusted(false)),
                AttributeType::SerialNumber => {
                    cert.serial_number().map(Attribute::SerialNumber).ok()
                }
                AttributeType::Subject => cert.subject().map(Attribute::Subject).ok(),
                AttributeType::Value => cert.to_der().map(Attribute::Value).ok(),
                _ => {
                    debug!("certificate: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Self::PrivateKey(private_key) => match type_ {
                AttributeType::AlwaysSensitive => Some(Attribute::AlwaysSensitive(true)),
                AttributeType::AlwaysAuthenticate => Some(Attribute::AlwaysAuthenticate(false)),
                AttributeType::Class => Some(Attribute::Class(CKO_PRIVATE_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(false)),
                AttributeType::EcParams => {
                    Some(Attribute::EcParams(p256::NistP256::OID.to_der().ok()?))
                }
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(
                    crate::core::compoundid::encode(&crate::core::compoundid::Id {
                        label: Some(private_key.label()),
                        hash: private_key.public_key_id(),
                    })
                    .ok()?,
                )),
                AttributeType::KeyType => Some(Attribute::KeyType(match private_key.algorithm() {
                    KeyAlgorithm::Rsa => CKK_RSA,
                    KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Modulus => {
                    let modulus = private_key
                        .find_public_key(backend())
                        .ok()
                        .flatten()
                        .and_then(|public_key| {
                            let der = public_key.to_der();
                            RsaPublicKey::from_der(&der)
                                .map(|pk| pk.modulus.as_bytes().to_vec())
                                .ok()
                        });
                    modulus.map(Attribute::Modulus)
                }
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PublicExponent => {
                    let public_exponent = private_key
                        .find_public_key(backend())
                        .ok()
                        .flatten()
                        .and_then(|public_key| {
                            let der = public_key.to_der();
                            RsaPublicKey::from_der(&der)
                                .map(|pk| pk.public_exponent.as_bytes().to_vec())
                                .ok()
                        });
                    public_exponent.map(Attribute::PublicExponent)
                }
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(false)),
                _ => {
                    debug!("private_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Self::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                _ => {
                    debug!("profile: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Self::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Modulus => {
                    let key = pk.to_der();
                    let key = RsaPublicKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.modulus.as_bytes().to_vec()))
                }
                AttributeType::PublicExponent => {
                    let key = pk.to_der();
                    let key = RsaPublicKey::from_der(&key).unwrap();
                    Some(Attribute::Modulus(key.public_exponent.as_bytes().to_vec()))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(match pk.algorithm() {
                    KeyAlgorithm::Rsa => CKK_RSA,
                    KeyAlgorithm::Ecc => CKK_EC,
                })),
                AttributeType::Id => Some(Attribute::Id(
                    crate::core::compoundid::encode(&crate::core::compoundid::Id {
                        label: Some(pk.label()),
                        hash: pk.public_key_hash(),
                    })
                    .ok()?,
                )),
                AttributeType::EcPoint => {
                    if pk.algorithm() != KeyAlgorithm::Ecc {
                        return None;
                    }
                    let wrapped = OctetString::new(pk.to_der()).ok()?;
                    Some(Attribute::EcPoint(wrapped.to_der().ok()?))
                }
                AttributeType::EcParams => {
                    Some(Attribute::EcParams(p256::NistP256::OID.to_der().ok()?))
                }
                _ => {
                    debug!("public_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Self::DataObject(data) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_DATA)),
                AttributeType::Id => Some(Attribute::Id(
                    crate::core::compoundid::encode(&crate::core::compoundid::Id {
                        label: Some(data.label()),
                        hash: data.data_hash(),
                    })
                    .ok()?,
                )),
                // TODO(BGR) we should hold zeroizable values here
                AttributeType::Value => Some(Attribute::Value(data.value().to_vec())),
                AttributeType::Application => Some(Attribute::Application(data.application())),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::Label => Some(Attribute::Label(data.label())),
                _ => {
                    debug!("Data object: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Self::RemoteObjectId(remote_object_id) => {
                if type_ == AttributeType::Id {
                    Some(Attribute::Id(
                        remote_object_id.remote_id().as_bytes().to_vec(),
                    ))
                } else {
                    debug!("Remote object id: type_ unimplemented: {:?}", type_);
                    None
                }
            }
        };
        debug!("attribute: {:?} => {:?}", type_, attribute);
        attribute
    }

    #[must_use]
    pub fn matches(&self, others: &Attributes) -> bool {
        if let Some(class) = others.get(AttributeType::Class) {
            if *class != self.attribute(AttributeType::Class).unwrap() {
                return false;
            }
        }
        for other in &**others {
            if let Some(attr) = self.attribute(other.attribute_type()) {
                if *other != attr {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    }
}

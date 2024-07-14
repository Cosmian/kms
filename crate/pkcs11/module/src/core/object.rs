// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// This :
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

use std::sync::Arc;

use log::error;
use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::der::Encode};
use pkcs11_sys::{
    CKC_X_509, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PROFILE, CKO_PUBLIC_KEY,
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED, CK_PROFILE_ID,
};
use tracing::debug;

use crate::{
    core::{
        attribute::{Attribute, AttributeType},
        compoundid::Id,
    },
    traits::{Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey},
    MResult,
};

#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(Hash, Eq, Clone)]
pub enum Object {
    Certificate(Arc<dyn Certificate>),
    PrivateKey(Arc<dyn PrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<dyn PublicKey>),
    DataObject(Arc<dyn DataObject>),
    // RemoteObjectId(Arc<dyn RemoteObjectId>),
}

impl Object {
    pub fn id(&self) -> MResult<Id> {
        match self {
            Object::Certificate(cert) => cert.id(),
            Object::PrivateKey(private_key) => Ok(private_key.id()),
            Object::Profile(id) => Ok(Id {
                label: "Profile".to_string(),
                hash: id.to_be_bytes().to_vec(),
            }),
            Object::PublicKey(public_key) => Ok(public_key.id()),
            Object::DataObject(data) => Ok(data.id()),
            // Object::RemoteObjectId(remote_object_id) => Ok(remote_object_id.id()),
        }
    }
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
            // (Self::RemoteObjectId(l0), Self::RemoteObjectId(r0)) => l0 == r0,
            (
                Self::Certificate(_)
                | Self::PrivateKey(_)
                | Self::Profile(_)
                | Self::PublicKey(_)
                | Self::DataObject(_),
                // | Self::RemoteObjectId(_),
                _,
            ) => false,
        }
    }
}

impl Object {
    pub fn name(&self) -> String {
        match self {
            Object::Certificate(_) => "Certificate",
            Object::PrivateKey(_) => "Private Key",
            Object::Profile(_) => "Profile",
            Object::PublicKey(_) => "Public Key",
            Object::DataObject(_) => "Data Object",
            // Object::RemoteObjectId(_) => "Remote Object ID",
        }
        .to_string()
    }

    pub fn attribute(&self, type_: AttributeType) -> MResult<Option<Attribute>> {
        let attribute = match self {
            Object::Certificate(cert) => match type_ {
                AttributeType::CertificateCategory => Some(Attribute::CertificateCategory(
                    CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
                )),
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(cert.id()?.encode()?)),
                AttributeType::Issuer => cert.issuer().map(Attribute::Issuer).ok(),
                AttributeType::Label => Some(Attribute::Label(cert.label())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Trusted => Some(Attribute::Trusted(false)),
                AttributeType::SerialNumber => {
                    cert.serial_number().map(Attribute::SerialNumber).ok()
                }
                AttributeType::Subject => cert.subject().map(Attribute::Subject).ok(),
                AttributeType::Value => cert.to_der().map(Attribute::Value).ok(),
                AttributeType::Decrypt => Some(Attribute::Decrypt(false)),
                AttributeType::Modulus => {
                    Some(Attribute::Modulus(cert.public_key()?.rsa_modulus()?))
                }
                AttributeType::PublicExponent => Some(Attribute::PublicExponent(
                    cert.public_key()?.rsa_public_exponent()?,
                )),
                _ => {
                    error!("certificate: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PrivateKey(private_key) => match type_ {
                AttributeType::AlwaysSensitive => Some(Attribute::AlwaysSensitive(true)),
                AttributeType::AlwaysAuthenticate => Some(Attribute::AlwaysAuthenticate(false)),
                AttributeType::Class => Some(Attribute::Class(CKO_PRIVATE_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(true)),
                AttributeType::EcParams => {
                    let algorithm = private_key.algorithm();
                    match algorithm {
                        KeyAlgorithm::EccP256
                        | KeyAlgorithm::EccP384
                        | KeyAlgorithm::EccP521
                        | KeyAlgorithm::X25519 {}
                        | KeyAlgorithm::Ed25519
                        | KeyAlgorithm::X448
                        | KeyAlgorithm::Ed448 => Some(Attribute::EcParams(
                            private_key.algorithm().to_oid()?.to_der()?,
                        )),
                        _ => None,
                    }
                }
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(private_key.id().encode()?)),
                AttributeType::KeyType => {
                    Some(Attribute::KeyType(private_key.algorithm().to_ck_key_type()))
                }
                AttributeType::Label => Some(Attribute::Label(private_key.label())),
                AttributeType::Modulus => Some(Attribute::Modulus(
                    private_key.key_size().to_be_bytes().to_vec(),
                )),
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PublicExponent => Some(Attribute::PublicExponent(
                    private_key.rsa_public_exponent()?.to_vec(),
                )),
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(false)),
                _ => {
                    error!("private_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                _ => {
                    error!("profile: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Label => Some(Attribute::Label(pk.label())),
                AttributeType::Modulus => Some(Attribute::Modulus(pk.rsa_modulus()?)),
                AttributeType::PublicExponent => {
                    Some(Attribute::PublicExponent(pk.rsa_public_exponent()?))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(pk.algorithm().to_ck_key_type())),
                AttributeType::Id => Some(Attribute::Id(pk.id().encode()?)),
                AttributeType::EcPoint => {
                    if !pk.algorithm().is_ecc() {
                        return Ok(None);
                    }
                    Some(Attribute::EcPoint(
                        pk.ec_p256_public_key()?
                            .to_encoded_point(false)
                            .to_bytes()
                            .to_vec(),
                    ))
                }
                AttributeType::EcParams => {
                    if !pk.algorithm().is_ecc() {
                        return Ok(None);
                    }
                    Some(Attribute::EcParams(pk.algorithm().to_oid()?.to_der()?))
                }
                _ => {
                    error!("public_key: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            Object::DataObject(data) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_DATA)),
                AttributeType::Id => Some(Attribute::Id(data.id().encode()?)),
                // TODO(BGR) should we hold zeroizable values here ?
                AttributeType::Value => Some(Attribute::Value(data.value().to_vec())),
                AttributeType::Application => Some(Attribute::Application(data.application())),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::Label => Some(Attribute::Label(data.label())),
                _ => {
                    error!("Data object: type_ unimplemented: {:?}", type_);
                    None
                }
            },
            // Object::RemoteObjectId(remote_object_id) => match type_ {
            //     AttributeType::Id => Some(Attribute::Id(remote_object_id.id().encode()?)),
            //     AttributeType::Decrypt => match remote_object_id.remote_type() {
            //         RemoteObjectType::PrivateKey | RemoteObjectType::SymmetricKey => {
            //             Some(Attribute::Decrypt(true))
            //         }
            //         _ => Some(Attribute::Decrypt(false)),
            //     },
            //     AttributeType::Modulus => Some(Attribute::Modulus(2048_u32.to_be_bytes().to_vec())),
            //     AttributeType::PublicExponent => {
            //         Some(Attribute::PublicExponent(65537_u32.to_be_bytes().to_vec()))
            //     }
            //     AttributeType::Value => {
            //         warn!(
            //             "Requesting value of Remote Object {:?}",
            //             remote_object_id.id()
            //         );
            //         Some(Attribute::Value(vec![]))
            //     }
            //     _ => {
            //         error!("Remote object id: type_ unimplemented: {:?}", type_);
            //         None
            //     }
            // },
        };
        debug!(
            "Object: {}, attribute: {:?} => {:?}",
            self.name(),
            type_,
            attribute
        );
        Ok(attribute)
    }

    // #[must_use]
    // pub fn matches(&self, others: &Attributes) -> bool {
    //     if let Some(class) = others.get(AttributeType::Class) {
    //         if *class != self.attribute(AttributeType::Class).unwrap() {
    //             return false;
    //         }
    //     }
    //     for other in &**others {
    //         if let Some(attr) = self.attribute(other.attribute_type()) {
    //             if *other != attr {
    //                 return false;
    //             }
    //         } else {
    //             return false;
    //         }
    //     }
    //     true
    // }
}

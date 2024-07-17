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
use pkcs1::EncodeRsaPrivateKey;
use pkcs11_sys::{
    CKC_X_509, CKO_CERTIFICATE, CKO_DATA, CKO_PRIVATE_KEY, CKO_PROFILE, CKO_PUBLIC_KEY,
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED, CK_PROFILE_ID,
};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use tracing::debug;

use crate::{
    core::attribute::{Attribute, AttributeType},
    traits::{Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey},
    MError, MResult,
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
    pub fn remote_id(&self) -> String {
        match self {
            Object::Certificate(cert) => cert.remote_id(),
            Object::PrivateKey(private_key) => private_key.remote_id(),
            Object::Profile(id) => id.to_string(),
            Object::PublicKey(public_key) => public_key.remote_id(),
            Object::DataObject(data) => data.remote_id(),
        }
    }

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
                AttributeType::Id => Some(Attribute::Id(cert.remote_id().clone())),
                AttributeType::Issuer => cert.issuer().map(Attribute::Issuer).ok(),
                AttributeType::Label => Some(Attribute::Label("Certificate".to_string())),
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
                AttributeType::Id => Some(Attribute::Id(private_key.remote_id().clone())),
                AttributeType::KeyType => {
                    Some(Attribute::KeyType(private_key.algorithm().to_ck_key_type()))
                }
                AttributeType::Label => Some(Attribute::Label("Private Key".to_string())),
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
                AttributeType::Unwrap => Some(Attribute::Unwrap(true)),
                AttributeType::Value => match private_key.algorithm() {
                    KeyAlgorithm::Rsa => {
                        let der_bytes = private_key.pkcs8_der_bytes()?;
                        RsaPrivateKey::from_pkcs8_der(der_bytes.as_ref())
                            .map(|sk| sk.to_pkcs1_der())
                            .map_err(|e| {
                                error!("Failed to fetch the PKCS1 DER bytes: {:?}", e);
                                MError::Cryptography(
                                    "Failed to fetch the PKCS1 DER bytes".to_string(),
                                )
                            })?
                            .map(|sd| Attribute::Value(sd.as_bytes().to_vec()))
                            .ok()
                    }
                    KeyAlgorithm::EccP256
                    | KeyAlgorithm::EccP384
                    | KeyAlgorithm::EccP521
                    | KeyAlgorithm::Ed25519
                    | KeyAlgorithm::X25519
                    | KeyAlgorithm::X448
                    | KeyAlgorithm::Ed448 => {
                        Some(Attribute::Value(private_key.pkcs8_der_bytes()?.to_vec()))
                    }
                },
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
                AttributeType::Label => Some(Attribute::Label("Public Key".to_string())),
                AttributeType::Modulus => Some(Attribute::Modulus(pk.rsa_modulus()?)),
                AttributeType::PublicExponent => {
                    Some(Attribute::PublicExponent(pk.rsa_public_exponent()?))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(pk.algorithm().to_ck_key_type())),
                AttributeType::Id => Some(Attribute::Id(pk.remote_id().clone())),
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
                AttributeType::Id => Some(Attribute::Id(data.remote_id().clone())),
                // TODO(BGR) should we hold zeroizable values here ?
                AttributeType::Value => Some(Attribute::Value(data.value().to_vec())),
                AttributeType::Application => Some(Attribute::Application(data.application())),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::Label => Some(Attribute::Label("Data Object".to_string())),
                _ => {
                    error!("Data object: type_ unimplemented: {:?}", type_);
                    None
                }
            },
        };
        debug!(
            "Object: {}, attribute: {:?} => {:?}",
            self.name(),
            type_,
            attribute
        );
        Ok(attribute)
    }
}

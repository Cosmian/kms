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

use cosmian_logger::debug;
use log::error;
use openssl::pkey::PKey;
use p256::{
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::der::{Encode, asn1::OctetStringRef},
};
use pkcs11_sys::{
    CK_CERTIFICATE_CATEGORY_UNSPECIFIED, CK_PROFILE_ID, CKC_X_509, CKO_CERTIFICATE, CKO_DATA,
    CKO_PRIVATE_KEY, CKO_PROFILE, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
};

use crate::{
    ModuleError, ModuleResult,
    core::attribute::{Attribute, AttributeType},
    traits::{Certificate, DataObject, KeyAlgorithm, PrivateKey, PublicKey, SymmetricKey},
};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum Object {
    Certificate(Arc<dyn Certificate>),
    PrivateKey(Arc<dyn PrivateKey>),
    Profile(CK_PROFILE_ID),
    PublicKey(Arc<dyn PublicKey>),
    DataObject(Arc<dyn DataObject>),
    SymmetricKey(Arc<dyn SymmetricKey>),
}

#[derive(Debug, Eq, PartialEq)]
pub enum ObjectType {
    Certificate,
    PrivateKey,
    Profile,
    PublicKey,
    DataObject,
    SymmetricKey,
}

impl Object {
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::Certificate(_) => ObjectType::Certificate,
            Self::PrivateKey(_) => ObjectType::PrivateKey,
            Self::Profile(_) => ObjectType::Profile,
            Self::PublicKey(_) => ObjectType::PublicKey,
            Self::DataObject(_) => ObjectType::DataObject,
            Self::SymmetricKey(_) => ObjectType::SymmetricKey,
        }
    }

    #[must_use]
    pub fn remote_id(&self) -> String {
        match self {
            Self::Certificate(cert) => cert.remote_id().to_owned(),
            Self::PrivateKey(private_key) => private_key.remote_id().to_owned(),
            Self::SymmetricKey(symmetric_key) => symmetric_key.remote_id().to_owned(),
            Self::Profile(id) => id.to_string(),
            Self::PublicKey(public_key) => public_key.remote_id().to_owned(),
            Self::DataObject(data) => data.remote_id().to_owned(),
        }
    }

    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Certificate(_) => "Certificate",
            Self::PrivateKey(_) => "Private Key",
            Self::SymmetricKey(_) => "Symmetric Key",
            Self::Profile(_) => "Profile",
            Self::PublicKey(_) => "Public Key",
            Self::DataObject(_) => "Data Object",
        }
        .to_owned()
    }

    #[expect(clippy::too_many_lines)]
    pub fn attribute(&self, type_: AttributeType) -> ModuleResult<Option<Attribute>> {
        let attribute = match self {
            Self::Certificate(cert) => match type_ {
                AttributeType::CertificateCategory => Some(Attribute::CertificateCategory(
                    CK_CERTIFICATE_CATEGORY_UNSPECIFIED,
                )),
                AttributeType::CertificateType => Some(Attribute::CertificateType(CKC_X_509)),
                AttributeType::Class => Some(Attribute::Class(CKO_CERTIFICATE)),
                AttributeType::Id => Some(Attribute::Id(cert.private_key_id().into_bytes())),
                AttributeType::Issuer => cert.issuer().map(Attribute::Issuer).ok(),
                AttributeType::Label => Some(Attribute::Label("Certificate".to_owned())),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Trusted => Some(Attribute::Trusted(true)),
                AttributeType::SerialNumber => {
                    cert.serial_number().map(Attribute::SerialNumber).ok()
                }
                AttributeType::Subject => cert.subject().map(Attribute::Subject).ok(),
                AttributeType::Value => cert.to_der().map(Attribute::Value).ok(),
                AttributeType::Decrypt => Some(Attribute::Decrypt(true)),
                AttributeType::Modulus => {
                    Some(Attribute::Modulus(cert.public_key()?.rsa_modulus()?))
                }
                AttributeType::PublicExponent => Some(Attribute::PublicExponent(
                    cert.public_key()?.rsa_public_exponent()?,
                )),
                _ => {
                    error!("certificate: type_ unimplemented: {type_:?}");
                    None
                }
            },
            Self::SymmetricKey(sym_key) => match type_ {
                AttributeType::AlwaysSensitive => Some(Attribute::AlwaysSensitive(true)),
                AttributeType::Class => Some(Attribute::Class(CKO_SECRET_KEY)),
                AttributeType::Decrypt => Some(Attribute::Decrypt(true)),
                AttributeType::Encrypt => Some(Attribute::Encrypt(true)),
                // Oracle TDE requires CKA_EXTRACTABLE=FALSE for master keys
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => Some(Attribute::Id(sym_key.remote_id().as_bytes().to_vec())),
                AttributeType::KeyType => {
                    Some(Attribute::KeyType(sym_key.algorithm().to_ck_key_type()))
                }
                AttributeType::Label => Some(Attribute::Label("Symmetric Key".to_owned())),
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(false)),
                // Oracle TDE requires CKA_SENSITIVE=TRUE for master keys
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Token => Some(Attribute::Token(true)),
                // Oracle TDE requires CKA_UNWRAP=TRUE to verify master key usability
                AttributeType::Unwrap => Some(Attribute::Unwrap(true)),
                AttributeType::Value => Some(Attribute::Value(sym_key.raw_bytes()?.to_vec())),
                // Oracle TDE requires CKA_WRAP=TRUE to verify master key usability
                AttributeType::Wrap => Some(Attribute::Wrap(true)),
                _ => {
                    error!("symmetric_key: type_ unimplemented: {type_:?}");
                    None
                }
            },
            Self::PrivateKey(private_key) => match type_ {
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
                        | KeyAlgorithm::X25519
                        | KeyAlgorithm::Ed25519
                        | KeyAlgorithm::X448
                        | KeyAlgorithm::Ed448 => Some(Attribute::EcParams(
                            private_key.algorithm().to_oid()?.to_der()?,
                        )),
                        _ => None,
                    }
                }
                AttributeType::Extractable => Some(Attribute::Extractable(false)),
                AttributeType::Id => {
                    Some(Attribute::Id(private_key.remote_id().as_bytes().to_vec()))
                }
                AttributeType::KeyType => {
                    Some(Attribute::KeyType(private_key.algorithm().to_ck_key_type()))
                }
                AttributeType::Label => Some(Attribute::Label("Private Key".to_owned())),
                AttributeType::Modulus => {
                    let der_bytes = private_key.pkcs8_der_bytes()?;
                    let pkey = PKey::private_key_from_der(der_bytes.as_ref()).map_err(|e| {
                        error!("Failed to parse RSA private key from PKCS#8 DER: {e:?}");
                        ModuleError::Cryptography(
                            "Failed to parse RSA private key from PKCS#8 DER".to_owned(),
                        )
                    })?;
                    let rsa = pkey.rsa().map_err(|e| {
                        error!("Failed to extract RSA key parameters: {e:?}");
                        ModuleError::Cryptography("Failed to extract RSA key parameters".to_owned())
                    })?;
                    Some(Attribute::Modulus(rsa.n().to_vec()))
                }
                AttributeType::NeverExtractable => Some(Attribute::NeverExtractable(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                AttributeType::PublicExponent => {
                    let der_bytes = private_key.pkcs8_der_bytes()?;
                    let pkey = PKey::private_key_from_der(der_bytes.as_ref()).map_err(|e| {
                        error!("Failed to parse RSA private key from PKCS#8 DER: {e:?}");
                        ModuleError::Cryptography(
                            "Failed to parse RSA private key from PKCS#8 DER".to_owned(),
                        )
                    })?;
                    let rsa = pkey.rsa().map_err(|e| {
                        error!("Failed to extract RSA key parameters: {e:?}");
                        ModuleError::Cryptography("Failed to extract RSA key parameters".to_owned())
                    })?;
                    Some(Attribute::PublicExponent(rsa.e().to_vec()))
                }
                AttributeType::Sensitive => Some(Attribute::Sensitive(true)),
                AttributeType::Sign => Some(Attribute::Sign(true)),
                AttributeType::SignRecover => Some(Attribute::SignRecover(false)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Unwrap => Some(Attribute::Unwrap(true)),
                AttributeType::Value => match private_key.algorithm() {
                    KeyAlgorithm::Rsa => {
                        let der_bytes = private_key.pkcs8_der_bytes()?;
                        let pkey = PKey::private_key_from_der(der_bytes.as_ref()).map_err(|e| {
                            error!("Failed to parse RSA private key from PKCS#8 DER: {e:?}");
                            ModuleError::Cryptography(
                                "Failed to parse RSA private key from PKCS#8 DER".to_owned(),
                            )
                        })?;
                        let rsa = pkey.rsa().map_err(|e| {
                            error!("Failed to extract RSA key parameters: {e:?}");
                            ModuleError::Cryptography(
                                "Failed to extract RSA key parameters".to_owned(),
                            )
                        })?;

                        rsa.private_key_to_der().map(Attribute::Value).ok()
                    }
                    KeyAlgorithm::EccP256
                    | KeyAlgorithm::Secp224k1
                    | KeyAlgorithm::Secp256k1
                    | KeyAlgorithm::Aes256
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
                    error!("private_key: type_ unimplemented: {type_:?}");
                    None
                }
            },
            Self::Profile(id) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PROFILE)),
                AttributeType::ProfileId => Some(Attribute::ProfileId(*id)),
                AttributeType::Token => Some(Attribute::Token(true)),
                AttributeType::Private => Some(Attribute::Private(true)),
                _ => {
                    error!("profile: type_ unimplemented: {type_:?}");
                    None
                }
            },
            Self::PublicKey(pk) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_PUBLIC_KEY)),
                AttributeType::Label => Some(Attribute::Label("Public Key".to_owned())),
                AttributeType::Modulus => {
                    if !pk.algorithm().is_rsa() {
                        return Ok(None);
                    }
                    Some(Attribute::Modulus(pk.rsa_modulus()?))
                }
                AttributeType::PublicExponent => {
                    if !pk.algorithm().is_rsa() {
                        return Ok(None);
                    }
                    Some(Attribute::PublicExponent(pk.rsa_public_exponent()?))
                }
                AttributeType::KeyType => Some(Attribute::KeyType(pk.algorithm().to_ck_key_type())),
                AttributeType::Id => Some(Attribute::Id(pk.remote_id().as_bytes().to_vec())),
                AttributeType::EcPoint => {
                    if !pk.algorithm().is_ecc() {
                        return Ok(None);
                    }
                    let encoded = pk.ec_p256_public_key()?.to_encoded_point(false);
                    let point_bytes = encoded.as_bytes();
                    // PKCS#11 CKA_EC_POINT must be the DER-encoded ANSI X9.62 ECPoint
                    // (i.e. the raw SEC1 point wrapped in a DER OCTET STRING).
                    let der_point = OctetStringRef::new(point_bytes)
                        .and_then(|s| s.to_der())
                        .map_err(|e| {
                            ModuleError::Cryptography(format!("EC point DER encoding failed: {e}"))
                        })?;
                    Some(Attribute::EcPoint(der_point))
                }
                AttributeType::EcParams => {
                    if !pk.algorithm().is_ecc() {
                        return Ok(None);
                    }
                    Some(Attribute::EcParams(pk.algorithm().to_oid()?.to_der()?))
                }
                _ => {
                    error!("public_key: type_ unimplemented: {type_:?}");
                    None
                }
            },
            Self::DataObject(data) => match type_ {
                AttributeType::Class => Some(Attribute::Class(CKO_DATA)),
                AttributeType::Id => Some(Attribute::Id(data.remote_id().as_bytes().to_vec())),
                // TODO(BGR) should we hold zeroizable values here ?
                AttributeType::Value => Some(Attribute::Value(data.value().to_vec())),
                AttributeType::Application => Some(Attribute::Application(data.application())),
                AttributeType::Private => Some(Attribute::Private(true)),
                // Return the actual object ID as label so callers (e.g. Oracle TDE) can
                // match ORACLE.SECURITY.KM.ENCRYPTION.* labels during C_FindObjects filtering.
                AttributeType::Label => Some(Attribute::Label(data.remote_id().to_owned())),
                _ => {
                    error!("Data object: type_ unimplemented: {type_:?}");
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

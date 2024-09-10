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

use core::ops::Deref;
use std::ffi::CString;

use pkcs11_sys::{
    CKA_ALWAYS_AUTHENTICATE, CKA_ALWAYS_SENSITIVE, CKA_APPLICATION, CKA_CERTIFICATE_CATEGORY,
    CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_COEFFICIENT, CKA_DECRYPT, CKA_EC_PARAMS, CKA_EC_POINT,
    CKA_ENCRYPT, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_EXTRACTABLE, CKA_ID, CKA_ISSUER, CKA_KEY_TYPE,
    CKA_LABEL, CKA_MODULUS, CKA_MODULUS_BITS, CKA_NEVER_EXTRACTABLE, CKA_PRIME_1, CKA_PRIME_2,
    CKA_PRIVATE, CKA_PRIVATE_EXPONENT, CKA_PROFILE_ID, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE,
    CKA_SERIAL_NUMBER, CKA_SIGN, CKA_SIGN_RECOVER, CKA_SUBJECT, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP,
    CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_WRAP, CKC_X_509, CK_ATTRIBUTE,
    CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_CERTIFICATE_CATEGORY, CK_CERTIFICATE_TYPE, CK_FALSE,
    CK_KEY_TYPE, CK_OBJECT_CLASS, CK_PROFILE_ID, CK_TRUE, CK_ULONG,
};
use strum_macros::Display;
use tracing::{debug, trace};

use crate::{MError, MResult};

#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
pub enum AttributeType {
    AlwaysAuthenticate,
    AlwaysSensitive,
    Application,
    CertificateCategory,
    CertificateType,
    Class,
    Coefficient,
    Decrypt,
    EcParams,
    EcPoint,
    Encrypt,
    Exponent1,
    Exponent2,
    Extractable,
    Id,
    Issuer,
    KeyType,
    Label,
    Modulus,
    ModulusBits,
    NeverExtractable,
    Prime1,
    Prime2,
    Private,
    PrivateExponent,
    ProfileId,
    PublicExponent,
    Sensitive,
    SerialNumber,
    Sign,
    SignRecover,
    Subject,
    Token,
    Trusted,
    Unwrap,
    Value,
    ValueLen,
    Verify,
    VerifyRecover,
    Wrap,
}

impl TryFrom<CK_ATTRIBUTE_TYPE> for AttributeType {
    type Error = MError;

    fn try_from(type_: CK_ATTRIBUTE_TYPE) -> MResult<Self> {
        match type_ {
            CKA_ALWAYS_AUTHENTICATE => Ok(Self::AlwaysAuthenticate),
            CKA_ALWAYS_SENSITIVE => Ok(Self::AlwaysSensitive),
            CKA_APPLICATION => Ok(Self::Application),
            CKA_CERTIFICATE_CATEGORY => Ok(Self::CertificateCategory),
            CKA_CERTIFICATE_TYPE => Ok(Self::CertificateType),
            CKA_CLASS => Ok(Self::Class),
            CKA_COEFFICIENT => Ok(Self::Coefficient),
            CKA_DECRYPT => Ok(Self::Decrypt),
            CKA_EC_PARAMS => Ok(Self::EcParams),
            CKA_EC_POINT => Ok(Self::EcPoint),
            CKA_ENCRYPT => Ok(Self::Encrypt),
            CKA_EXPONENT_1 => Ok(Self::Exponent1),
            CKA_EXPONENT_2 => Ok(Self::Exponent2),
            CKA_EXTRACTABLE => Ok(Self::Extractable),
            CKA_ID => Ok(Self::Id),
            CKA_ISSUER => Ok(Self::Issuer),
            CKA_KEY_TYPE => Ok(Self::KeyType),
            CKA_LABEL => Ok(Self::Label),
            CKA_MODULUS => Ok(Self::Modulus),
            CKA_MODULUS_BITS => Ok(Self::ModulusBits),
            CKA_NEVER_EXTRACTABLE => Ok(Self::NeverExtractable),
            CKA_PRIME_1 => Ok(Self::Prime1),
            CKA_PRIME_2 => Ok(Self::Prime2),
            CKA_PRIVATE => Ok(Self::Private),
            CKA_PRIVATE_EXPONENT => Ok(Self::PrivateExponent),
            CKA_PROFILE_ID => Ok(Self::ProfileId),
            CKA_PUBLIC_EXPONENT => Ok(Self::PublicExponent),
            CKA_SENSITIVE => Ok(Self::Sensitive),
            CKA_SIGN => Ok(Self::Sign),
            CKA_SIGN_RECOVER => Ok(Self::SignRecover),
            CKA_SERIAL_NUMBER => Ok(Self::SerialNumber),
            CKA_SUBJECT => Ok(Self::Subject),
            CKA_TOKEN => Ok(Self::Token),
            CKA_TRUSTED => Ok(Self::Trusted),
            CKA_UNWRAP => Ok(Self::Unwrap),
            CKA_VALUE => Ok(Self::Value),
            CKA_VALUE_LEN => Ok(Self::ValueLen),
            CKA_VERIFY => Ok(Self::Verify),
            CKA_VERIFY_RECOVER => Ok(Self::VerifyRecover),
            CKA_WRAP => Ok(Self::Wrap),
            _ => Err(MError::AttributeTypeInvalid(type_)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Attribute {
    AlwaysAuthenticate(bool),
    AlwaysSensitive(bool),
    Application(CString),
    CertificateCategory(CK_CERTIFICATE_CATEGORY),
    CertificateType(CK_CERTIFICATE_TYPE),
    Class(CK_OBJECT_CLASS),
    Coefficient(Vec<u8>),
    Decrypt(bool),
    EcParams(Vec<u8>),
    EcPoint(Vec<u8>),
    Encrypt(bool),
    Exponent1(Vec<u8>),
    Exponent2(Vec<u8>),
    Extractable(bool),
    Id(Vec<u8>),
    Issuer(Vec<u8>),
    KeyType(CK_KEY_TYPE),
    Label(String),
    Modulus(Vec<u8>),
    ModulusBits(CK_ULONG),
    NeverExtractable(bool),
    Prime1(Vec<u8>),
    Prime2(Vec<u8>),
    Private(bool),
    PrivateExponent(Vec<u8>),
    ProfileId(CK_PROFILE_ID),
    PublicExponent(Vec<u8>),
    Sensitive(bool),
    SerialNumber(Vec<u8>),
    Sign(bool),
    SignRecover(bool),
    Subject(Vec<u8>),
    Token(bool),
    Trusted(bool),
    Unwrap(bool),
    Value(Vec<u8>),
    ValueLen(CK_ULONG),
    Verify(bool),
    VerifyRecover(bool),
    Wrap(bool),
}

impl Attribute {
    #[must_use]
    pub const fn attribute_type(&self) -> AttributeType {
        match self {
            Self::AlwaysAuthenticate(_) => AttributeType::AlwaysAuthenticate,
            Self::AlwaysSensitive(_) => AttributeType::AlwaysSensitive,
            Self::Application(_) => AttributeType::Application,
            Self::CertificateCategory(_) => AttributeType::CertificateCategory,
            Self::CertificateType(_) => AttributeType::CertificateType,
            Self::Class(_) => AttributeType::Class,
            Self::Coefficient(_) => AttributeType::Coefficient,
            Self::Decrypt(_) => AttributeType::Decrypt,
            Self::EcParams(_) => AttributeType::EcParams,
            Self::EcPoint(_) => AttributeType::EcPoint,
            Self::Encrypt(_) => AttributeType::Encrypt,
            Self::Exponent1(_) => AttributeType::Exponent1,
            Self::Exponent2(_) => AttributeType::Exponent2,
            Self::Extractable(_) => AttributeType::Extractable,
            Self::Id(_) => AttributeType::Id,
            Self::Issuer(_) => AttributeType::Issuer,
            Self::KeyType(_) => AttributeType::KeyType,
            Self::Label(_) => AttributeType::Label,
            Self::Modulus(_) => AttributeType::Modulus,
            Self::ModulusBits(_) => AttributeType::ModulusBits,
            Self::NeverExtractable(_) => AttributeType::NeverExtractable,
            Self::Prime1(_) => AttributeType::Prime1,
            Self::Prime2(_) => AttributeType::Prime2,
            Self::Private(_) => AttributeType::Private,
            Self::PrivateExponent(_) => AttributeType::PrivateExponent,
            Self::ProfileId(_) => AttributeType::ProfileId,
            Self::PublicExponent(_) => AttributeType::PublicExponent,
            Self::Sensitive(_) => AttributeType::Sensitive,
            Self::SerialNumber(_) => AttributeType::SerialNumber,
            Self::Sign(_) => AttributeType::Sign,
            Self::SignRecover(_) => AttributeType::SignRecover,
            Self::Subject(_) => AttributeType::Subject,
            Self::Token(_) => AttributeType::Token,
            Self::Trusted(_) => AttributeType::Trusted,
            Self::Unwrap(_) => AttributeType::Unwrap,
            Self::Value(_) => AttributeType::Value,
            Self::ValueLen(_) => AttributeType::ValueLen,
            Self::Verify(_) => AttributeType::Verify,
            Self::VerifyRecover(_) => AttributeType::VerifyRecover,
            Self::Wrap(_) => AttributeType::Wrap,
        }
    }

    #[must_use]
    pub fn as_raw_value(&self) -> Vec<u8> {
        match self {
            Self::AlwaysAuthenticate(bool)
            | Self::AlwaysSensitive(bool)
            | Self::Decrypt(bool)
            | Self::Encrypt(bool)
            | Self::Extractable(bool)
            | Self::NeverExtractable(bool)
            | Self::Private(bool)
            | Self::Sensitive(bool)
            | Self::Sign(bool)
            | Self::SignRecover(bool)
            | Self::Token(bool)
            | Self::Trusted(bool)
            | Self::Unwrap(bool)
            | Self::Verify(bool)
            | Self::VerifyRecover(bool)
            | Self::Wrap(bool) => {
                CK_BBOOL::to_ne_bytes(if *bool { CK_TRUE } else { CK_FALSE }).to_vec()
            }
            Self::CertificateCategory(int)
            | Self::CertificateType(int)
            | Self::Class(int)
            | Self::KeyType(int)
            | Self::ModulusBits(int)
            | Self::ProfileId(int)
            | Self::ValueLen(int) => int.to_ne_bytes().to_vec(),
            Self::Coefficient(bytes)
            | Self::EcParams(bytes)
            | Self::EcPoint(bytes)
            | Self::Exponent1(bytes)
            | Self::Exponent2(bytes)
            | Self::Id(bytes)
            | Self::Issuer(bytes)
            | Self::Modulus(bytes)
            | Self::Prime1(bytes)
            | Self::Prime2(bytes)
            | Self::PrivateExponent(bytes)
            | Self::PublicExponent(bytes)
            | Self::SerialNumber(bytes)
            | Self::Subject(bytes)
            | Self::Value(bytes) => bytes.clone(),
            Self::Application(c_string) => c_string.as_bytes().to_vec(),
            Self::Label(string) => string.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<CK_ATTRIBUTE> for Attribute {
    type Error = MError;

    fn try_from(attribute: CK_ATTRIBUTE) -> MResult<Self> {
        trace!("Parsing attribute: {:?}", attribute);
        let attr_type = AttributeType::try_from(attribute.type_)?;
        let val = if attribute.ulValueLen > 0 {
            if attribute.pValue.is_null() {
                return Err(MError::NullPtr);
            }
            unsafe {
                std::slice::from_raw_parts(
                    attribute.pValue as *const u8,
                    attribute.ulValueLen.try_into()?,
                )
            }
        } else {
            &[]
        };

        let attr = match attr_type {
            AttributeType::AlwaysAuthenticate => {
                Ok(Self::AlwaysAuthenticate(try_u8_into_bool(val)?))
            }
            AttributeType::AlwaysSensitive => Ok(Self::AlwaysSensitive(try_u8_into_bool(val)?)),
            AttributeType::Application => {
                Ok(Self::Application(CString::from_vec_with_nul(val.to_vec())?))
            }
            AttributeType::CertificateCategory => Ok(Self::CertificateCategory(
                CK_CERTIFICATE_CATEGORY::from_ne_bytes(val.try_into()?),
            )),
            AttributeType::CertificateType => Ok(Self::CertificateType(
                CK_CERTIFICATE_TYPE::from_ne_bytes(val.try_into()?),
            )),
            AttributeType::Class => {
                Ok(Self::Class(CK_OBJECT_CLASS::from_ne_bytes(val.try_into()?)))
            }
            AttributeType::Coefficient => Ok(Self::Coefficient(val.to_vec())),
            AttributeType::Decrypt => Ok(Self::Decrypt(try_u8_into_bool(val)?)),
            AttributeType::EcParams => Ok(Self::EcParams(val.to_vec())),
            AttributeType::EcPoint => Ok(Self::EcPoint(val.to_vec())),
            AttributeType::Encrypt => Ok(Self::Encrypt(try_u8_into_bool(val)?)),
            AttributeType::Exponent1 => Ok(Self::Exponent1(val.to_vec())),
            AttributeType::Exponent2 => Ok(Self::Exponent2(val.to_vec())),
            AttributeType::Extractable => Ok(Self::Extractable(try_u8_into_bool(val)?)),
            AttributeType::Id => Ok(Self::Id(val.to_vec())),
            AttributeType::Issuer => Ok(Self::Issuer(val.to_vec())),
            AttributeType::KeyType => {
                Ok(Self::KeyType(CK_KEY_TYPE::from_ne_bytes(val.try_into()?)))
            }
            AttributeType::Label => Ok(Self::Label(String::from_utf8(val.to_vec())?)),
            AttributeType::Modulus => Ok(Self::Modulus(val.to_vec())),
            AttributeType::ModulusBits => {
                Ok(Self::ModulusBits(CK_ULONG::from_ne_bytes(val.try_into()?)))
            }
            AttributeType::NeverExtractable => Ok(Self::NeverExtractable(try_u8_into_bool(val)?)),
            AttributeType::Prime1 => Ok(Self::Prime1(val.to_vec())),
            AttributeType::Prime2 => Ok(Self::Prime2(val.to_vec())),
            AttributeType::Private => Ok(Self::Private(try_u8_into_bool(val)?)),
            AttributeType::PrivateExponent => Ok(Self::PrivateExponent(val.to_vec())),
            AttributeType::ProfileId => {
                Ok(Self::ProfileId(CK_ULONG::from_ne_bytes(val.try_into()?)))
            }
            AttributeType::PublicExponent => Ok(Self::PublicExponent(val.to_vec())),
            AttributeType::Sensitive => Ok(Self::Sensitive(try_u8_into_bool(val)?)),
            AttributeType::SerialNumber => Ok(Self::SerialNumber(val.to_vec())),
            AttributeType::Subject => Ok(Self::Subject(val.to_vec())),
            AttributeType::Sign => Ok(Self::Sign(try_u8_into_bool(val)?)),
            AttributeType::SignRecover => Ok(Self::SignRecover(try_u8_into_bool(val)?)),
            AttributeType::Token => Ok(Self::Token(try_u8_into_bool(val)?)),
            AttributeType::Trusted => Ok(Self::Trusted(try_u8_into_bool(val)?)),
            AttributeType::Unwrap => Ok(Self::Unwrap(try_u8_into_bool(val)?)),
            AttributeType::Value => Ok(Self::Value(val.to_vec())),
            AttributeType::ValueLen => Ok(Self::ValueLen(CK_ULONG::from_ne_bytes(val.try_into()?))),
            AttributeType::Verify => Ok(Self::Verify(try_u8_into_bool(val)?)),
            AttributeType::VerifyRecover => Ok(Self::VerifyRecover(try_u8_into_bool(val)?)),
            AttributeType::Wrap => Ok(Self::Wrap(try_u8_into_bool(val)?)),
        };

        debug!("Attribute {:?} => {:?}", attribute, attr);
        attr
    }
}

// Borrowed from:
// https://github.com/parallaxsecond/rust-cryptoki/blob/89055f2a30e30d07a99e5904e9231d743c75d8e5/cryptoki/src/object.rs#L769
fn try_u8_into_bool(slice: &[u8]) -> MResult<bool> {
    let as_array: [u8; std::mem::size_of::<CK_BBOOL>()] = slice.try_into()?;
    let as_byte = CK_BBOOL::from_ne_bytes(as_array);
    Ok(!matches!(as_byte, 0u8))
}

#[derive(Debug, Clone)]
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    #[must_use]
    pub fn get(&self, type_: AttributeType) -> Option<&Attribute> {
        self.0.iter().find(|&attr| attr.attribute_type() == type_)
    }

    pub fn get_class(&self) -> MResult<CK_OBJECT_CLASS> {
        match self.get(AttributeType::Class) {
            Some(Attribute::Class(class)) => Ok(*class),
            None => Err(MError::Todo("get_class: no class attribute".to_owned())),
            other => Err(MError::Todo(format!(
                "get_class: unexpected attribute value: {other:?}, on class attribute type"
            ))),
        }
    }

    /// Ensure that the attributes contain a `CKC_X_509` certificate request or None.
    pub fn ensure_X509_or_none(&self) -> MResult<()> {
        match self.get(AttributeType::CertificateType) {
            Some(Attribute::CertificateType(cert_type)) => match *cert_type {
                CKC_X_509 => Ok(()),
                _ => Err(MError::Todo(format!(
                    "ensure_X509_or_none: support for certificate type: {cert_type} is not \
                     implemented"
                ))),
            },
            Some(other_type) => Err(MError::Todo(format!(
                "ensure_X509_or_none: unexpected attribute value: {other_type:?}, on class \
                 attribute type"
            ))),
            None => Ok(()),
        }
    }
}

impl Deref for Attributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Vec<Attribute> {
        &self.0
    }
}

impl From<Vec<Attribute>> for Attributes {
    fn from(value: Vec<Attribute>) -> Self {
        Self(value)
    }
}

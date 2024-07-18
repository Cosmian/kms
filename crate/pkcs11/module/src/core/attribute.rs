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
use tracing::trace;

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
    /// DER-encoding of an ANSI X9.62 Parameters value
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
            CKA_ALWAYS_AUTHENTICATE => Ok(AttributeType::AlwaysAuthenticate),
            CKA_ALWAYS_SENSITIVE => Ok(AttributeType::AlwaysSensitive),
            CKA_APPLICATION => Ok(AttributeType::Application),
            CKA_CERTIFICATE_CATEGORY => Ok(AttributeType::CertificateCategory),
            CKA_CERTIFICATE_TYPE => Ok(AttributeType::CertificateType),
            CKA_CLASS => Ok(AttributeType::Class),
            CKA_COEFFICIENT => Ok(AttributeType::Coefficient),
            CKA_DECRYPT => Ok(AttributeType::Decrypt),
            CKA_EC_PARAMS => Ok(AttributeType::EcParams),
            CKA_EC_POINT => Ok(AttributeType::EcPoint),
            CKA_ENCRYPT => Ok(AttributeType::Encrypt),
            CKA_EXPONENT_1 => Ok(AttributeType::Exponent1),
            CKA_EXPONENT_2 => Ok(AttributeType::Exponent2),
            CKA_EXTRACTABLE => Ok(AttributeType::Extractable),
            CKA_ID => Ok(AttributeType::Id),
            CKA_ISSUER => Ok(AttributeType::Issuer),
            CKA_KEY_TYPE => Ok(AttributeType::KeyType),
            CKA_LABEL => Ok(AttributeType::Label),
            CKA_MODULUS => Ok(AttributeType::Modulus),
            CKA_MODULUS_BITS => Ok(AttributeType::ModulusBits),
            CKA_NEVER_EXTRACTABLE => Ok(AttributeType::NeverExtractable),
            CKA_PRIME_1 => Ok(AttributeType::Prime1),
            CKA_PRIME_2 => Ok(AttributeType::Prime2),
            CKA_PRIVATE => Ok(AttributeType::Private),
            CKA_PRIVATE_EXPONENT => Ok(AttributeType::PrivateExponent),
            CKA_PROFILE_ID => Ok(AttributeType::ProfileId),
            CKA_PUBLIC_EXPONENT => Ok(AttributeType::PublicExponent),
            CKA_SENSITIVE => Ok(AttributeType::Sensitive),
            CKA_SIGN => Ok(AttributeType::Sign),
            CKA_SIGN_RECOVER => Ok(AttributeType::SignRecover),
            CKA_SERIAL_NUMBER => Ok(AttributeType::SerialNumber),
            CKA_SUBJECT => Ok(AttributeType::Subject),
            CKA_TOKEN => Ok(AttributeType::Token),
            CKA_TRUSTED => Ok(AttributeType::Trusted),
            CKA_UNWRAP => Ok(AttributeType::Unwrap),
            CKA_VALUE => Ok(AttributeType::Value),
            CKA_VALUE_LEN => Ok(AttributeType::ValueLen),
            CKA_VERIFY => Ok(AttributeType::Verify),
            CKA_VERIFY_RECOVER => Ok(AttributeType::VerifyRecover),
            CKA_WRAP => Ok(AttributeType::Wrap),
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
    /// DER-encoding of an ANSI X9.62 Parameters value
    EcParams(Vec<u8>),
    EcPoint(Vec<u8>),
    Encrypt(bool),
    Exponent1(Vec<u8>),
    Exponent2(Vec<u8>),
    Extractable(bool),
    Id(String),
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
    pub fn attribute_type(&self) -> AttributeType {
        match self {
            Attribute::AlwaysAuthenticate(_) => AttributeType::AlwaysAuthenticate,
            Attribute::AlwaysSensitive(_) => AttributeType::AlwaysSensitive,
            Attribute::Application(_) => AttributeType::Application,
            Attribute::CertificateCategory(_) => AttributeType::CertificateCategory,
            Attribute::CertificateType(_) => AttributeType::CertificateType,
            Attribute::Class(_) => AttributeType::Class,
            Attribute::Coefficient(_) => AttributeType::Coefficient,
            Attribute::Decrypt(_) => AttributeType::Decrypt,
            Attribute::EcParams(_) => AttributeType::EcParams,
            Attribute::EcPoint(_) => AttributeType::EcPoint,
            Attribute::Encrypt(_) => AttributeType::Encrypt,
            Attribute::Exponent1(_) => AttributeType::Exponent1,
            Attribute::Exponent2(_) => AttributeType::Exponent2,
            Attribute::Extractable(_) => AttributeType::Extractable,
            Attribute::Id(_) => AttributeType::Id,
            Attribute::Issuer(_) => AttributeType::Issuer,
            Attribute::KeyType(_) => AttributeType::KeyType,
            Attribute::Label(_) => AttributeType::Label,
            Attribute::Modulus(_) => AttributeType::Modulus,
            Attribute::ModulusBits(_) => AttributeType::ModulusBits,
            Attribute::NeverExtractable(_) => AttributeType::NeverExtractable,
            Attribute::Prime1(_) => AttributeType::Prime1,
            Attribute::Prime2(_) => AttributeType::Prime2,
            Attribute::Private(_) => AttributeType::Private,
            Attribute::PrivateExponent(_) => AttributeType::PrivateExponent,
            Attribute::ProfileId(_) => AttributeType::ProfileId,
            Attribute::PublicExponent(_) => AttributeType::PublicExponent,
            Attribute::Sensitive(_) => AttributeType::Sensitive,
            Attribute::SerialNumber(_) => AttributeType::SerialNumber,
            Attribute::Sign(_) => AttributeType::Sign,
            Attribute::SignRecover(_) => AttributeType::SignRecover,
            Attribute::Subject(_) => AttributeType::Subject,
            Attribute::Token(_) => AttributeType::Token,
            Attribute::Trusted(_) => AttributeType::Trusted,
            Attribute::Unwrap(_) => AttributeType::Unwrap,
            Attribute::Value(_) => AttributeType::Value,
            Attribute::ValueLen(_) => AttributeType::ValueLen,
            Attribute::Verify(_) => AttributeType::Verify,
            Attribute::VerifyRecover(_) => AttributeType::VerifyRecover,
            Attribute::Wrap(_) => AttributeType::Wrap,
        }
    }

    #[must_use]
    pub fn as_raw_value(&self) -> Vec<u8> {
        match self {
            Attribute::AlwaysAuthenticate(bool)
            | Attribute::AlwaysSensitive(bool)
            | Attribute::Decrypt(bool)
            | Attribute::Encrypt(bool)
            | Attribute::Extractable(bool)
            | Attribute::NeverExtractable(bool)
            | Attribute::Private(bool)
            | Attribute::Sensitive(bool)
            | Attribute::Sign(bool)
            | Attribute::SignRecover(bool)
            | Attribute::Token(bool)
            | Attribute::Trusted(bool)
            | Attribute::Unwrap(bool)
            | Attribute::Verify(bool)
            | Attribute::VerifyRecover(bool)
            | Attribute::Wrap(bool) => {
                CK_BBOOL::to_ne_bytes(if *bool { CK_TRUE } else { CK_FALSE }).to_vec()
            }
            Attribute::CertificateCategory(int)
            | Attribute::CertificateType(int)
            | Attribute::Class(int)
            | Attribute::KeyType(int)
            | Attribute::ModulusBits(int)
            | Attribute::ProfileId(int)
            | Attribute::ValueLen(int) => int.to_ne_bytes().to_vec(),
            Attribute::Coefficient(bytes)
            | Attribute::EcParams(bytes)
            | Attribute::EcPoint(bytes)
            | Attribute::Exponent1(bytes)
            | Attribute::Exponent2(bytes)
            | Attribute::Issuer(bytes)
            | Attribute::Modulus(bytes)
            | Attribute::Prime1(bytes)
            | Attribute::Prime2(bytes)
            | Attribute::PrivateExponent(bytes)
            | Attribute::PublicExponent(bytes)
            | Attribute::SerialNumber(bytes)
            | Attribute::Subject(bytes)
            | Attribute::Value(bytes) => bytes.clone(),
            Attribute::Application(c_string) => c_string.as_bytes().to_vec(),
            Attribute::Label(string) => string.as_bytes().to_vec(),
            Attribute::Id(string) => string.as_bytes().to_vec(),
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
                Ok(Attribute::AlwaysAuthenticate(try_u8_into_bool(val)?))
            }
            AttributeType::AlwaysSensitive => {
                Ok(Attribute::AlwaysSensitive(try_u8_into_bool(val)?))
            }
            AttributeType::Application => Ok(Attribute::Application(CString::from_vec_with_nul(
                val.to_vec(),
            )?)),
            AttributeType::CertificateCategory => Ok(Attribute::CertificateCategory(
                CK_CERTIFICATE_CATEGORY::from_ne_bytes(val.try_into()?),
            )),
            AttributeType::CertificateType => Ok(Attribute::CertificateType(
                CK_CERTIFICATE_TYPE::from_ne_bytes(val.try_into()?),
            )),
            AttributeType::Class => Ok(Attribute::Class(CK_OBJECT_CLASS::from_ne_bytes(
                val.try_into()?,
            ))),
            AttributeType::Coefficient => Ok(Attribute::Coefficient(val.to_vec())),
            AttributeType::Decrypt => Ok(Attribute::Decrypt(try_u8_into_bool(val)?)),
            AttributeType::EcParams => Ok(Attribute::EcParams(val.to_vec())),
            AttributeType::EcPoint => Ok(Attribute::EcPoint(val.to_vec())),
            AttributeType::Encrypt => Ok(Attribute::Encrypt(try_u8_into_bool(val)?)),
            AttributeType::Exponent1 => Ok(Attribute::Exponent1(val.to_vec())),
            AttributeType::Exponent2 => Ok(Attribute::Exponent2(val.to_vec())),
            AttributeType::Extractable => Ok(Attribute::Extractable(try_u8_into_bool(val)?)),
            AttributeType::Id => Ok(Attribute::Id(String::from_utf8(val.to_vec())?)),
            AttributeType::Issuer => Ok(Attribute::Issuer(val.to_vec())),
            AttributeType::KeyType => Ok(Attribute::KeyType(CK_KEY_TYPE::from_ne_bytes(
                val.try_into()?,
            ))),
            AttributeType::Label => Ok(Attribute::Label(String::from_utf8(val.to_vec())?)),
            AttributeType::Modulus => Ok(Attribute::Modulus(val.to_vec())),
            AttributeType::ModulusBits => Ok(Attribute::ModulusBits(CK_ULONG::from_ne_bytes(
                val.try_into()?,
            ))),
            AttributeType::NeverExtractable => {
                Ok(Attribute::NeverExtractable(try_u8_into_bool(val)?))
            }
            AttributeType::Prime1 => Ok(Attribute::Prime1(val.to_vec())),
            AttributeType::Prime2 => Ok(Attribute::Prime2(val.to_vec())),
            AttributeType::Private => Ok(Attribute::Private(try_u8_into_bool(val)?)),
            AttributeType::PrivateExponent => Ok(Attribute::PrivateExponent(val.to_vec())),
            AttributeType::ProfileId => Ok(Attribute::ProfileId(CK_ULONG::from_ne_bytes(
                val.try_into()?,
            ))),
            AttributeType::PublicExponent => Ok(Attribute::PublicExponent(val.to_vec())),
            AttributeType::Sensitive => Ok(Attribute::Sensitive(try_u8_into_bool(val)?)),
            AttributeType::SerialNumber => Ok(Attribute::SerialNumber(val.to_vec())),
            AttributeType::Subject => Ok(Attribute::Subject(val.to_vec())),
            AttributeType::Sign => Ok(Attribute::Sign(try_u8_into_bool(val)?)),
            AttributeType::SignRecover => Ok(Attribute::SignRecover(try_u8_into_bool(val)?)),
            AttributeType::Token => Ok(Attribute::Token(try_u8_into_bool(val)?)),
            AttributeType::Trusted => Ok(Attribute::Trusted(try_u8_into_bool(val)?)),
            AttributeType::Unwrap => Ok(Attribute::Unwrap(try_u8_into_bool(val)?)),
            AttributeType::Value => Ok(Attribute::Value(val.to_vec())),
            AttributeType::ValueLen => Ok(Attribute::ValueLen(CK_ULONG::from_ne_bytes(
                val.try_into()?,
            ))),
            AttributeType::Verify => Ok(Attribute::Verify(try_u8_into_bool(val)?)),
            AttributeType::VerifyRecover => Ok(Attribute::VerifyRecover(try_u8_into_bool(val)?)),
            AttributeType::Wrap => Ok(Attribute::Wrap(try_u8_into_bool(val)?)),
        };

        trace!("Attribute {:?} => {:?}", attribute, attr);
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
            None => Err(MError::Todo("get_class: no class attribute".to_string())),
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
        Attributes(value)
    }
}

use std::sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard};

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
use pkcs11_sys::{
    CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID,
    CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_FUNCTION_NOT_PARALLEL, CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID, CKR_MECHANISM_INVALID, CKR_NEED_TO_CREATE_THREADS,
    CKR_OBJECT_HANDLE_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_RANDOM_NO_RNG,
    CKR_SESSION_HANDLE_INVALID, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID,
    CKR_TOKEN_WRITE_PROTECTED,
};
use thiserror::Error;

use crate::{core::attribute::AttributeType, objects_store::ObjectsStore};

pub(crate) mod result;
pub use result::ModuleResult;

#[derive(Error, Debug)]
pub enum ModuleError {
    #[error("pkcs11 error: {0}")]
    Default(String),

    #[error("{context}: {source}")]
    Context {
        context: String,
        #[source]
        source: Box<ModuleError>,
    },
    // Cryptoki errors.
    #[error("bad arguments: {0}")]
    BadArguments(String),
    #[error("{0} is not a valid attribute type")]
    AttributeTypeInvalid(CK_ATTRIBUTE_TYPE),
    #[error("the value for attribute {0} is invalid")]
    AttributeValueInvalid(AttributeType),
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("cryptoki module has already been initialized")]
    CryptokiAlreadyInitialized,
    #[error("cryptoki module has not been initialized")]
    CryptokiNotInitialized,
    #[error("function not parallel")]
    FunctionNotParallel,
    #[error("function not supported")]
    FunctionNotSupported,
    #[error("key handle {0} is invalid")]
    KeyHandleInvalid(CK_OBJECT_HANDLE),
    #[error("module cannot function without being able to spawn threads")]
    NeedToCreateThreads,
    #[error("{0} is not a valid mechanism")]
    MechanismInvalid(CK_MECHANISM_TYPE),
    #[error("object {0} is invalid")]
    ObjectHandleInvalid(CK_OBJECT_HANDLE),
    #[error("operation has not been initialized, session: {0}")]
    OperationNotInitialized(CK_SESSION_HANDLE),
    #[error("no random number generator")]
    RandomNoRng,
    #[error("session handle {0} is invalid")]
    SessionHandleInvalid(CK_SESSION_HANDLE),
    #[error("token does not support parallel sessions")]
    SessionParallelNotSupported,
    #[error("slot id {0} is invalid")]
    SlotIdInvalid(CK_SLOT_ID),
    #[error("token is write protected")]
    TokenWriteProtected,
    // Other errors.
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    FromVecWithNul(#[from] std::ffi::FromVecWithNulError),
    #[error("{0} is a null pointer")]
    NullPtr(String),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("Algorithm not supported")]
    AlgorithmNotSupported(String),
    // Catch-all for backend-related errors.
    #[error(transparent)]
    Backend(#[from] Box<dyn std::error::Error>),
    #[error(transparent)]
    Pkcs1DerError(#[from] pkcs1::der::Error),
    #[error(transparent)]
    ReadGuardError(#[from] PoisonError<RwLockReadGuard<'static, ObjectsStore>>),
    #[error(transparent)]
    WriteGuardError(#[from] PoisonError<RwLockWriteGuard<'static, ObjectsStore>>),
    #[error("Oid: {0}")]
    Oid(String),
    #[error("{0}")]
    Todo(String),
    #[error("cryptographic error: {0}")]
    Cryptography(String),
}

impl From<const_oid::Error> for ModuleError {
    fn from(e: const_oid::Error) -> Self {
        Self::Oid(e.to_string())
    }
}

impl From<ModuleError> for CK_RV {
    fn from(e: ModuleError) -> Self {
        match e {
            ModuleError::Context { source, .. } => (*source).into(),
            ModuleError::BadArguments(_) => CKR_ARGUMENTS_BAD,
            ModuleError::AttributeTypeInvalid(_) => CKR_ATTRIBUTE_TYPE_INVALID,
            ModuleError::AttributeValueInvalid(_) => CKR_ATTRIBUTE_VALUE_INVALID,
            ModuleError::BufferTooSmall => CKR_BUFFER_TOO_SMALL,
            ModuleError::CryptokiAlreadyInitialized => CKR_CRYPTOKI_ALREADY_INITIALIZED,
            ModuleError::CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED,
            ModuleError::FunctionNotParallel => CKR_FUNCTION_NOT_PARALLEL,
            ModuleError::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED,
            ModuleError::KeyHandleInvalid(_) => CKR_KEY_HANDLE_INVALID,
            ModuleError::MechanismInvalid(_) => CKR_MECHANISM_INVALID,
            ModuleError::NeedToCreateThreads => CKR_NEED_TO_CREATE_THREADS,
            ModuleError::ObjectHandleInvalid(_) => CKR_OBJECT_HANDLE_INVALID,
            ModuleError::OperationNotInitialized(_) => CKR_OPERATION_NOT_INITIALIZED,
            ModuleError::RandomNoRng => CKR_RANDOM_NO_RNG,
            ModuleError::SessionHandleInvalid(_) => CKR_SESSION_HANDLE_INVALID,
            ModuleError::SessionParallelNotSupported => CKR_SESSION_PARALLEL_NOT_SUPPORTED,
            ModuleError::SlotIdInvalid(_) => CKR_SLOT_ID_INVALID,
            ModuleError::TokenWriteProtected => CKR_TOKEN_WRITE_PROTECTED,

            ModuleError::Backend(_)
            | ModuleError::AlgorithmNotSupported(_)
            | ModuleError::Default(_)
            | ModuleError::FromUtf8(_)
            | ModuleError::FromVecWithNul(_)
            | ModuleError::NullPtr(_)
            | ModuleError::Todo(_)
            | ModuleError::Cryptography(_)
            | ModuleError::TryFromInt(_)
            | ModuleError::Pkcs1DerError(_)
            | ModuleError::Oid(_)
            | ModuleError::ReadGuardError(_)
            | ModuleError::WriteGuardError(_)
            | ModuleError::TryFromSlice(_) => CKR_GENERAL_ERROR,
        }
    }
}

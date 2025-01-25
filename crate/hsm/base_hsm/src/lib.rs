//! Copyright 2024 Cosmian Tech SAS

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
extern crate core;

mod error;

pub use base_hsm::BaseHsm;
pub use error::{PError, PResult};
use rand::{rngs::OsRng, TryRngCore};
pub use session::{AesKeySize, HsmEncryptionAlgorithm, RsaKeySize, Session};
pub use slots::{ObjectHandlesCache, SlotManager};

mod base_hsm;
mod hsm_lib;
mod session;

mod kms_hsm;
mod slots;

/// A macro is used here to ensure inline expansion due to mutable pointer parameters
#[macro_export]
macro_rules! aes_mechanism {
    ($nonce:expr) => {{
        let mut params = CK_AES_GCM_PARAMS {
            pIv: $nonce as *mut u8,
            ulIvLen: 12,
            ulIvBits: 96,
            pAAD: std::ptr::null_mut(),
            ulAADLen: 0,
            ulTagBits: 128,
        };
        CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: &mut params as *mut _ as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CK_AES_GCM_PARAMS>() as CK_ULONG,
        }
    }};
}
#[macro_export]
macro_rules! rsa_mechanism {
    ($algorithm:expr) => {
        match $algorithm {
            HsmEncryptionAlgorithm::RsaPkcsV15 => CK_MECHANISM {
                mechanism: CKM_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            HsmEncryptionAlgorithm::RsaOaep => {
                let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA256,
                    mgf: CKG_MGF1_SHA256,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: std::ptr::null_mut(),
                    ulSourceDataLen: 0,
                };
                CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS_OAEP,
                    pParameter: &mut params as *mut _ as CK_VOID_PTR,
                    ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
                }
            }
            _ => return Err(PError::Default("expecting an RSA algorithm".to_string())),
        }
    };
}

//! Copyright 2024 Cosmian Tech SAS

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
extern crate core;

mod error;

pub use error::{PError, PResult};
pub use proteccio::Proteccio;
use rand::{rngs::OsRng, TryRngCore};
pub use session::{AesKeySize, ProteccioEncryptionAlgorithm, RsaKeySize, Session};
pub use slots::{ObjectHandlesCache, SlotManager};

mod proteccio;
mod session;

mod kms_hsm;
mod slots;
#[cfg(test)]
#[cfg(feature = "proteccio")]
mod tests;

/// This is a macro because of the mut pointer to the params
/// We therefore want this code to be inlined
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
            ProteccioEncryptionAlgorithm::RsaPkcsV15 => CK_MECHANISM {
                mechanism: CKM_RSA_PKCS,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            ProteccioEncryptionAlgorithm::RsaOaep => {
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

fn generate_random_nonce<const T: usize>() -> PResult<[u8; T]> {
    let mut bytes = [0u8; T];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| PError::Default(format!("Error generating random nonce: {}", e)))?;
    Ok(bytes)
}

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

#![allow(clippy::as_conversions)]

use std::slice;

use cosmian_logger::{debug, error};
use pkcs11_sys::{
    CK_GCM_PARAMS, CK_MECHANISM, CK_MECHANISM_TYPE, CK_RSA_PKCS_PSS_PARAMS, CKG_MGF1_SHA1,
    CKG_MGF1_SHA224, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKM_AES_CBC,
    CKM_AES_CBC_PAD, CKM_AES_GCM, CKM_AES_KEY_GEN, CKM_ECDSA, CKM_EDDSA, CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS, CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA224, CKM_SHA256, CKM_SHA256_RSA_PKCS,
    CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA512, CKM_SHA512_RSA_PKCS,
};

use crate::{
    ModuleError, ModuleResult, not_null,
    traits::{DigestType, EncryptionAlgorithm, KeyAlgorithm, SignatureAlgorithm},
};

pub const AES_IV_SIZE: usize = 16;

/// Maximum accepted `CKM_AES_GCM` nonce (`pIv`) length in bytes. 12 bytes (96 bits) is the
/// standard/recommended GCM nonce size; a generous upper bound is kept to accept
/// non-standard-but-valid nonce lengths without allowing unbounded allocation from a
/// caller-supplied `ulIvLen`.
pub const AES_GCM_MAX_IV_SIZE: usize = 128;

/// Maximum accepted `CKM_AES_GCM` additional authenticated data (`pAAD`) length in bytes.
/// Bounds the allocation driven by the caller-supplied `ulAADLen`.
pub const AES_GCM_MAX_AAD_SIZE: usize = 1 << 20; // 1 MiB

/// The only authentication tag length supported by the KMS's AES-GCM backend (128 bits / 16
/// bytes), matching `AES_128_GCM_MAC_LENGTH`/`AES_192_GCM_MAC_LENGTH`/`AES_256_GCM_MAC_LENGTH`
/// in `crate/crypto`.
pub const AES_GCM_TAG_BITS: pkcs11_sys::CK_ULONG = 128;

pub const SUPPORTED_SIGNATURE_MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_RSA_PKCS,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_ECDSA,
    CKM_EDDSA,
    CKM_RSA_PKCS_PSS,
    CKM_AES_KEY_GEN,
    CKM_AES_CBC,
    CKM_AES_CBC_PAD,
    CKM_AES_GCM,
];

#[derive(Debug)]
pub enum Mechanism {
    AesKeyGen,
    AesCbc {
        iv: [u8; AES_IV_SIZE],
    },
    AesCbcPad {
        iv: [u8; AES_IV_SIZE],
    },
    /// `CKM_AES_GCM` (PKCS#11 v3.0). `iv` is the nonce (`pIv`); `aad` is the additional
    /// authenticated data (`pAAD`, may be empty). The authentication tag length
    /// (`ulTagBits`) is validated to be exactly 128 bits at parse time and is not stored,
    /// since the KMS backend always uses a 16-byte GCM tag.
    AesGcm {
        iv: Vec<u8>,
        aad: Vec<u8>,
    },
    Ecdsa,
    EdDsa,
    RsaPkcs,
    RsaPkcsSha1,
    RsaPkcsSha256,
    RsaPkcsSha384,
    RsaPkcsSha512,
    RsaPss {
        digest_algorithm: DigestType,
        mask_generation_function: DigestType,
        salt_length: u64,
    },
}

#[expect(clippy::missing_safety_doc)]
pub unsafe fn parse_mechanism(mechanism: CK_MECHANISM) -> Result<Mechanism, ModuleError> {
    debug!("parse_mechanism: {mechanism:?}");
    match mechanism.mechanism {
        CKM_AES_KEY_GEN => Ok(Mechanism::AesKeyGen),
        CKM_AES_CBC_PAD | CKM_AES_CBC => {
            let iv_slice = unsafe {
                slice::from_raw_parts(
                    mechanism.pParameter.cast::<u8>(),
                    usize::try_from(mechanism.ulParameterLen)?,
                )
            };
            if iv_slice.len() != AES_IV_SIZE {
                return Err(ModuleError::BadArguments(format!(
                    "AES IV size incorrect. {AES_IV_SIZE} bytes expected"
                )));
            }
            let mut iv = [0_u8; AES_IV_SIZE];
            iv.copy_from_slice(iv_slice);
            debug!("parse_mechanism: iv: {iv:?}");
            match mechanism.mechanism {
                CKM_AES_CBC_PAD => Ok(Mechanism::AesCbcPad { iv }),
                _ => Ok(Mechanism::AesCbc { iv }),
            }
        }

        CKM_AES_GCM => {
            let mechanism_type = mechanism.mechanism;
            let parameter_ptr = mechanism.pParameter;
            let parameter_len = mechanism.ulParameterLen;
            not_null!(parameter_ptr, "parse_mechanism: CKM_AES_GCM pParameter");
            if (usize::try_from(parameter_len)?) != std::mem::size_of::<CK_GCM_PARAMS>() {
                error!(
                    "CKM_AES_GCM pParameter incorrect size: {} != {}",
                    parameter_len,
                    std::mem::size_of::<CK_GCM_PARAMS>()
                );
                return Err(ModuleError::MechanismInvalid(mechanism_type));
            }
            // SAFETY: `parameter_ptr` was just checked non-null and the pointed-to buffer was
            // checked above to be exactly `size_of::<CK_GCM_PARAMS>()` bytes, as required by the
            // PKCS#11 v3.0 spec for `CKM_AES_GCM`.
            let params: CK_GCM_PARAMS = unsafe { parameter_ptr.cast::<CK_GCM_PARAMS>().read() };

            if params.ulTagBits != AES_GCM_TAG_BITS {
                error!(
                    "CKM_AES_GCM: unsupported ulTagBits {} (only {} is supported)",
                    params.ulTagBits, AES_GCM_TAG_BITS
                );
                return Err(ModuleError::MechanismInvalid(mechanism_type));
            }

            let iv_len = usize::try_from(params.ulIvLen)?;
            if iv_len == 0 || iv_len > AES_GCM_MAX_IV_SIZE {
                return Err(ModuleError::BadArguments(format!(
                    "CKM_AES_GCM: invalid ulIvLen {iv_len} (must be in 1..={AES_GCM_MAX_IV_SIZE})"
                )));
            }
            not_null!(params.pIv, "parse_mechanism: CKM_AES_GCM pIv");
            // SAFETY: `pIv` was just checked non-null and `iv_len` was validated above to be
            // within the bounded `AES_GCM_MAX_IV_SIZE`, matching the caller-supplied `ulIvLen`.
            let iv = unsafe { slice::from_raw_parts(params.pIv.cast::<u8>(), iv_len) }.to_vec();

            let aad_len = usize::try_from(params.ulAADLen)?;
            if aad_len > AES_GCM_MAX_AAD_SIZE {
                return Err(ModuleError::BadArguments(format!(
                    "CKM_AES_GCM: ulAADLen {aad_len} exceeds the maximum of \
                     {AES_GCM_MAX_AAD_SIZE} bytes"
                )));
            }
            let aad = if aad_len == 0 {
                Vec::new()
            } else {
                not_null!(params.pAAD, "parse_mechanism: CKM_AES_GCM pAAD");
                // SAFETY: `pAAD` was just checked non-null (for a non-zero length) and
                // `aad_len` was validated above to be within the bounded `AES_GCM_MAX_AAD_SIZE`,
                // matching the caller-supplied `ulAADLen`.
                unsafe { slice::from_raw_parts(params.pAAD.cast::<u8>(), aad_len) }.to_vec()
            };

            debug!(
                "parse_mechanism: CKM_AES_GCM iv_len: {}, aad_len: {}",
                iv.len(),
                aad.len()
            );
            Ok(Mechanism::AesGcm { iv, aad })
        }

        CKM_ECDSA => Ok(Mechanism::Ecdsa),
        CKM_EDDSA => Ok(Mechanism::EdDsa),
        CKM_RSA_PKCS => Ok(Mechanism::RsaPkcs),
        CKM_SHA1_RSA_PKCS => Ok(Mechanism::RsaPkcsSha1),
        CKM_SHA256_RSA_PKCS => Ok(Mechanism::RsaPkcsSha256),
        CKM_SHA384_RSA_PKCS => Ok(Mechanism::RsaPkcsSha384),
        CKM_SHA512_RSA_PKCS => Ok(Mechanism::RsaPkcsSha512),
        CKM_RSA_PKCS_PSS => {
            //  Bind to locals to prevent unaligned reads https://github.com/rust-lang/rust/issues/82523
            let mechanism_type = mechanism.mechanism;
            let parameter_ptr = mechanism.pParameter;
            let parameter_len = mechanism.ulParameterLen;
            not_null!(parameter_ptr, "parse_mechanism: parameter_ptr");
            if (usize::try_from(parameter_len)?) != std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>() {
                error!(
                    "pParameter incorrect: {} != {}",
                    parameter_len,
                    std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>()
                );
                return Err(ModuleError::MechanismInvalid(mechanism_type));
            }
            //  TODO(kcking): check alignment as well?
            let params: CK_RSA_PKCS_PSS_PARAMS =
                unsafe { parameter_ptr.cast::<CK_RSA_PKCS_PSS_PARAMS>().read() };
            let mgf = params.mgf;
            let hash_alg = params.hashAlg;
            let salt_len = params.sLen;

            let mgf = match mgf {
                CKG_MGF1_SHA1 => DigestType::Sha1,
                CKG_MGF1_SHA224 => DigestType::Sha224,
                CKG_MGF1_SHA256 => DigestType::Sha256,
                CKG_MGF1_SHA384 => DigestType::Sha384,
                CKG_MGF1_SHA512 => DigestType::Sha512,
                _ => {
                    error!("Unsupported mgf: {}", mgf);
                    return Err(ModuleError::MechanismInvalid(mechanism_type));
                }
            };

            let hash_alg = match hash_alg {
                CKM_SHA_1 => DigestType::Sha1,
                CKM_SHA224 => DigestType::Sha224,
                CKM_SHA256 => DigestType::Sha256,
                CKM_SHA384 => DigestType::Sha384,
                CKM_SHA512 => DigestType::Sha512,
                _ => {
                    error!("Unsupported hashAlg: {}", hash_alg);
                    return Err(ModuleError::MechanismInvalid(mechanism_type));
                }
            };

            Ok(Mechanism::RsaPss {
                digest_algorithm: hash_alg,
                mask_generation_function: mgf,
                // CK_ULONG is u32 on Windows, u64 on Linux; the conversion is needed for Windows
                #[allow(clippy::useless_conversion)]
                salt_length: u64::from(salt_len),
            })
        }
        _ => Err(ModuleError::MechanismInvalid(mechanism.mechanism)),
    }
}

impl From<&Mechanism> for CK_MECHANISM_TYPE {
    fn from(mechanism: &Mechanism) -> Self {
        match mechanism {
            Mechanism::AesKeyGen => CKM_AES_KEY_GEN,
            Mechanism::AesCbcPad { .. } => CKM_AES_CBC_PAD,
            Mechanism::AesCbc { .. } => CKM_AES_CBC,
            Mechanism::AesGcm { .. } => CKM_AES_GCM,
            Mechanism::Ecdsa => CKM_ECDSA,
            Mechanism::EdDsa => CKM_EDDSA,
            Mechanism::RsaPkcs => CKM_RSA_PKCS,
            Mechanism::RsaPkcsSha1 => CKM_SHA1_RSA_PKCS,
            Mechanism::RsaPkcsSha256 => CKM_SHA256_RSA_PKCS,
            Mechanism::RsaPkcsSha384 => CKM_SHA384_RSA_PKCS,
            Mechanism::RsaPkcsSha512 => CKM_SHA512_RSA_PKCS,
            Mechanism::RsaPss { .. } => CKM_RSA_PKCS_PSS,
        }
    }
}

impl TryFrom<Mechanism> for SignatureAlgorithm {
    type Error = ModuleError;

    fn try_from(mechanism: Mechanism) -> ModuleResult<Self> {
        match mechanism {
            Mechanism::Ecdsa => Ok(Self::Ecdsa),
            Mechanism::EdDsa => Ok(Self::EdDsa),
            Mechanism::RsaPkcs => Ok(Self::RsaPkcs1v15Raw),
            Mechanism::RsaPkcsSha1 => Ok(Self::RsaPkcs1v15Sha1),
            Mechanism::RsaPkcsSha256 => Ok(Self::RsaPkcs1v15Sha256),
            Mechanism::RsaPkcsSha384 => Ok(Self::RsaPkcs1v15Sha384),
            Mechanism::RsaPkcsSha512 => Ok(Self::RsaPkcs1v15Sha512),
            Mechanism::RsaPss {
                digest_algorithm,
                mask_generation_function,
                salt_length,
            } => Ok(Self::RsaPss {
                digest: digest_algorithm,
                mask_generation_function,
                salt_length,
            }),
            x => Err(ModuleError::AlgorithmNotSupported(format!("{x:?}"))),
        }
    }
}

impl TryFrom<Mechanism> for EncryptionAlgorithm {
    type Error = ModuleError;

    fn try_from(mechanism: Mechanism) -> ModuleResult<Self> {
        match mechanism {
            Mechanism::RsaPkcs => Ok(Self::RsaPkcs1v15),
            Mechanism::AesCbcPad { .. } => Ok(Self::AesCbcPad),
            Mechanism::AesCbc { .. } => Ok(Self::AesCbc),
            Mechanism::AesGcm { .. } => Ok(Self::AesGcm),
            x => Err(ModuleError::AlgorithmNotSupported(format!("{x:?}"))),
        }
    }
}

impl TryFrom<Mechanism> for KeyAlgorithm {
    type Error = ModuleError;

    fn try_from(mechanism: Mechanism) -> ModuleResult<Self> {
        match mechanism {
            // When generating AES key where `CKM_AES_KEY_GEN` is given as `Mechanism`, we assume an AES-256 key is required
            Mechanism::AesKeyGen => Ok(Self::Aes256),
            x => Err(ModuleError::AlgorithmNotSupported(format!("{x:?}"))),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use pkcs11_sys::CK_MECHANISM;

    use super::{
        AES_GCM_MAX_AAD_SIZE, AES_GCM_MAX_IV_SIZE, CK_GCM_PARAMS, CKM_AES_GCM, Mechanism,
        ModuleResult, parse_mechanism,
    };

    /// Build a `CK_MECHANISM`/`CK_GCM_PARAMS` pair for `CKM_AES_GCM` from the given raw
    /// `(iv, aad, tag_bits)` fields, keeping the backing buffers alive in the returned tuple so
    /// the pointers stashed in the mechanism remain valid for the caller's use.
    fn gcm_mechanism(
        iv: &mut [u8],
        aad: &mut [u8],
        tag_bits: pkcs11_sys::CK_ULONG,
    ) -> ModuleResult<(CK_MECHANISM, CK_GCM_PARAMS)> {
        let params = CK_GCM_PARAMS {
            pIv: iv.as_mut_ptr(),
            ulIvLen: pkcs11_sys::CK_ULONG::try_from(iv.len())?,
            ulIvBits: 0,
            pAAD: if aad.is_empty() {
                std::ptr::null_mut()
            } else {
                aad.as_mut_ptr()
            },
            ulAADLen: pkcs11_sys::CK_ULONG::try_from(aad.len())?,
            ulTagBits: tag_bits,
        };
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            // SAFETY: `&params` outlives this function call site since the caller receives
            // `params` back and must keep it (and `iv`/`aad`) alive while using `mechanism`.
            pParameter: (&raw const params).cast::<std::ffi::c_void>().cast_mut(),
            ulParameterLen: pkcs11_sys::CK_ULONG::try_from(std::mem::size_of::<CK_GCM_PARAMS>())?,
        };
        Ok((mechanism, params))
    }

    #[test]
    fn ckm_aes_gcm_valid_iv_and_aad_are_parsed() -> ModuleResult<()> {
        let mut iv = [0x42_u8; 12];
        let mut aad = [0x24_u8; 8];
        let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, 128)?;
        let parsed = unsafe { parse_mechanism(mechanism) }?;
        let Mechanism::AesGcm {
            iv: parsed_iv,
            aad: parsed_aad,
        } = parsed
        else {
            return Err(super::ModuleError::BadArguments(
                "expected Mechanism::AesGcm".to_owned(),
            ));
        };
        if parsed_iv != iv.to_vec() || parsed_aad != aad.to_vec() {
            return Err(super::ModuleError::BadArguments(
                "parsed iv/aad did not match input".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_empty_aad_is_parsed_as_empty_vec() -> ModuleResult<()> {
        let mut iv = [0x01_u8; 12];
        let mut aad: [u8; 0] = [];
        let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, 128)?;
        let parsed = unsafe { parse_mechanism(mechanism) }?;
        let Mechanism::AesGcm { aad, .. } = parsed else {
            return Err(super::ModuleError::BadArguments(
                "expected Mechanism::AesGcm".to_owned(),
            ));
        };
        if !aad.is_empty() {
            return Err(super::ModuleError::BadArguments(
                "expected empty AAD".to_owned(),
            ));
        }
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_rejects_non_128_bit_tag() -> ModuleResult<()> {
        let mut iv = [0x01_u8; 12];
        let mut aad: [u8; 0] = [];
        for tag_bits in [0, 64, 96, 120, 127, 129, 256] {
            let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, tag_bits)?;
            unsafe { parse_mechanism(mechanism) }.unwrap_err();
        }
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_rejects_zero_length_iv() -> ModuleResult<()> {
        let mut iv: [u8; 0] = [];
        let mut aad: [u8; 0] = [];
        let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, 128)?;
        unsafe { parse_mechanism(mechanism) }.unwrap_err();
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_rejects_oversized_iv() -> ModuleResult<()> {
        let mut iv = vec![0_u8; AES_GCM_MAX_IV_SIZE + 1];
        let mut aad: [u8; 0] = [];
        let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, 128)?;
        unsafe { parse_mechanism(mechanism) }.unwrap_err();
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_rejects_oversized_aad() -> ModuleResult<()> {
        let mut iv = [0x01_u8; 12];
        // AES_GCM_MAX_AAD_SIZE is 1 MiB; allocate one byte over that bound.
        let mut aad = vec![0_u8; AES_GCM_MAX_AAD_SIZE + 1];
        let (mechanism, _params) = gcm_mechanism(&mut iv, &mut aad, 128)?;
        unsafe { parse_mechanism(mechanism) }.unwrap_err();
        Ok(())
    }

    #[test]
    fn ckm_aes_gcm_rejects_wrong_parameter_size() {
        let mechanism = CK_MECHANISM {
            mechanism: CKM_AES_GCM,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 4,
        };
        unsafe { parse_mechanism(mechanism) }.unwrap_err();
    }
}

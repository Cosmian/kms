//! AES-CMAC (NIST SP 800-38B) and AES-GMAC (NIST SP 800-38D), one-shot and multi-part.
//!
//! Both are computed by the OpenSSL provider that is loaded (the FIPS provider in a FIPS
//! build): CMAC through the `CMAC` key / `EVP_DigestSign` path, GMAC through the provider's
//! `GMAC` `EVP_MAC`, which takes the IV as a parameter. GMAC is deliberately not AES-GCM with a
//! caller-supplied IV: OpenSSL classifies that GCM use as non-approved, the `GMAC` MAC is not.
//!
//! # GMAC wire format
//!
//! A GMAC nonce must never repeat under one key. KMIP MAC has no IV field, so the MAC value of
//! this module is `IV (12 bytes) || tag (16 bytes)`: the caller generates the IV, the verifier
//! reads it back with [`gmac_iv`].

use openssl::{md_ctx::MdCtx, pkey::PKey, symm::Cipher};

use crate::error::{CryptoError, result::CryptoResult};

/// Length in bytes of an AES-CMAC tag.
pub const CMAC_TAG_LENGTH: usize = 16;
/// Length in bytes of the IV of an AES-GMAC (96 bits, the SP 800-38D recommended size).
pub const GMAC_IV_LENGTH: usize = 12;
/// Length in bytes of an AES-GMAC tag.
pub const GMAC_TAG_LENGTH: usize = 16;
/// Length in bytes of an AES-GMAC MAC value: `IV || tag`.
pub const GMAC_MAC_LENGTH: usize = GMAC_IV_LENGTH + GMAC_TAG_LENGTH;

/// A running AES-CMAC or AES-GMAC.
pub enum AesMac {
    /// AES-CMAC.
    Cmac(MdCtx),
    /// AES-GMAC: the `EVP_MAC` context (IV already set) and the IV, which prefixes the result.
    Gmac {
        /// `GMAC` context fed with the message as additional authenticated data.
        ctx: evp_gmac::GmacCtx,
        /// IV the context was initialized with.
        iv: [u8; GMAC_IV_LENGTH],
    },
}

impl AesMac {
    /// Start an AES-CMAC with `key` (16, 24 or 32 bytes).
    ///
    /// # Errors
    /// Returns an error if the key length is not an AES key length or OpenSSL fails.
    pub fn new_cmac(key: &[u8]) -> CryptoResult<Self> {
        // The cipher only selects the AES key size: CMAC runs the block cipher in CBC.
        let cipher = match key.len() {
            16 => Cipher::aes_128_cbc(),
            24 => Cipher::aes_192_cbc(),
            32 => Cipher::aes_256_cbc(),
            len => return Err(invalid_key_length(len)),
        };
        let key = PKey::cmac(&cipher, key)?;
        let mut ctx = MdCtx::new()?;
        ctx.digest_sign_init(None, &key)?;
        Ok(Self::Cmac(ctx))
    }

    /// Start an AES-GMAC with `key` (16, 24 or 32 bytes) and the 12-byte `iv`.
    ///
    /// The IV MUST be unique per message under one key: generate it with the KMS random source.
    ///
    /// # Errors
    /// Returns an error if the key length is not an AES key length or OpenSSL fails.
    pub fn new_gmac(key: &[u8], iv: [u8; GMAC_IV_LENGTH]) -> CryptoResult<Self> {
        let cipher_name = match key.len() {
            16 => c"AES-128-GCM",
            24 => c"AES-192-GCM",
            32 => c"AES-256-GCM",
            len => return Err(invalid_key_length(len)),
        };
        let ctx = evp_gmac::GmacCtx::new(key, cipher_name, &iv)?;
        Ok(Self::Gmac { ctx, iv })
    }

    /// Authenticate the next part of the message.
    ///
    /// # Errors
    /// Returns an error if OpenSSL fails.
    pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
        match self {
            Self::Cmac(ctx) => ctx.digest_sign_update(data)?,
            Self::Gmac { ctx, .. } => ctx.update(data)?,
        }
        Ok(())
    }

    /// End the MAC: the 16-byte tag for CMAC, `IV || tag` (28 bytes) for GMAC.
    ///
    /// # Errors
    /// Returns an error if OpenSSL fails.
    pub fn finalize(&mut self) -> CryptoResult<Vec<u8>> {
        match self {
            Self::Cmac(ctx) => {
                let mut tag = Vec::with_capacity(CMAC_TAG_LENGTH);
                ctx.digest_sign_final_to_vec(&mut tag)?;
                Ok(tag)
            }
            Self::Gmac { ctx, iv } => Ok([iv.as_slice(), ctx.finalize()?.as_slice()].concat()),
        }
    }
}

/// Raw `EVP_MAC` FFI for GMAC: rust-openssl has no safe `EVP_MAC` wrapper.
#[expect(
    unsafe_code,
    reason = "raw EVP_MAC FFI; rust-openssl has no safe EVP_MAC wrapper"
)]
mod evp_gmac {
    use std::{
        ffi::{CStr, c_void},
        ptr::NonNull,
    };

    use openssl::error::ErrorStack;

    use super::{GMAC_IV_LENGTH, GMAC_TAG_LENGTH};
    use crate::error::{CryptoError, result::CryptoResult};

    /// `OSSL_PARAM_UTF8_STRING` (`openssl/core.h`); `openssl-sys` has no utf8 constructor.
    const OSSL_PARAM_UTF8_STRING: u32 = 4;

    /// A `GMAC` `EVP_MAC_CTX`, freed on drop.
    pub struct GmacCtx(NonNull<openssl_sys::EVP_MAC_CTX>);

    // SAFETY: the context is owned by exactly one `GmacCtx` and is only used through `&mut self`,
    // so it is never accessed from two threads at once; OpenSSL contexts may change thread
    // between calls.
    unsafe impl Send for GmacCtx {}

    impl GmacCtx {
        /// Start a `GMAC` with the AES-GCM cipher `cipher_name` (e.g. `AES-256-GCM`).
        pub fn new(
            key: &[u8],
            cipher_name: &CStr,
            iv: &[u8; GMAC_IV_LENGTH],
        ) -> CryptoResult<Self> {
            let mut iv = *iv;
            // SAFETY: the algorithm name is a NUL-terminated static; null libctx/properties select
            // the defaults. The context keeps its own reference to the `EVP_MAC`, so `mac` is
            // freed right after `EVP_MAC_CTX_new`.
            let ctx = unsafe {
                let mac = openssl_sys::EVP_MAC_fetch(
                    std::ptr::null_mut(),
                    c"GMAC".as_ptr(),
                    std::ptr::null(),
                );
                if mac.is_null() {
                    return Err(ErrorStack::get().into());
                }
                let ctx = openssl_sys::EVP_MAC_CTX_new(mac);
                openssl_sys::EVP_MAC_free(mac);
                NonNull::new(ctx).ok_or_else(|| CryptoError::from(ErrorStack::get()))?
            };
            // From here on `Drop` frees the context, whatever happens.
            let ctx = Self(ctx);
            // SAFETY: `cipher_name` and `iv` outlive the call and are only read by OpenSSL, which
            // reads the `cipher` parameter as a C string (hence the `CStr`, NUL-terminated; the
            // parameter size excludes the NUL); the array is terminated by
            // `OSSL_PARAM_construct_end`; `ctx` is a live `EVP_MAC_CTX`; `key` is readable for
            // `key.len()` bytes.
            let rc = unsafe {
                let mut cipher_param = openssl_sys::OSSL_PARAM_construct_octet_string(
                    c"cipher".as_ptr(),
                    cipher_name.as_ptr().cast_mut().cast::<c_void>(),
                    cipher_name.to_bytes().len(),
                );
                cipher_param.data_type = OSSL_PARAM_UTF8_STRING;
                let params = [
                    cipher_param,
                    openssl_sys::OSSL_PARAM_construct_octet_string(
                        c"iv".as_ptr(),
                        iv.as_mut_ptr().cast::<c_void>(),
                        iv.len(),
                    ),
                    openssl_sys::OSSL_PARAM_construct_end(),
                ];
                openssl_sys::EVP_MAC_init(ctx.0.as_ptr(), key.as_ptr(), key.len(), params.as_ptr())
            };
            if rc != 1 {
                return Err(ErrorStack::get().into());
            }
            Ok(ctx)
        }

        /// Authenticate the next part of the message.
        pub fn update(&mut self, data: &[u8]) -> CryptoResult<()> {
            if data.is_empty() {
                return Ok(());
            }
            // SAFETY: `self.0` is a live, initialized context; `data` is readable for `data.len()`.
            let rc =
                unsafe { openssl_sys::EVP_MAC_update(self.0.as_ptr(), data.as_ptr(), data.len()) };
            if rc == 1 {
                Ok(())
            } else {
                Err(ErrorStack::get().into())
            }
        }

        /// End the MAC and return the 16-byte tag.
        pub fn finalize(&mut self) -> CryptoResult<[u8; GMAC_TAG_LENGTH]> {
            let mut tag = [0_u8; GMAC_TAG_LENGTH];
            let mut written = 0_usize;
            // SAFETY: `self.0` is a live, initialized context; `tag` is writable for its length
            // and `written` receives the number of bytes produced (at most `tag.len()`).
            let rc = unsafe {
                openssl_sys::EVP_MAC_final(
                    self.0.as_ptr(),
                    tag.as_mut_ptr(),
                    &raw mut written,
                    tag.len(),
                )
            };
            if rc != 1 {
                return Err(ErrorStack::get().into());
            }
            if written != GMAC_TAG_LENGTH {
                return Err(CryptoError::InvalidSize(format!(
                    "AES-GMAC produced {written} tag bytes, expected {GMAC_TAG_LENGTH}"
                )));
            }
            Ok(tag)
        }
    }

    impl Drop for GmacCtx {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a live `EVP_MAC_CTX` freed exactly once, here.
            unsafe { openssl_sys::EVP_MAC_CTX_free(self.0.as_ptr()) };
        }
    }
}

/// One-shot AES-CMAC of `data` under `key`.
///
/// # Errors
/// Returns an error if the key length is not an AES key length or OpenSSL fails.
pub fn aes_cmac(key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut mac = AesMac::new_cmac(key)?;
    mac.update(data)?;
    mac.finalize()
}

/// One-shot AES-GMAC of `data` under `key` with `iv`; the result is `IV || tag`.
///
/// # Errors
/// Returns an error if the key length is not an AES key length or OpenSSL fails.
pub fn aes_gmac(key: &[u8], iv: [u8; GMAC_IV_LENGTH], data: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut mac = AesMac::new_gmac(key, iv)?;
    mac.update(data)?;
    mac.finalize()
}

/// The IV of an AES-GMAC MAC value (`IV || tag`).
///
/// # Errors
/// Returns an error if `mac` is not exactly [`GMAC_MAC_LENGTH`] bytes long.
pub fn gmac_iv(mac: &[u8]) -> CryptoResult<[u8; GMAC_IV_LENGTH]> {
    match mac.split_first_chunk::<GMAC_IV_LENGTH>() {
        Some((iv, tag)) if tag.len() == GMAC_TAG_LENGTH => Ok(*iv),
        _ => Err(CryptoError::InvalidSize(format!(
            "an AES-GMAC MAC is {GMAC_MAC_LENGTH} bytes (12-byte IV || 16-byte tag), got {}",
            mac.len()
        ))),
    }
}

fn invalid_key_length(len: usize) -> CryptoError {
    CryptoError::InvalidSize(format!(
        "an AES-CMAC/GMAC key is 16, 24 or 32 bytes long, got {len}"
    ))
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    const MESSAGE: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";

    /// NIST SP 800-38B Appendix D examples (AES-128, AES-192, AES-256).
    #[test]
    fn test_aes_cmac_sp_800_38b() -> CryptoResult<()> {
        let message = unhex(MESSAGE);
        let k128 = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let k192 = unhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        let k256 = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        for (key, len, expected) in [
            (&k128, 0, "bb1d6929e95937287fa37d129b756746"),
            (&k128, 16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (&k128, 40, "dfa66747de9ae63030ca32611497c827"),
            (&k128, 64, "51f0bebf7e3b9d92fc49741779363cfe"),
            (&k192, 0, "d17ddf46adaacde531cac483de7a9367"),
            (&k192, 16, "9e99a7bf31e710900662f65e617c5184"),
            (&k192, 40, "8a1de5be2eb31aad089a82e6ee908b0e"),
            (&k192, 64, "a1d5df0eed790f794d77589659f39a11"),
            (&k256, 0, "028962f61b7bf89efc6b551f4667d983"),
            (&k256, 16, "28a7023f452e8f82bd4bf28d8c37c35c"),
            (&k256, 40, "aaf3d8f1de5640c232f5b169b9c911e6"),
            (&k256, 64, "e1992190549f6ed5696a2c056c315410"),
        ] {
            assert_eq!(aes_cmac(key, &message[..len])?, unhex(expected));
        }
        Ok(())
    }

    /// A multi-part MAC equals the one-shot MAC, whatever the split.
    #[test]
    fn test_multi_part_equals_one_shot() -> CryptoResult<()> {
        let message = unhex(MESSAGE);
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = [7_u8; GMAC_IV_LENGTH];

        let mut cmac = AesMac::new_cmac(&key)?;
        let mut gmac = AesMac::new_gmac(&key, iv)?;
        for part in [&message[..1], &[], &message[1..37], &message[37..]] {
            cmac.update(part)?;
            gmac.update(part)?;
        }
        assert_eq!(cmac.finalize()?, aes_cmac(&key, &message)?);
        assert_eq!(gmac.finalize()?, aes_gmac(&key, iv, &message)?);
        Ok(())
    }

    /// Every official AES-CMAC vector (SP 800-38B, CAVP with truncated tags, Wycheproof, OpenSSL).
    #[test]
    fn test_aes_cmac_official_vectors() -> CryptoResult<()> {
        for v in crate::kat_vectors::aes_cmac_vectors()? {
            let mac = aes_cmac(&v.key, &v.msg)?;
            assert_eq!(mac[..v.tag.len()], v.tag[..], "{} ({})", v.id, v.source);
            let (head, tail) = v.msg.split_at(v.msg.len() / 2);
            let mut multi = AesMac::new_cmac(&v.key)?;
            multi.update(head)?;
            multi.update(tail)?;
            assert_eq!(multi.finalize()?, mac, "{} multi-part", v.id);
        }
        Ok(())
    }

    /// Every official AES-GMAC vector (OpenSSL NIST/IEEE 802.1AE, empty-plaintext GCM).
    #[test]
    fn test_aes_gmac_official_vectors() -> CryptoResult<()> {
        for v in crate::kat_vectors::aes_gmac_vectors()? {
            let iv: [u8; GMAC_IV_LENGTH] = v.iv[..].try_into().map_err(|e| {
                CryptoError::Default(format!("{}: IV is not {GMAC_IV_LENGTH} bytes: {e}", v.id))
            })?;
            let expected = [&v.iv[..], &v.tag[..]].concat();
            let mac = aes_gmac(&v.key, iv, &v.msg)?;
            assert_eq!(mac == expected, v.valid, "{} ({})", v.id, v.source);
            let (head, tail) = v.msg.split_at(v.msg.len() / 2);
            let mut multi = AesMac::new_gmac(&v.key, iv)?;
            multi.update(head)?;
            multi.update(tail)?;
            assert_eq!(multi.finalize()?, mac, "{} multi-part", v.id);
        }
        Ok(())
    }

    #[test]
    fn test_gmac_depends_on_iv_and_data() -> CryptoResult<()> {
        let key = [1_u8; 32];
        let base = aes_gmac(&key, [0; GMAC_IV_LENGTH], b"data")?;
        assert_eq!(base.len(), GMAC_MAC_LENGTH);
        assert_ne!(base, aes_gmac(&key, [1; GMAC_IV_LENGTH], b"data")?);
        assert_ne!(
            base[GMAC_IV_LENGTH..],
            aes_gmac(&key, [0; GMAC_IV_LENGTH], b"datb")?[GMAC_IV_LENGTH..]
        );
        Ok(())
    }

    #[test]
    fn test_rejects_bad_key_and_mac_lengths() {
        for len in [0, 15, 17, 31, 64] {
            aes_cmac(&vec![0; len], b"x").unwrap_err();
            aes_gmac(&vec![0; len], [0; GMAC_IV_LENGTH], b"x").unwrap_err();
        }
        for len in [0, 12, 16, 27, 29] {
            gmac_iv(&vec![0; len]).unwrap_err();
        }
    }
}

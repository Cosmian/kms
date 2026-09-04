use std::ptr;

use cosmian_kms_interfaces::EcCurve;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CKA_EC_PARAMS, CKA_EXTRACTABLE, CKA_ID, CKA_KEY_TYPE,
    CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKK_EC,
    CKM_EC_KEY_PAIR_GEN,
};

use crate::{HError, HResult, hsm_call, session::Session};

/// DER-encoded `ASN.1 OBJECT IDENTIFIER` for each FIPS-approved NIST prime curve supported for
/// HSM-delegated EC key generation, as required by the PKCS#11 `CKA_EC_PARAMS` attribute.
#[must_use]
pub(crate) const fn curve_der_oid(curve: EcCurve) -> &'static [u8] {
    match curve {
        // secp224r1 (1.3.132.0.33)
        EcCurve::P224 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21],
        // prime256v1 / secp256r1 (1.2.840.10045.3.1.7)
        EcCurve::P256 => &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // secp384r1 (1.3.132.0.34)
        EcCurve::P384 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22],
        // secp521r1 (1.3.132.0.35)
        EcCurve::P521 => &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23],
    }
}

/// Recover the `EcCurve` matching a DER-encoded `CKA_EC_PARAMS` value read back from the HSM.
pub(crate) fn curve_from_der_oid(oid: &[u8]) -> HResult<EcCurve> {
    for curve in [EcCurve::P224, EcCurve::P256, EcCurve::P384, EcCurve::P521] {
        if curve_der_oid(curve) == oid {
            return Ok(curve);
        }
    }
    Err(HError::Default(format!(
        "Unsupported or non-FIPS EC curve OID: {oid:02x?}"
    )))
}

/// The curve's field element size, in bytes (used to size the `CKA_VALUE` private scalar and
/// to split the raw `r || s` ECDSA signature).
#[must_use]
pub(crate) const fn curve_byte_size(curve: EcCurve) -> usize {
    match curve {
        EcCurve::P224 => 28,
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
        // 521 bits -> ceil(521 / 8) = 66 bytes
        EcCurve::P521 => 66,
    }
}

impl Session {
    /// Generate an EC key pair and return the private and public key handles in this order.
    ///
    /// Only FIPS-approved NIST prime curves (P-224/P-256/P-384/P-521) are supported.
    ///
    /// If exportable is set to `false`, the `sensitive` flag is set to true, and the private
    /// key will not be exportable.
    /// # Arguments
    /// * `sk_id` - The ID of the private key
    /// * `pk_id` - The ID of the public key
    /// * `curve` - The NIST curve to use
    /// * `sensitive` - If the private key is sensitive
    /// # Returns
    /// * `Ok((HsmId, HsmId))` - The private and public key handles
    pub fn generate_ec_key_pair(
        &self,
        sk_id: &[u8],
        pk_id: &[u8],
        curve: EcCurve,
        sensitive: bool,
    ) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let ec_params = curve_der_oid(curve);
        let sensitive = if sensitive { CK_TRUE } else { CK_FALSE };

        let mut pub_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_EC)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ec_params.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(ec_params.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_VERIFY,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
        ];
        // AES/RSA-style wrap/encrypt flags do not apply to EC keys — only sign/verify are set
        // (matching PKCS#11's CKA_SIGN/CKA_VERIFY convention for EC keys).

        let mut priv_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_EC)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_ID,
                pValue: sk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(sk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SIGN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: (&raw const sensitive).cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXTRACTABLE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
        ];
        // CKA_ENCRYPT/CKA_DECRYPT/CKA_WRAP/CKA_UNWRAP are intentionally omitted for EC keys —
        // ECDSA private keys are used only for CKA_SIGN, matching the KMIP EC private key usage
        // mask set by the software EC key generation path.

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut pub_key_handle = CK_OBJECT_HANDLE::default();
        let mut priv_key_handle = CK_OBJECT_HANDLE::default();
        let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;

        hsm_call!(
            self.hsm(),
            "Failed generating EC key pair",
            C_GenerateKeyPair,
            self.session_handle(),
            p_mechanism,
            pub_key_template.as_mut_ptr(),
            CK_ULONG::try_from(pub_key_template.len())?,
            priv_key_template.as_mut_ptr(),
            CK_ULONG::try_from(priv_key_template.len())?,
            &raw mut pub_key_handle,
            &raw mut priv_key_handle
        );

        self.object_handles_cache()
            .insert(sk_id.to_vec(), priv_key_handle)?;
        self.object_handles_cache()
            .insert(pk_id.to_vec(), pub_key_handle)?;

        Ok((priv_key_handle, pub_key_handle))
    }
}

use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR, CK_OBJECT_CLASS,
    CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CKA_CLASS, CKA_EC_PARAMS, CKA_EXTRACTABLE, CKA_ID,
    CKA_KEY_TYPE, CKA_LABEL, CKA_PRIVATE, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VERIFY,
    CKK_EC_EDWARDS, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY,
};

use crate::{HResult, hsm_call, session::Session};

/// DER encoding of the Ed25519 curve OID `1.3.101.112` (RFC 8410 §3), as required
/// in the `CKA_EC_PARAMS` attribute for `CKK_EC_EDWARDS` keys (OASIS Cryptoki v3.0
/// §2.3.9, `CKM_EC_EDWARDS_KEY_PAIR_GEN`).
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2B, 0x65, 0x70];

impl Session {
    /// Generate an Ed25519 (`EdDSA`) key pair and return the `(private, public)` key
    /// handles, in that order.
    ///
    /// Requires the loaded PKCS#11 library to support `CKM_EC_EDWARDS_KEY_PAIR_GEN`
    /// (OASIS Cryptoki v3.0 §2.3.9). This is an optional v3.0 mechanism: any v2.40-only
    /// library, and some v3.0 libraries, will not support it — callers should check
    /// `SlotManager::get_supported_mechanisms`/`get_mechanism_info` beforehand, or
    /// simply handle the resulting `CKR_MECHANISM_INVALID` error gracefully.
    ///
    /// If `sensitive` is `false`, the private key is exportable via `Session::export_key`.
    pub fn generate_eddsa_key_pair(
        &self,
        sk_id: &[u8],
        pk_id: &[u8],
        sensitive: bool,
    ) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
        let mut ec_params = ED25519_OID_DER;

        let mut pub_key_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: std::ptr::from_ref(&CKO_PUBLIC_KEY)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_EC_EDWARDS)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ec_params.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(ec_params.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_VERIFY,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
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
        ];

        let mut priv_key_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: std::ptr::from_ref(&CKO_PRIVATE_KEY)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_EC_EDWARDS)
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
        ];

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_key_handle = CK_OBJECT_HANDLE::default();
        let mut priv_key_handle = CK_OBJECT_HANDLE::default();
        let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;

        hsm_call!(
            self.hsm(),
            "Failed generating EdDSA (Ed25519) key pair",
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

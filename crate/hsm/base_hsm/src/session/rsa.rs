use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_RSA_PKCS_OAEP_PARAMS, CK_TRUE, CK_ULONG, CKA_CLASS, CKA_DECRYPT,
    CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS_BITS, CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VERIFY, CKA_WRAP,
    CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKK_AES, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS_OAEP,
    CKM_SHA_1, CKM_SHA256, CKO_SECRET_KEY, CKZ_DATA_SPECIFIED,
};

use crate::{HResult, hsm_call, session::Session};

#[derive(Debug, Clone, Copy)]
pub enum RsaKeySize {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

#[derive(Debug, Clone, Copy)]
pub enum RsaOaepDigest {
    SHA1,
    SHA256,
}

impl Session {
    /// Generate RSA key pair and return the private and public key handles
    /// in this order
    ///
    /// If exportable is set to `false`, the `sensitive` flag is set to true,
    /// and the private key will not be exportable.
    /// # Arguments
    /// * `sk_id` - The ID of the private key
    /// * `pk_id` - The ID of the public key
    /// * `key_size` - The size of the RSA key
    /// * `label` - The label of the keys
    /// * `sensitive` - If the private key is sensitive
    /// # Returns
    /// * `Ok((HsmId, HsmId))` - The private and public key handles
    pub fn generate_rsa_key_pair(
        &self,
        sk_id: &[u8],
        pk_id: &[u8],
        key_size: RsaKeySize,
        sensitive: bool,
    ) -> HResult<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let key_size: usize = match key_size {
            RsaKeySize::Rsa1024 => 1024,
            RsaKeySize::Rsa2048 => 2048,
            RsaKeySize::Rsa3072 => 3072,
            RsaKeySize::Rsa4096 => 4096,
        };
        let public_exponent: [u8; 3] = [0x01, 0x00, 0x01];
        let sensitive = if sensitive { CK_TRUE } else { CK_FALSE };
        let mut pub_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_RSA)
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
                type_: CKA_ENCRYPT,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS_BITS,
                pValue: (&raw const key_size).cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent
                    .as_ptr()
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(public_exponent.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: pk_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(pk_id.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_WRAP,
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
        ];

        let mut priv_key_template = vec![
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_RSA)
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
                type_: CKA_DECRYPT,
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
                type_: CKA_UNWRAP,
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
        ];

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        let mut pub_key_handle = CK_OBJECT_HANDLE::default();
        let mut priv_key_handle = CK_OBJECT_HANDLE::default();
        let p_mechanism: CK_MECHANISM_PTR = &raw mut mechanism;

        hsm_call!(
            self.hsm(),
            "Failed generating RSA key pair",
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

    pub fn wrap_aes_key_with_rsa_oaep(
        &self,
        wrapping_key_handle: CK_OBJECT_HANDLE,
        aes_key_handle: CK_OBJECT_HANDLE,
        digest: RsaOaepDigest,
    ) -> HResult<Vec<u8>> {
        // Initialize the RSA-OAEP mechanism
        let mut oaep_params = match digest {
            RsaOaepDigest::SHA256 => CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            },
            RsaOaepDigest::SHA1 => CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA_1,
                mgf: CKG_MGF1_SHA1,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            },
        };

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: (&raw mut oaep_params).cast::<std::ffi::c_void>(),
            ulParameterLen: CK_ULONG::try_from(size_of::<CK_RSA_PKCS_OAEP_PARAMS>())?,
        };

        // Determine the length of the wrapped key
        let mut wrapped_key_len: CK_ULONG = 0;
        hsm_call!(
            self.hsm(),
            "Failed to get wrapped key length",
            C_WrapKey,
            self.session_handle(),
            &raw mut mechanism,
            wrapping_key_handle,
            aes_key_handle,
            ptr::null_mut(),
            &raw mut wrapped_key_len
        );

        // Allocate buffer for the wrapped key
        let mut wrapped_key = vec![0_u8; usize::try_from(wrapped_key_len)?];

        // Wrap the key
        hsm_call!(
            self.hsm(),
            "Failed to wrap key",
            C_WrapKey,
            self.session_handle(),
            &raw mut mechanism,
            wrapping_key_handle,
            aes_key_handle,
            wrapped_key.as_mut_ptr(),
            &raw mut wrapped_key_len
        );

        // Truncate the buffer to the actual size of the wrapped key
        wrapped_key.truncate(usize::try_from(wrapped_key_len)?);
        Ok(wrapped_key)
    }

    pub fn unwrap_aes_key_with_rsa_oaep(
        &self,
        unwrapping_key_handle: CK_OBJECT_HANDLE,
        wrapped_aes_key: &[u8],
        aes_key_label: &str,
        digest: RsaOaepDigest,
    ) -> HResult<CK_OBJECT_HANDLE> {
        let mut wrapped_key = wrapped_aes_key.to_vec();
        // Initialize the RSA-OAEP mechanism
        let mut oaep_params = match digest {
            RsaOaepDigest::SHA256 => CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA256,
                mgf: CKG_MGF1_SHA256,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            },
            RsaOaepDigest::SHA1 => CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: CKM_SHA_1,
                mgf: CKG_MGF1_SHA1,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            },
        };

        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_OAEP,
            pParameter: (&raw mut oaep_params).cast::<std::ffi::c_void>(),
            ulParameterLen: CK_ULONG::try_from(size_of::<CK_RSA_PKCS_OAEP_PARAMS>())?,
        };

        // Unwrap the key
        let mut aes_key_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: std::ptr::from_ref(&CKO_SECRET_KEY)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_AES)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_TOKEN,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: aes_key_label.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
                ulValueLen: CK_ULONG::try_from(aes_key_label.len())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_SENSITIVE,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
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
                type_: CKA_ENCRYPT,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_DECRYPT,
                pValue: std::ptr::from_ref(&CK_TRUE)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
            },
        ];
        let mut unwrapped_key_handle: CK_OBJECT_HANDLE = 0;
        hsm_call!(
            self.hsm(),
            "Failed to unwrap key",
            C_UnwrapKey,
            self.session_handle(),
            &raw mut mechanism,
            unwrapping_key_handle,
            wrapped_key.as_mut_ptr(),
            CK_ULONG::try_from(wrapped_key.len())?,
            aes_key_template.as_mut_ptr(),
            CK_ULONG::try_from(aes_key_template.len())?,
            &raw mut unwrapped_key_handle
        );

        Ok(unwrapped_key_handle)
    }
}

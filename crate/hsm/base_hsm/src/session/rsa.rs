use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_RSA_PKCS_OAEP_PARAMS, CK_TRUE, CK_ULONG, CK_VOID_PTR, CKA_CLASS,
    CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS_BITS,
    CKA_PRIVATE, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_UNWRAP, CKA_VERIFY,
    CKA_WRAP, CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKK_AES, CKK_RSA, CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP, CKM_SHA_1, CKM_SHA256, CKO_SECRET_KEY, CKR_OK, CKZ_DATA_SPECIFIED,
};

use crate::{HError, HResult, session::Session};

pub enum RsaKeySize {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

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
        unsafe {
            let mut pub_key_template = vec![
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_ENCRYPT,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_MODULUS_BITS,
                    pValue: &raw const key_size as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_PUBLIC_EXPONENT,
                    pValue: public_exponent.as_ptr() as CK_VOID_PTR,
                    ulValueLen: public_exponent.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: pk_id.as_ptr() as CK_VOID_PTR,
                    ulValueLen: pk_id.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_WRAP,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_VERIFY,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
            ];

            let mut priv_key_template = vec![
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_PRIVATE,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_DECRYPT,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: sk_id.as_ptr() as CK_VOID_PTR,
                    ulValueLen: sk_id.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_UNWRAP,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_SIGN,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_SENSITIVE,
                    pValue: &raw const sensitive as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_EXTRACTABLE,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
            ];

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter: ptr::null_mut(),
                ulParameterLen: 0,
            };

            let mut pub_key_handle = CK_OBJECT_HANDLE::default();
            let mut priv_key_handle = CK_OBJECT_HANDLE::default();
            let pMechanism: CK_MECHANISM_PTR = &raw mut mechanism;

            let rv = self.hsm().C_GenerateKeyPair.ok_or_else(|| {
                HError::Default("C_GenerateKeyPair not available on library".to_string())
            })?(
                self.session_handle(),
                pMechanism,
                pub_key_template.as_mut_ptr(),
                pub_key_template.len() as CK_ULONG,
                priv_key_template.as_mut_ptr(),
                priv_key_template.len() as CK_ULONG,
                &raw mut pub_key_handle,
                &raw mut priv_key_handle,
            );

            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed generating RSA key pair: {rv}"
                )));
            }

            self.object_handles_cache()
                .insert(sk_id.to_vec(), priv_key_handle);
            self.object_handles_cache()
                .insert(pk_id.to_vec(), pub_key_handle);

            Ok((priv_key_handle, pub_key_handle))
        }
    }

    pub fn wrap_aes_key_with_rsa_oaep(
        &self,
        wrapping_key_handle: CK_OBJECT_HANDLE,
        aes_key_handle: CK_OBJECT_HANDLE,
        digest: RsaOaepDigest,
    ) -> HResult<Vec<u8>> {
        unsafe {
            // Initialize the RSA-OAEP mechanism
            let mut oaep_params = match digest {
                RsaOaepDigest::SHA256 => CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA256,
                    mgf: CKG_MGF1_SHA256,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: ptr::null_mut(),
                    ulSourceDataLen: 0_usize as CK_ULONG,
                },
                RsaOaepDigest::SHA1 => CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA_1,
                    mgf: CKG_MGF1_SHA1,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: ptr::null_mut(),
                    ulSourceDataLen: 0_usize as CK_ULONG,
                },
            };

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_OAEP,
                pParameter: &raw mut oaep_params as CK_VOID_PTR,
                ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            };

            // Determine the length of the wrapped key
            let mut wrapped_key_len: CK_ULONG = 0;
            let rv = self
                .hsm()
                .C_WrapKey
                .ok_or_else(|| HError::Default("C_WrapKey not available on library".to_string()))?(
                self.session_handle(),
                &raw mut mechanism,
                wrapping_key_handle,
                aes_key_handle,
                ptr::null_mut(),
                &raw mut wrapped_key_len,
            );

            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to get wrapped key length: {rv}"
                )));
            }

            // Allocate buffer for the wrapped key
            let mut wrapped_key = vec![0u8; wrapped_key_len as usize];

            // Wrap the key
            let rv = self
                .hsm()
                .C_WrapKey
                .ok_or_else(|| HError::Default("C_WrapKey not available on library".to_string()))?(
                self.session_handle(),
                &raw mut mechanism,
                wrapping_key_handle,
                aes_key_handle,
                wrapped_key.as_mut_ptr(),
                &raw mut wrapped_key_len,
            );

            if rv != CKR_OK {
                return Err(HError::Default("Failed to wrap key".to_string()));
            }

            // Truncate the buffer to the actual size of the wrapped key
            wrapped_key.truncate(wrapped_key_len as usize);
            Ok(wrapped_key)
        }
    }

    pub fn unwrap_aes_key_with_rsa_oaep(
        &self,
        unwrapping_key_handle: CK_OBJECT_HANDLE,
        wrapped_aes_key: &[u8],
        aes_key_label: &str,
        digest: RsaOaepDigest,
    ) -> HResult<CK_OBJECT_HANDLE> {
        let mut wrapped_key = wrapped_aes_key.to_vec();
        unsafe {
            // Initialize the RSA-OAEP mechanism
            let mut oaep_params = match digest {
                RsaOaepDigest::SHA256 => CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA256,
                    mgf: CKG_MGF1_SHA256,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: ptr::null_mut(),
                    ulSourceDataLen: 0_usize as CK_ULONG,
                },
                RsaOaepDigest::SHA1 => CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA_1,
                    mgf: CKG_MGF1_SHA1,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: ptr::null_mut(),
                    ulSourceDataLen: 0_usize as CK_ULONG,
                },
            };

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_OAEP,
                pParameter: &raw mut oaep_params as CK_VOID_PTR,
                ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            };

            // Unwrap the key
            let mut aes_key_template = [
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_SECRET_KEY) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_AES) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_TOKEN,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: aes_key_label.as_ptr() as CK_VOID_PTR,
                    ulValueLen: aes_key_label.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_PRIVATE,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_SENSITIVE,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_EXTRACTABLE,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_ENCRYPT,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_DECRYPT,
                    pValue: std::ptr::from_ref(&CK_TRUE) as CK_VOID_PTR,
                    ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                },
            ];
            let mut unwrapped_key_handle: CK_OBJECT_HANDLE = 0;
            let rv = self.hsm().C_UnwrapKey.ok_or_else(|| {
                HError::Default("C_UnwrapKey not available on library".to_string())
            })?(
                self.session_handle(),
                &raw mut mechanism,
                unwrapping_key_handle,
                wrapped_key.as_mut_ptr(),
                wrapped_key.len() as CK_ULONG,
                aes_key_template.as_mut_ptr(),
                aes_key_template.len() as CK_ULONG,
                &raw mut unwrapped_key_handle,
            );

            if rv != CKR_OK {
                return Err(HError::Default("Failed to unwrap key".to_string()));
            }

            Ok(unwrapped_key_handle)
        }
    }
}

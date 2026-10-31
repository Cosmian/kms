//! AES-KW (NIST SP 800-38F KW, RFC 3394) and AES-KWP (NIST SP 800-38F KWP, RFC 5649) of raw
//! key bytes under an HSM AES key. Neither mode uses an IV.

use std::ptr;

use pkcs11_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_OBJECT_HANDLE, CK_TRUE, CK_ULONG, CKA_CLASS,
    CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_PRIVATE, CKA_SENSITIVE, CKA_TOKEN, CKA_UNWRAP, CKA_VALUE,
    CKA_WRAP, CKK_GENERIC_SECRET, CKO_SECRET_KEY,
};
use zeroize::Zeroizing;

use crate::{
    HResult,
    base_hsm::AesKeyWrapMechanism,
    hsm_call,
    session::{Session, session_impl::checked_output_length},
};

fn ulong_attribute(type_: CK_ULONG, value: &CK_ULONG) -> HResult<CK_ATTRIBUTE> {
    Ok(CK_ATTRIBUTE {
        type_,
        pValue: ptr::from_ref(value).cast::<std::ffi::c_void>().cast_mut(),
        ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
    })
}

fn bool_attribute(type_: CK_ULONG, value: &CK_BBOOL) -> HResult<CK_ATTRIBUTE> {
    Ok(CK_ATTRIBUTE {
        type_,
        pValue: ptr::from_ref(value).cast::<std::ffi::c_void>().cast_mut(),
        ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
    })
}

/// Template of the ephemeral, extractable session object carrying the bytes to (un)wrap.
fn ephemeral_secret_template() -> HResult<Vec<CK_ATTRIBUTE>> {
    Ok(vec![
        ulong_attribute(CKA_CLASS, &CKO_SECRET_KEY)?,
        ulong_attribute(CKA_KEY_TYPE, &CKK_GENERIC_SECRET)?,
        bool_attribute(CKA_TOKEN, &CK_FALSE)?,
        bool_attribute(CKA_PRIVATE, &CK_TRUE)?,
        bool_attribute(CKA_SENSITIVE, &CK_FALSE)?,
        bool_attribute(CKA_EXTRACTABLE, &CK_TRUE)?,
    ])
}

impl Session {
    /// Set `CKA_WRAP` and `CKA_UNWRAP` on `key_handle`, so AES-KW/KWP can use `C_WrapKey`.
    pub fn set_wrap_attributes(&self, key_handle: CK_OBJECT_HANDLE, enabled: bool) -> HResult<()> {
        let value = if enabled { CK_TRUE } else { CK_FALSE };
        let mut template = [
            bool_attribute(CKA_WRAP, &value)?,
            bool_attribute(CKA_UNWRAP, &value)?,
        ];
        hsm_call!(
            self.hsm(),
            format!("Failed to set CKA_WRAP/CKA_UNWRAP on key handle {key_handle}"),
            C_SetAttributeValue,
            self.session_handle(),
            key_handle,
            template.as_mut_ptr(),
            CK_ULONG::try_from(template.len())?
        );
        Ok(())
    }

    /// Wrap `data` under the AES key `kek` with AES-KW or AES-KWP.
    pub(crate) fn aes_key_wrap(
        &self,
        kek: CK_OBJECT_HANDLE,
        m: AesKeyWrapMechanism,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut mechanism = CK_MECHANISM {
            mechanism: m.mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        if m.single_part {
            return self.encrypt_with_mechanism(kek, &mut mechanism, data);
        }

        let mut template = ephemeral_secret_template()?;
        template.push(CK_ATTRIBUTE {
            type_: CKA_VALUE,
            pValue: data.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(data.len())?,
        });
        let mut tmp: CK_OBJECT_HANDLE = 0;
        hsm_call!(
            self.hsm(),
            "Failed to create the ephemeral object to wrap",
            C_CreateObject,
            self.session_handle(),
            template.as_mut_ptr(),
            CK_ULONG::try_from(template.len())?,
            &raw mut tmp
        );

        let wrapped = (|| -> HResult<Vec<u8>> {
            // RFC 3394/5649 output bound; no length probe (SoftHSM2 rejects probes).
            let mut wrapped = vec![0_u8; data.len().div_ceil(8) * 8 + 8];
            let mut wrapped_len = CK_ULONG::try_from(wrapped.len())?;
            hsm_call!(
                self.hsm(),
                "Failed to wrap key",
                C_WrapKey,
                self.session_handle(),
                &raw mut mechanism,
                kek,
                tmp,
                wrapped.as_mut_ptr(),
                &raw mut wrapped_len
            );
            wrapped.truncate(checked_output_length(wrapped_len, wrapped.len())?);
            Ok(wrapped)
        })();
        let destroyed = self.destroy_object(tmp);
        let wrapped = wrapped?;
        destroyed?;
        Ok(wrapped)
    }

    /// Unwrap AES-KW or AES-KWP `wrapped` bytes under the AES key `kek`.
    pub(crate) fn aes_key_unwrap(
        &self,
        kek: CK_OBJECT_HANDLE,
        m: AesKeyWrapMechanism,
        wrapped: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        let mut mechanism = CK_MECHANISM {
            mechanism: m.mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        if m.single_part {
            return self.decrypt_with_mechanism(kek, &mut mechanism, wrapped);
        }

        let mut wrapped = wrapped.to_vec();
        let mut template = ephemeral_secret_template()?;
        let mut tmp: CK_OBJECT_HANDLE = 0;
        hsm_call!(
            self.hsm(),
            "Failed to unwrap key",
            C_UnwrapKey,
            self.session_handle(),
            &raw mut mechanism,
            kek,
            wrapped.as_mut_ptr(),
            CK_ULONG::try_from(wrapped.len())?,
            template.as_mut_ptr(),
            CK_ULONG::try_from(template.len())?,
            &raw mut tmp
        );

        let value = (|| -> HResult<Zeroizing<Vec<u8>>> {
            let mut value_template = [CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            }];
            self.call_get_attributes(tmp, &mut value_template)?
                .ok_or_else(|| crate::HError::Default("unwrapped object vanished".to_owned()))?;
            let length = checked_output_length(value_template[0].ulValueLen, wrapped.len())?;
            let mut value = Zeroizing::new(vec![0_u8; length]);
            value_template[0].pValue = value.as_mut_ptr().cast::<std::ffi::c_void>();
            self.call_get_attributes(tmp, &mut value_template)?
                .ok_or_else(|| crate::HError::Default("unwrapped object vanished".to_owned()))?;
            let length = checked_output_length(value_template[0].ulValueLen, value.len())?;
            value.truncate(length);
            Ok(value)
        })();
        let destroyed = self.destroy_object(tmp);
        let value = value?;
        destroyed?;
        Ok(value)
    }
}

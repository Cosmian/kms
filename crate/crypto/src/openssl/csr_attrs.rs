//! Access to PKCS#10 request attributes not exposed by the safe `openssl` API.
#![allow(unsafe_code)]

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKeyRef, Private},
    x509::{X509Req, X509ReqRef},
};

use super::cms_ffi::attribute_string_bytes;
use crate::error::CryptoError;

/// Return a copy of `req` carrying the PKCS#9 `challengePassword` attribute
/// (RFC 2985 §5.4.1), re-signed with `key` (SHA-256) so that the proof of possession remains
/// valid. This is what a SCEP client puts in its `PKCSReq` (RFC 8894 §3.2.1.1).
///
/// # Errors
/// Fails when the request cannot be copied, extended or re-signed.
pub fn csr_with_challenge_password(
    req: &X509ReqRef,
    key: &PKeyRef<Private>,
    password: &str,
) -> Result<X509Req, CryptoError> {
    let req = X509Req::from_der(&req.to_der()?)?;
    let len = i32::try_from(password.len())?;
    // SAFETY: `req` is a live, uniquely owned X509_REQ; `X509_REQ_add1_attr_by_NID` copies the
    // `len` bytes of `password`, which are readable for the duration of the call.
    let added = unsafe {
        openssl_sys::X509_REQ_add1_attr_by_NID(
            req.as_ptr(),
            Nid::PKCS9_CHALLENGEPASSWORD.as_raw(),
            openssl_sys::V_ASN1_PRINTABLESTRING,
            password.as_ptr(),
            len,
        )
    };
    if added != 1 {
        return Err(openssl::error::ErrorStack::get().into());
    }
    // SAFETY: `req` and `key` are live; `X509_REQ_sign` returns the signature size, 0 on error.
    let signed = unsafe {
        openssl_sys::X509_REQ_sign(req.as_ptr(), key.as_ptr(), MessageDigest::sha256().as_ptr())
    };
    if signed <= 0 {
        return Err(openssl::error::ErrorStack::get().into());
    }
    Ok(req)
}

/// Return the PKCS#9 `challengePassword` attribute of a certification request, if present
/// and string-typed (RFC 2985 §5.4.1).
#[must_use]
pub fn csr_challenge_password(req: &X509ReqRef) -> Option<String> {
    // SAFETY: `req` is a live X509_REQ; the attribute pointer returned by `X509_REQ_get_attr`
    // is owned by the request and only used while `req` is borrowed.
    let bytes = unsafe {
        let idx = openssl_sys::X509_REQ_get_attr_by_NID(
            req.as_ptr(),
            openssl_sys::NID_pkcs9_challengePassword,
            -1,
        );
        if idx < 0 {
            return None;
        }
        attribute_string_bytes(openssl_sys::X509_REQ_get_attr(req.as_ptr(), idx))
    }?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use openssl::{pkey::PKey, rsa::Rsa, x509::X509NameBuilder};

    use super::*;

    fn build(password: Option<&str>) -> X509Req {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "d").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let req = b.build();
        match password {
            Some(p) => csr_with_challenge_password(&req, &key, p).unwrap(),
            None => req,
        }
    }

    #[test]
    fn challenge_password_is_extracted_or_absent() {
        assert_eq!(
            csr_challenge_password(&build(Some("SecretChallenge123"))).as_deref(),
            Some("SecretChallenge123")
        );
        assert_eq!(csr_challenge_password(&build(None)), None);
        // The re-signed request keeps a valid proof of possession.
        let req = build(Some("pw"));
        assert!(req.verify(&req.public_key().unwrap()).unwrap());
    }
}

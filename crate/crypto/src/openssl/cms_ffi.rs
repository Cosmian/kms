//! Raw FFI bindings for CMS functions absent from `openssl-sys` 0.9.x.
//!
//! `openssl-sys` only declares the one-shot `CMS_sign` / `CMS_verify` /
//! `CMS_encrypt` / `CMS_decrypt` entry points.  SCEP (RFC 8894 §3.2.1) requires
//! custom CMS *signed attributes* (`transactionID`, `messageType`, `senderNonce`, …)
//! to be injected into the `SignerInfo` and read back from a received message,
//! which needs the "partial" CMS building API declared here.
//!
//! # Safety policy
//! Every function here is `unsafe`; callers are responsible for:
//! - passing non-null pointers where the C API requires non-null,
//! - freeing returned owned pointers with the matching `_free` function,
//! - ensuring that lifetimes of passed-in objects exceed the call.
//!
//! All `unsafe` call sites in the rest of the crate must carry a `// SAFETY:`
//! comment.
//!
//! This module is intentionally allowed to use `unsafe` code: it is the FFI
//! boundary layer and cannot be expressed without `unsafe extern` blocks.
#![allow(unsafe_code)]
// FFI declarations: not every binding is called at compile time; dead_code is expected.
#![allow(dead_code)]

use std::ffi::{c_int, c_uint, c_void};

use openssl_sys::{
    ASN1_OBJECT, ASN1_OCTET_STRING, BIO, CMS_ContentInfo, EVP_MD, EVP_PKEY, OPENSSL_STACK, X509,
    X509_ATTRIBUTE,
};

/// An opaque pointer to `CMS_SignerInfo` (not exposed by openssl-sys).
#[allow(non_camel_case_types)]
pub(crate) enum CMS_SignerInfo {}

unsafe extern "C" {
    /// `CMS_add1_signer` — add a signer to a (partial) `SignedData` structure.
    ///
    /// Returns the new `CMS_SignerInfo` (owned by `cms`, do **not** free) or null on error.
    pub(crate) fn CMS_add1_signer(
        cms: *mut CMS_ContentInfo,
        signer: *mut X509,
        pk: *mut EVP_PKEY,
        md: *const EVP_MD,
        flags: c_uint,
    ) -> *mut CMS_SignerInfo;

    /// `CMS_get0_SignerInfos` — the `STACK_OF(CMS_SignerInfo)` of a `SignedData`.
    ///
    /// The returned stack is owned by `cms`; do **not** free.
    pub(crate) fn CMS_get0_SignerInfos(cms: *mut CMS_ContentInfo) -> *mut OPENSSL_STACK;

    /// `CMS_SignerInfo_get0_algs` — retrieve the signer key / certificate / algorithms.
    ///
    /// The signer certificate is only populated after a successful `CMS_verify`.
    /// Every out-pointer may be null.
    pub(crate) fn CMS_SignerInfo_get0_algs(
        si: *mut CMS_SignerInfo,
        pk: *mut *mut EVP_PKEY,
        signer: *mut *mut X509,
        pdig: *mut *mut c_void,
        psig: *mut *mut c_void,
    );

    /// `CMS_signed_add1_attr_by_OBJ` — add a signed attribute.  Returns 1 on success.
    pub(crate) fn CMS_signed_add1_attr_by_OBJ(
        si: *mut CMS_SignerInfo,
        obj: *const ASN1_OBJECT,
        ty: c_int,
        bytes: *const c_void,
        len: c_int,
    ) -> c_int;

    /// `CMS_signed_get_attr_by_OBJ` — index of the signed attribute, or -1.
    pub(crate) fn CMS_signed_get_attr_by_OBJ(
        si: *const CMS_SignerInfo,
        obj: *const ASN1_OBJECT,
        lastpos: c_int,
    ) -> c_int;

    /// `CMS_signed_get_attr` — the signed attribute at `loc` (owned by `si`).
    pub(crate) fn CMS_signed_get_attr(si: *const CMS_SignerInfo, loc: c_int)
    -> *mut X509_ATTRIBUTE;

    /// `CMS_final` — finalise a partial CMS structure, computing digest and signatures.
    ///
    /// Returns 1 on success.
    pub(crate) fn CMS_final(
        cms: *mut CMS_ContentInfo,
        data: *mut BIO,
        dcont: *mut BIO,
        flags: c_uint,
    ) -> c_int;

    /// `CMS_get0_content` — pointer to the encapsulated content (`*ptr` null when detached).
    pub(crate) fn CMS_get0_content(cms: *mut CMS_ContentInfo) -> *mut *mut ASN1_OCTET_STRING;
}

/// `CMS_NOCERTS` — do not include the signer certificate in the message.
pub(crate) const CMS_NOCERTS: c_uint = 0x2;
/// `CMS_NO_SIGNER_CERT_VERIFY` — do not validate the signer certificate chain.
pub(crate) const CMS_NO_SIGNER_CERT_VERIFY: c_uint = 0x20;
/// `CMS_DETACHED` — omit the encapsulated content.
pub(crate) const CMS_DETACHED: c_uint = 0x40;
/// `CMS_BINARY` — no MIME canonicalisation.
pub(crate) const CMS_BINARY: c_uint = 0x80;
/// `CMS_NOSMIMECAP` — do not add the `SMIMECapabilities` signed attribute.
pub(crate) const CMS_NOSMIMECAP: c_uint = 0x200;
/// `CMS_PARTIAL` — return a partial structure to be finalised with `CMS_final`.
pub(crate) const CMS_PARTIAL: c_uint = 0x4000;

/// `V_ASN1_IA5STRING` (not exported by every `openssl-sys` version).
pub(crate) const V_ASN1_IA5STRING: c_int = 22;

/// Read the first value of an `X509_ATTRIBUTE` that holds a string-like ASN.1 type
/// (`PrintableString`, `UTF8String`, `IA5String` or `OCTET STRING`).
///
/// Returns the raw string bytes, or `None` when the attribute is absent, multi-valued
/// or of a different ASN.1 type.
///
/// # Safety
/// `attr` must be null or a valid `X509_ATTRIBUTE*`.
pub(crate) unsafe fn attribute_string_bytes(attr: *mut X509_ATTRIBUTE) -> Option<Vec<u8>> {
    if attr.is_null() {
        return None;
    }
    // SAFETY: `attr` is non-null and valid per this function's contract.
    if unsafe { openssl_sys::X509_ATTRIBUTE_count(attr) } != 1 {
        return None;
    }
    for ty in [
        openssl_sys::V_ASN1_PRINTABLESTRING,
        openssl_sys::V_ASN1_UTF8STRING,
        V_ASN1_IA5STRING,
        openssl_sys::V_ASN1_OCTET_STRING,
    ] {
        // SAFETY: `attr` is valid; index 0 exists (count == 1); `data` may be null.
        let p = unsafe { openssl_sys::X509_ATTRIBUTE_get0_data(attr, 0, ty, std::ptr::null_mut()) };
        if p.is_null() {
            continue;
        }
        let s = p.cast::<openssl_sys::ASN1_STRING>();
        // SAFETY: for the string types above, `X509_ATTRIBUTE_get0_data` returns an
        // `ASN1_STRING*` owned by the attribute; data/length are valid while `attr` lives.
        let bytes = unsafe {
            let len = openssl_sys::ASN1_STRING_length(s);
            let data = openssl_sys::ASN1_STRING_get0_data(s);
            if data.is_null() || len < 0 {
                return None;
            }
            std::slice::from_raw_parts(data, usize::try_from(len).ok()?).to_vec()
        };
        // Drain the error queue entries produced by the failed type probes.
        drop(openssl::error::ErrorStack::get());
        return Some(bytes);
    }
    drop(openssl::error::ErrorStack::get());
    None
}

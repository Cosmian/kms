//! Raw FFI bindings for OCSP functions absent from `openssl-sys` 0.9.x.
//!
//! The `openssl-sys` crate exposes `OCSP_BASICRESP_new`, `OCSP_response_create`,
//! `d2i_OCSP_REQUEST`, and `i2d_OCSP_RESPONSE`, but omits the functions needed
//! to *build* a response.  This module adds the missing bindings.
//!
//! # Safety policy
//! Every function here is `unsafe`; callers are responsible for:
//! - passing non-null pointers where the C API requires non-null,
//! - freeing returned pointers with the matching `_free` function,
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

use std::ffi::{c_int, c_long, c_uchar, c_ulong};

use openssl_sys::{
    ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_OBJECT, EVP_MD, EVP_PKEY, OCSP_BASICRESP, OCSP_CERTID,
    X509,
};

/// An opaque pointer to `OCSP_SINGLERESP` (not exposed by openssl-sys).
#[allow(non_camel_case_types)]
pub(crate) enum OCSP_SINGLERESP {}

unsafe extern "C" {
    /// `OCSP_basic_add1_status` — add a single certificate status to a `BasicResponse`.
    ///
    /// Returns a pointer to the newly added `OCSP_SINGLERESP`, or null on error.
    /// The `OCSP_BASICRESP` takes ownership; do **not** free the returned pointer.
    ///
    /// # Arguments
    /// - `rsp`    — the `OCSP_BASICRESP` to populate
    /// - `id`     — the `OCSP_CERTID` identifying the certificate
    /// - `status` — `V_OCSP_CERTSTATUS_GOOD` / `_REVOKED` / `_UNKNOWN`
    /// - `reason` — `CRL_REASON_*` constant (ignored when status ≠ revoked)
    /// - `revtime`— `ASN1_GENERALIZEDTIME*` revocation time (null when status ≠ revoked)
    /// - `thisupd`— `ASN1_GENERALIZEDTIME*` thisUpdate
    /// - `nextupd`— `ASN1_GENERALIZEDTIME*` nextUpdate (null to omit)
    pub(crate) fn OCSP_basic_add1_status(
        rsp: *mut OCSP_BASICRESP,
        id: *mut OCSP_CERTID,
        status: c_int,
        reason: c_int,
        revtime: *mut ASN1_GENERALIZEDTIME,
        thisupd: *mut ASN1_GENERALIZEDTIME,
        nextupd: *mut ASN1_GENERALIZEDTIME,
    ) -> *mut OCSP_SINGLERESP;

    /// `OCSP_basic_sign` — sign an `OCSP_BASICRESP` with the given signer.
    ///
    /// Returns 1 on success, 0 on error.
    ///
    /// # Arguments
    /// - `brsp`  — the `OCSP_BASICRESP` to sign (must already have status entries)
    /// - `signer`— X.509 signing certificate (responder cert or CA cert)
    /// - `key`   — private key matching `signer`
    /// - `dgst`  — message digest (e.g. SHA-256); pass null for default
    /// - `certs` — stack of additional certificates to include; pass null for none
    /// - `flags` — `OCSP_NOCERTS` to suppress cert inclusion, etc.
    pub(crate) fn OCSP_basic_sign(
        brsp: *mut OCSP_BASICRESP,
        signer: *mut X509,
        key: *mut EVP_PKEY,
        dgst: *const EVP_MD,
        certs: *mut openssl_sys::stack_st_X509,
        flags: c_ulong,
    ) -> c_int;

    /// `OCSP_add1_basic_nonce` — add (or echo) a nonce extension to an `OCSP_BASICRESP`.
    ///
    /// Copies `len` bytes from `val` into the nonce extension.
    /// Returns 1 on success, ≤ 0 on error.
    pub(crate) fn OCSP_basic_add1_nonce(
        resp: *mut OCSP_BASICRESP,
        val: *const c_uchar,
        len: c_int,
    ) -> c_int;

    /// `OCSP_request_add1_nonce` — add a random nonce to an `OCSP_REQUEST`.
    ///
    /// If `val` is null, a random nonce of length `len` is generated.
    /// Returns 1 on success, ≤ 0 on error.
    pub(crate) fn OCSP_request_add1_nonce(
        req: *mut openssl_sys::OCSP_REQUEST,
        val: *mut c_uchar,
        len: c_int,
    ) -> c_int;

    /// `OCSP_check_nonce` — verify nonce in a request matches that in a response.
    ///
    /// Returns:
    /// - 1  — both have a nonce and they match
    /// - 2  — neither request nor response has a nonce
    /// - 3  — response has a nonce, request does not
    /// - -1 — request has a nonce, response does not
    /// - 0  — both have a nonce but they differ
    pub(crate) fn OCSP_check_nonce(
        req: *mut openssl_sys::OCSP_REQUEST,
        bs: *mut OCSP_BASICRESP,
    ) -> c_int;

    /// `OCSP_REQUEST_get_ext_count` — number of extensions in the tbsRequest.
    pub(crate) fn OCSP_REQUEST_get_ext_count(req: *mut openssl_sys::OCSP_REQUEST) -> c_int;

    /// `OCSP_REQUEST_get_ext` — retrieve extension at index `loc`.
    pub(crate) fn OCSP_REQUEST_get_ext(
        req: *mut openssl_sys::OCSP_REQUEST,
        loc: c_int,
    ) -> *mut openssl_sys::X509_EXTENSION;

    /// `OCSP_request_onereq_count` — number of `OCSP_ONEREQ` in the request.
    pub(crate) fn OCSP_request_onereq_count(req: *mut openssl_sys::OCSP_REQUEST) -> c_int;

    /// `OCSP_request_onereq_get0` — retrieve `OCSP_ONEREQ` at index `i`.
    pub(crate) fn OCSP_request_onereq_get0(
        req: *mut openssl_sys::OCSP_REQUEST,
        i: c_int,
    ) -> *mut openssl_sys::OCSP_ONEREQ;

    /// `OCSP_onereq_get0_id` — extract the `OCSP_CERTID` from an `OCSP_ONEREQ`.
    pub(crate) fn OCSP_onereq_get0_id(
        one: *mut openssl_sys::OCSP_ONEREQ,
    ) -> *mut openssl_sys::OCSP_CERTID;

    /// `OCSP_id_get0_info` — decompose an `OCSP_CERTID` into its constituent fields.
    ///
    /// Any output parameter may be null if the caller does not need that field.
    /// The returned pointers are borrowed from `cid`; do **not** free them.
    pub(crate) fn OCSP_id_get0_info(
        piNameHash: *mut *mut openssl_sys::ASN1_OCTET_STRING,
        pmd: *mut *mut ASN1_OBJECT,
        piKeyHash: *mut *mut openssl_sys::ASN1_OCTET_STRING,
        pserial: *mut *mut ASN1_INTEGER,
        cid: *mut OCSP_CERTID,
    ) -> c_int;

    /// `OCSP_cert_id_new` — create an `OCSP_CERTID` from raw hash/key fields.
    ///
    /// All `ASN1_OCTET_STRING` and `ASN1_INTEGER` fields are copied.
    pub(crate) fn OCSP_cert_id_new(
        dgst: *const EVP_MD,
        issuerName: *const openssl_sys::ASN1_OCTET_STRING,
        issuerKey: *const openssl_sys::ASN1_OCTET_STRING,
        serialNumber: *const ASN1_INTEGER,
    ) -> *mut OCSP_CERTID;

    /// `ASN1_GENERALIZEDTIME_set` — set the value of an `ASN1_GENERALIZEDTIME` to `t`.
    ///
    /// Allocates a new `ASN1_GENERALIZEDTIME` if `s` is null.
    /// Returns the updated/allocated object, or null on error.
    pub(crate) fn ASN1_GENERALIZEDTIME_set(
        s: *mut ASN1_GENERALIZEDTIME,
        t: c_long,
    ) -> *mut ASN1_GENERALIZEDTIME;

    /// `ASN1_GENERALIZEDTIME_free` — free an `ASN1_GENERALIZEDTIME`.
    pub(crate) fn ASN1_GENERALIZEDTIME_free(a: *mut ASN1_GENERALIZEDTIME);

    /// `ASN1_OCTET_STRING_cmp` — compare two ASN1 octet strings.
    ///
    /// Returns 0 if equal, non-zero otherwise.
    pub(crate) fn ASN1_OCTET_STRING_cmp(
        a: *const openssl_sys::ASN1_OCTET_STRING,
        b: *const openssl_sys::ASN1_OCTET_STRING,
    ) -> c_int;

    /// `i2d_OCSP_REQUEST` — serialize an OCSP request to DER.
    ///
    /// Appends DER bytes to `*pp` and advances `*pp` by the length.
    /// Pass `pp = null` to query the size only.
    /// Returns the number of bytes written, or a negative value on error.
    pub(crate) fn i2d_OCSP_REQUEST(
        a: *mut openssl_sys::OCSP_REQUEST,
        pp: *mut *mut c_uchar,
    ) -> c_int;

    /// `OCSP_id_issuer_cmp` — compare the issuer fields of two `OCSP_CERTID`s.
    ///
    /// Returns 0 if the issuer name hash and key hash match.
    pub(crate) fn OCSP_id_issuer_cmp(a: *mut OCSP_CERTID, b: *mut OCSP_CERTID) -> c_int;

    /// `OCSP_CERTID_dup` — duplicate an `OCSP_CERTID`.
    pub(crate) fn OCSP_CERTID_dup(id: *mut OCSP_CERTID) -> *mut OCSP_CERTID;

    /// `X509_get_pubkey` — extract the public key from a certificate.
    pub(crate) fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;

    /// `OCSP_X509_id_hash` — compute the issuer name hash and key hash
    /// for the given issuer certificate using the given digest.
    pub(crate) fn OCSP_cert_to_id(
        dgst: *const EVP_MD,
        subject: *const X509,
        issuer: *const X509,
    ) -> *mut OCSP_CERTID;

    /// `ASN1_STRING_length` — return the length in bytes of an `ASN1_STRING` value.
    pub(crate) fn ASN1_STRING_length(x: *const openssl_sys::ASN1_STRING) -> c_int;

    /// `ASN1_STRING_get0_data` — return a read-only pointer to the `ASN1_STRING` data.
    pub(crate) fn ASN1_STRING_get0_data(x: *const openssl_sys::ASN1_STRING) -> *const c_uchar;

    /// `ASN1_INTEGER_to_BN` — convert `ASN1_INTEGER` to a `BIGNUM`.
    pub(crate) fn ASN1_INTEGER_to_BN(
        ai: *const ASN1_INTEGER,
        bn: *mut openssl_sys::BIGNUM,
    ) -> *mut openssl_sys::BIGNUM;

    /// `BN_bn2hex` — convert a `BIGNUM` to a NUL-terminated hex string.
    ///
    /// The returned string must be freed with `CRYPTO_free`.
    pub(crate) fn BN_bn2hex(a: *const openssl_sys::BIGNUM) -> *mut c_uchar;

    /// `CRYPTO_free` — free a pointer allocated by OpenSSL (e.g. from `BN_bn2hex`).
    ///
    /// `OPENSSL_free` is a C macro that expands to
    /// `CRYPTO_free(ptr, __FILE__, __LINE__)`.  Rust FFI cannot call macros, so
    /// we call the underlying function directly.
    pub(crate) fn CRYPTO_free(
        ptr: *mut std::ffi::c_void,
        file: *const std::ffi::c_char,
        line: std::ffi::c_int,
    );

    /// `BN_free` — free a `BIGNUM`.
    pub(crate) fn BN_free(a: *mut openssl_sys::BIGNUM);

    /// `X509_NAME_hash_old` — compute the "old-style" (MD5) name hash (deprecated).
    ///
    /// Used only for backward compatibility; prefer `X509_NAME_hash` (SHA-1-based)
    /// or the RFC 6960 SHA-256 name hash.
    pub(crate) fn X509_NAME_hash_old(x: *mut openssl_sys::X509_NAME) -> c_ulong;

    /// `ASN1_OCTET_STRING_new` — allocate a new empty `ASN1_OCTET_STRING`.
    pub(crate) fn ASN1_OCTET_STRING_new() -> *mut openssl_sys::ASN1_OCTET_STRING;

    /// `ASN1_OCTET_STRING_free` — free an `ASN1_OCTET_STRING`.
    pub(crate) fn ASN1_OCTET_STRING_free(a: *mut openssl_sys::ASN1_OCTET_STRING);

    /// `EVP_MD_CTX_new` — allocate a new `EVP_MD_CTX`.
    pub(crate) fn EVP_MD_CTX_new() -> *mut openssl_sys::EVP_MD_CTX;

    /// `EVP_MD_CTX_free` — free an `EVP_MD_CTX`.
    pub(crate) fn EVP_MD_CTX_free(ctx: *mut openssl_sys::EVP_MD_CTX);

    /// `OCSP_SINGLERESP_add1_ext_i2d` — add a pre-encoded extension to a single response.
    pub(crate) fn OCSP_SINGLERESP_add1_ext_i2d(
        x: *mut OCSP_SINGLERESP,
        nid: c_int,
        value: *mut std::ffi::c_void,
        crit: c_int,
        flags: c_ulong,
    ) -> c_int;

    /// `OCSP_BASICRESP_add1_ext_i2d` — add a pre-encoded extension to a basic response.
    pub(crate) fn OCSP_BASICRESP_add1_ext_i2d(
        x: *mut OCSP_BASICRESP,
        nid: c_int,
        value: *mut std::ffi::c_void,
        crit: c_int,
        flags: c_ulong,
    ) -> c_int;

    /// `OBJ_txt2nid` — look up an NID by OID text string or short name.
    pub(crate) fn OBJ_txt2nid(s: *const std::ffi::c_char) -> c_int;

    /// `ASN1_INTEGER_new` — allocate a new `ASN1_INTEGER`.
    pub(crate) fn ASN1_INTEGER_new() -> *mut ASN1_INTEGER;

    /// `ASN1_INTEGER_free` — free an `ASN1_INTEGER`.
    pub(crate) fn ASN1_INTEGER_free(a: *mut ASN1_INTEGER);

    /// `BN_new` — allocate a new `BIGNUM`.
    pub(crate) fn BN_new() -> *mut openssl_sys::BIGNUM;

    /// `BN_hex2bn` — set a `BIGNUM` from a hex string.
    ///
    /// Returns the number of hex digits consumed, or 0 on error.
    pub(crate) fn BN_hex2bn(a: *mut *mut openssl_sys::BIGNUM, str: *const c_uchar) -> c_int;

    /// `BN_to_ASN1_INTEGER` — convert a `BIGNUM` to an `ASN1_INTEGER`.
    pub(crate) fn BN_to_ASN1_INTEGER(
        bn: *const openssl_sys::BIGNUM,
        ai: *mut ASN1_INTEGER,
    ) -> *mut ASN1_INTEGER;

    /// `X509_getm_notBefore` — return a mutable pointer to the `notBefore` field.
    pub(crate) fn X509_getm_notBefore(x: *mut X509) -> *mut openssl_sys::ASN1_TIME;

    /// `ASN1_TIME_to_generalizedtime` — convert an `ASN1_TIME` to `ASN1_GENERALIZEDTIME`.
    pub(crate) fn ASN1_TIME_to_generalizedtime(
        t: *mut openssl_sys::ASN1_TIME,
        out: *mut *mut ASN1_GENERALIZEDTIME,
    ) -> *mut ASN1_GENERALIZEDTIME;

    /// `X509_get_subject_name` — return the subject name of a certificate.
    pub(crate) fn X509_get_subject_name(x: *const X509) -> *mut openssl_sys::X509_NAME;

    /// `ASN1_GENERALIZEDTIME_set_string` — set an `ASN1_GENERALIZEDTIME` to a string.
    pub(crate) fn ASN1_GENERALIZEDTIME_set_string(
        s: *mut ASN1_GENERALIZEDTIME,
        str: *const std::ffi::c_char,
    ) -> c_int;
}

/// Status constants for `OCSP_basic_add1_status`.
pub(crate) const V_OCSP_CERTSTATUS_GOOD: c_int = 0;
pub(crate) const V_OCSP_CERTSTATUS_REVOKED: c_int = 1;
pub(crate) const V_OCSP_CERTSTATUS_UNKNOWN: c_int = 2;

/// CRL reason codes for `OCSP_basic_add1_status`.
pub(crate) const CRL_REASON_UNSPECIFIED: c_int = 0;
pub(crate) const CRL_REASON_KEY_COMPROMISE: c_int = 1;
pub(crate) const CRL_REASON_CA_COMPROMISE: c_int = 2;
pub(crate) const CRL_REASON_AFFILIATION_CHANGED: c_int = 3;
pub(crate) const CRL_REASON_SUPERSEDED: c_int = 4;
pub(crate) const CRL_REASON_CESSATION_OF_OPERATION: c_int = 5;
pub(crate) const CRL_REASON_CERTIFICATE_HOLD: c_int = 6;
pub(crate) const CRL_REASON_REMOVE_FROM_CRL: c_int = 8;
pub(crate) const CRL_REASON_PRIVILEGE_WITHDRAWN: c_int = 9;
pub(crate) const CRL_REASON_AA_COMPROMISE: c_int = 10;

/// `OCSP_NOCERTS` flag for `OCSP_basic_sign` — suppress extra cert chain in response.
pub(crate) const OCSP_NOCERTS: c_ulong = 0x2;

/// OID string for the `id-pkix-ocsp-nonce` extension (RFC 6960 §4.4.1).
pub(crate) const OID_OCSP_NONCE: &[u8] = b"1.3.6.1.5.5.7.48.1.2\0";

/// OID string for `id-pkix-ocsp-archive-cutoff` extension (RFC 6960 §4.4.4).
pub(crate) const OID_OCSP_ARCHIVE_CUTOFF: &[u8] = b"1.3.6.1.5.5.7.48.1.6\0";

/// NID for `id-pkix-ocsp-nonce` (registered in OpenSSL 3.x).
/// Fall back to `OBJ_txt2nid(OID_OCSP_NONCE)` at runtime if this value is -1.
pub(crate) const NID_OCSP_NONCE: c_int = 365; // NID_id_pkix_OCSP_Nonce

/// Minimum and maximum nonce lengths per RFC 9654.
pub(crate) const OCSP_NONCE_MIN_LEN: usize = 16;
pub(crate) const OCSP_NONCE_MAX_LEN: usize = 128;
pub(crate) const OCSP_NONCE_RECOMMENDED_LEN: usize = 32;

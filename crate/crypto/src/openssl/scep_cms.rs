//! SCEP (RFC 8894) CMS helpers: signed `pkiMessage` construction / parsing and
//! the `pkcsPKIEnvelope` (`EnvelopedData`) layer.
//!
//! The OpenSSL safe wrapper does not expose custom signed attributes, so the
//! outer `pkiMessage` is built with the partial CMS API from [`super::cms_ffi`].
//!
//! Every `unsafe` block carries a `// SAFETY:` comment.

use std::{
    ffi::{CString, c_int, c_void},
    marker::PhantomData,
    ptr,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    cms::CmsContentInfo,
    nid::Nid,
    pkey::{Id, PKeyRef, Private, Public},
    pkey_ctx::PkeyCtxRef,
    rsa::Padding,
    stack::Stack,
    symm::Cipher,
    x509::{X509, X509Ref},
};
use x509_parser::asn1_rs::{Any, Class, FromDer};

use super::{
    cms_ffi::{
        CMS_BINARY, CMS_DETACHED, CMS_NO_SIGNER_CERT_VERIFY, CMS_NOSMIMECAP, CMS_PARTIAL,
        CMS_SignerInfo, attribute_string_bytes,
    },
    oid::nid_of,
};
use crate::{crypto_bail, crypto_error, error::result::CryptoResult};

/// Content-encryption algorithms accepted in a `pkcsPKIEnvelope`: the `AES` capability of
/// RFC 8894 §3.5.2. DES, 3DES and RC2 are refused even when a loaded provider implements them.
/// Protocol transport, outside the KMIP algorithm policy (like TLS): RFC 8894 defines only CBC
/// content encryption.
const ENVELOPE_CIPHERS: [Nid; 3] = [Nid::AES_128_CBC, Nid::AES_192_CBC, Nid::AES_256_CBC];
/// Key-transport algorithms accepted for the (RSA) CA recipient: RSAES-OAEP only. PKCS#1 v1.5
/// encryption is disallowed after 2023 (NIST SP 800-131A Rev. 2, Table 5).
#[cfg(not(feature = "non-fips"))]
const ENVELOPE_KEY_TRANSPORTS: [Nid; 1] = [Nid::RSAESOAEP];
/// Key-transport algorithms accepted for the (RSA) CA recipient: PKCS#1 v1.5 and RSAES-OAEP.
#[cfg(feature = "non-fips")]
const ENVELOPE_KEY_TRANSPORTS: [Nid; 2] = [Nid::RSAENCRYPTION, Nid::RSAESOAEP];
/// Signer digest algorithms accepted on a `pkiMessage` (RFC 8894 §3.5.2 `SHA-256`/`SHA-512`,
/// plus SHA-384); SHA-1 and MD5 are refused even when a loaded provider still verifies them.
const SIGNER_DIGESTS: [Nid; 3] = [Nid::SHA256, Nid::SHA384, Nid::SHA512];

/// OID of the SCEP `transactionID` signed attribute (RFC 8894 §3.2.1.1).
pub const OID_TRANSACTION_ID: &str = "2.16.840.1.113733.1.9.7";
/// OID of the SCEP `messageType` signed attribute.
pub const OID_MESSAGE_TYPE: &str = "2.16.840.1.113733.1.9.2";
/// OID of the SCEP `pkiStatus` signed attribute.
pub const OID_PKI_STATUS: &str = "2.16.840.1.113733.1.9.3";
/// OID of the SCEP `failInfo` signed attribute.
pub const OID_FAIL_INFO: &str = "2.16.840.1.113733.1.9.4";
/// OID of the SCEP `senderNonce` signed attribute.
pub const OID_SENDER_NONCE: &str = "2.16.840.1.113733.1.9.5";
/// OID of the SCEP `recipientNonce` signed attribute.
pub const OID_RECIPIENT_NONCE: &str = "2.16.840.1.113733.1.9.6";

/// `messageType` value of a `CertRep` response (RFC 8894 §3.2.1.2).
pub const MESSAGE_TYPE_CERT_REP: u8 = 3;
/// `messageType` value of a `RenewalReq` request.
pub const MESSAGE_TYPE_RENEWAL_REQ: u8 = 17;
/// `messageType` value of a `PKCSReq` request.
pub const MESSAGE_TYPE_PKCS_REQ: u8 = 19;

/// `pkiStatus` SUCCESS.
pub const PKI_STATUS_SUCCESS: u8 = 0;
/// `pkiStatus` FAILURE.
pub const PKI_STATUS_FAILURE: u8 = 2;

/// `failInfo` badAlg.
pub const FAIL_INFO_BAD_ALG: u8 = 0;
/// `failInfo` badMessageCheck.
pub const FAIL_INFO_BAD_MESSAGE_CHECK: u8 = 1;
/// `failInfo` badRequest.
pub const FAIL_INFO_BAD_REQUEST: u8 = 2;
/// `failInfo` badTime.
pub const FAIL_INFO_BAD_TIME: u8 = 3;
/// `failInfo` badCertId.
pub const FAIL_INFO_BAD_CERT_ID: u8 = 4;

/// Length in bytes of SCEP nonces (RFC 8894 §3.2.1.5).
pub const NONCE_LEN: usize = 16;

/// The SCEP signed attributes carried by a `pkiMessage` (RFC 8894 §3.2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScepAttrs {
    /// Transaction identifier (`PrintableString`).
    pub transaction_id: String,
    /// Message type (`PrintableString` holding a decimal number).
    pub message_type: u8,
    /// Status of a `CertRep` (`None` in requests).
    pub pki_status: Option<u8>,
    /// Failure reason of a failed `CertRep`.
    pub fail_info: Option<u8>,
    /// Fresh sender nonce.
    pub sender_nonce: [u8; NONCE_LEN],
    /// Nonce echoed from the request (`CertRep` only).
    pub recipient_nonce: Option<[u8; NONCE_LEN]>,
}

/// A signed `pkiMessage` after signature verification.
#[derive(Debug)]
pub struct ParsedPkiMessage {
    /// The SCEP signed attributes.
    pub attrs: ScepAttrs,
    /// The certificate that signed the message (taken from the CMS `certificates` field).
    /// Its trust chain is **not** evaluated here.
    pub signer_cert: X509,
    /// The encapsulated content (the `pkcsPKIEnvelope` DER); empty when absent.
    pub content: Vec<u8>,
}

/// Build a degenerate (certs-only) CMS `SignedData` carrying `certs` (RFC 5652 §5.1,
/// RFC 7030 §4.1.3, RFC 8894 §4.2.1.2).
///
/// # Errors
/// Fails when OpenSSL cannot build the structure.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
pub fn certs_only_der(certs: &[X509]) -> CryptoResult<Vec<u8>> {
    let mut stack = Stack::<X509>::new()?;
    for c in certs {
        stack.push(c.clone())?;
    }
    // `CMS_PARTIAL | CMS_DETACHED` without `CMS_final`: a SignedData carrying only the
    // certificates (no signer, no encapsulated content), which `CMS_final` would refuse.
    // SAFETY: `signcert`, `pkey` and `data` are null, which `CMS_sign` accepts; `stack` is a
    // live certificate stack that `CMS_sign` only reads (it takes its own references).
    let raw = unsafe {
        openssl_sys::CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            stack.as_ptr(),
            ptr::null_mut(),
            CMS_PARTIAL | CMS_DETACHED | CMS_BINARY,
        )
    };
    if raw.is_null() {
        return Err(openssl::error::ErrorStack::get().into());
    }
    // SAFETY: `raw` is a freshly allocated, owned `CMS_ContentInfo`; `CmsContentInfo` frees it.
    let cms = unsafe { CmsContentInfo::from_ptr(raw) };
    Ok(cms.to_der()?)
}

/// Encrypt `plaintext` into a CMS `EnvelopedData` addressed to `recipient`, using
/// AES-128-CBC (RFC 8894 §3.5.2 `AES` capability). An RSA recipient gets RSAES-OAEP key
/// transport in FIPS builds and PKCS#1 v1.5 otherwise; an EC recipient gets ECDH key agreement.
///
/// # Errors
/// Fails when OpenSSL cannot build the structure.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
pub fn envelope_for_recipient(recipient: &X509Ref, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    // SAFETY: null certificates and data are accepted with `CMS_PARTIAL`; the cipher is a
    // static method table. The result is a new owned structure or null.
    let raw = unsafe {
        openssl_sys::CMS_encrypt(
            ptr::null_mut(),
            ptr::null_mut(),
            Cipher::aes_128_cbc().as_ptr(),
            CMS_PARTIAL | CMS_BINARY,
        )
    };
    if raw.is_null() {
        return Err(openssl::error::ErrorStack::get().into());
    }
    // SAFETY: `raw` is a freshly allocated, owned `CMS_ContentInfo`; `CmsContentInfo` frees it.
    seal_envelope(
        &unsafe { CmsContentInfo::from_ptr(raw) },
        recipient,
        plaintext,
    )
}

/// Add `recipient` to the partial `EnvelopedData` `cms` and encrypt `plaintext` into it.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
fn seal_envelope(
    cms: &CmsContentInfo,
    recipient: &X509Ref,
    plaintext: &[u8],
) -> CryptoResult<Vec<u8>> {
    let rsa = recipient.public_key()?.id() == Id::RSA;
    // `CMS_KEY_PARAM` keeps the RSA recipient's key context so that its padding can be chosen.
    let flags = if rsa { openssl_sys::CMS_KEY_PARAM } else { 0 };
    // SAFETY: `cms` and `recipient` are live; OpenSSL takes its own reference on the
    // certificate and the returned RecipientInfo is owned by `cms`.
    let ri =
        unsafe { super::cms_ffi::CMS_add1_recipient_cert(cms.as_ptr(), recipient.as_ptr(), flags) };
    if ri.is_null() {
        return Err(openssl::error::ErrorStack::get().into());
    }
    if rsa {
        // SAFETY: `ri` is a live key-transport RecipientInfo added with `CMS_KEY_PARAM`.
        let pctx = unsafe { super::cms_ffi::CMS_RecipientInfo_get0_pkey_ctx(ri) };
        if pctx.is_null() {
            crypto_bail!("SCEP envelope: the RSA recipient has no key context");
        }
        // SAFETY: `pctx` is owned by `ri` (itself owned by `cms`, borrowed for this whole
        // function) and no other reference to it exists.
        set_response_key_transport(unsafe { PkeyCtxRef::<Public>::from_ptr_mut(pctx) })?;
    }
    let data = MemBio::over(plaintext)?;
    // SAFETY: `cms` is a partial structure with its recipient added; `data` outlives the call.
    let ok =
        unsafe { super::cms_ffi::CMS_final(cms.as_ptr(), data.0, ptr::null_mut(), CMS_BINARY) };
    if ok != 1 {
        return Err(openssl::error::ErrorStack::get().into());
    }
    Ok(cms.to_der()?)
}

/// RSAES-OAEP (SHA-256, MGF1-SHA-256) key transport: the only FIPS-approved RSA choice.
#[cfg(not(feature = "non-fips"))]
fn set_response_key_transport(ctx: &mut PkeyCtxRef<Public>) -> CryptoResult<()> {
    ctx.set_rsa_padding(Padding::PKCS1_OAEP)?;
    ctx.set_rsa_oaep_md(openssl::md::Md::sha256())?;
    ctx.set_rsa_mgf1_md(openssl::md::Md::sha256())?;
    Ok(())
}

/// PKCS#1 v1.5 key transport, which every SCEP client can decrypt.
#[cfg(feature = "non-fips")]
fn set_response_key_transport(ctx: &mut PkeyCtxRef<Public>) -> CryptoResult<()> {
    ctx.set_rsa_padding(Padding::PKCS1)?;
    Ok(())
}

/// Decrypt a CMS `EnvelopedData` addressed to `cert` with its private key.
///
/// Only AES-CBC content encryption and RSA key transport (RSAES-OAEP only in FIPS builds) are
/// accepted, checked before any decryption.
///
/// # Errors
/// Fails on malformed input, an algorithm outside the allow-list, or when the key does not
/// match any recipient.
pub fn decrypt_envelope(
    envelope_der: &[u8],
    key: &PKeyRef<Private>,
    cert: &X509,
) -> CryptoResult<Vec<u8>> {
    let cms = CmsContentInfo::from_der(envelope_der)?;
    // Walk OpenSSL's DER re-encoding: clients may send BER (indefinite lengths).
    check_envelope_algorithms(&cms.to_der()?)?;
    Ok(cms.decrypt(key, cert)?)
}

/// Refuse a `pkcsPKIEnvelope` whose algorithms are outside the SCEP allow-lists.
///
/// OpenSSL has no getter for `contentEncryptionAlgorithm`, so the DER is walked (RFC 5652 §6.1):
/// `ContentInfo { contentType, [0] EnvelopedData { version, [0] originatorInfo OPTIONAL,
/// recipientInfos SET, encryptedContentInfo { contentType, contentEncryptionAlgorithm, … } } }`.
fn check_envelope_algorithms(der: &[u8]) -> CryptoResult<()> {
    let (_, content_info) = der_element(der)?;
    let (rest, content_type) = der_element(content_info.data)?;
    if oid_nid(&content_type)? != Nid::PKCS7_ENVELOPED {
        crypto_bail!("SCEP pkcsPKIEnvelope is not a CMS EnvelopedData");
    }
    let (_, explicit) = der_element(rest)?;
    let (_, enveloped) = der_element(explicit.data)?;
    let (rest, _version) = der_element(enveloped.data)?;
    let (mut rest, mut recipient_infos) = der_element(rest)?;
    if recipient_infos.class() == Class::ContextSpecific {
        // Skip `[0] originatorInfo`.
        (rest, recipient_infos) = der_element(rest)?;
    }
    let mut remaining = recipient_infos.data;
    while !remaining.is_empty() {
        let (next, recipient) = der_element(remaining)?;
        // KeyTransRecipientInfo is the only untagged choice; kari/kekri/pwri/ori are [1]..[4].
        if recipient.class() != Class::Universal {
            crypto_bail!("SCEP pkcsPKIEnvelope recipients must use RSA key transport");
        }
        let (r, _version) = der_element(recipient.data)?;
        let (r, _rid) = der_element(r)?;
        let (_, key_alg) = der_element(r)?;
        ensure_allowed("key-transport", &key_alg, &ENVELOPE_KEY_TRANSPORTS)?;
        remaining = next;
    }
    let (_, encrypted_content_info) = der_element(rest)?;
    let (r, _content_type) = der_element(encrypted_content_info.data)?;
    let (_, content_alg) = der_element(r)?;
    ensure_allowed("content-encryption", &content_alg, &ENVELOPE_CIPHERS)
}

/// The next DER element of `input` and the bytes after it.
fn der_element(input: &[u8]) -> CryptoResult<(&[u8], Any<'_>)> {
    Any::from_der(input).map_err(|e| crypto_error!("malformed SCEP pkcsPKIEnvelope: {e}"))
}

/// The NID of an `OBJECT IDENTIFIER` element.
fn oid_nid(element: &Any<'_>) -> CryptoResult<Nid> {
    let oid = element
        .as_oid()
        .map_err(|e| crypto_error!("malformed SCEP pkcsPKIEnvelope: {e}"))?;
    Ok(nid_of(&oid.to_id_string()))
}

/// Fail unless the `AlgorithmIdentifier` `alg` names one of `allowed`.
fn ensure_allowed(kind: &str, alg: &Any<'_>, allowed: &[Nid]) -> CryptoResult<()> {
    let (_, oid) = der_element(alg.data)?;
    let nid = oid_nid(&oid)?;
    if !allowed.contains(&nid) {
        crypto_bail!(
            "SCEP {kind} algorithm {} is not allowed",
            nid.short_name().unwrap_or("unknown")
        );
    }
    Ok(())
}

/// Owned `ASN1_OBJECT` created from a dotted OID.
struct Asn1Obj(*mut openssl_sys::ASN1_OBJECT);

impl Asn1Obj {
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn new(oid: &str) -> CryptoResult<Self> {
        let c = CString::new(oid).map_err(|e| crypto_error!("invalid OID {oid}: {e}"))?;
        // SAFETY: `c` is a valid NUL-terminated string; `no_name = 1` restricts to dotted form.
        let p = unsafe { openssl_sys::OBJ_txt2obj(c.as_ptr(), 1) };
        if p.is_null() {
            crypto_bail!("OBJ_txt2obj failed for OID {oid}");
        }
        Ok(Self(p))
    }
}

impl Drop for Asn1Obj {
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn drop(&mut self) {
        // SAFETY: pointer was returned by `OBJ_txt2obj` and is freed exactly once.
        unsafe { openssl_sys::ASN1_OBJECT_free(self.0) }
    }
}

/// Owned memory BIO; `'a` is the lifetime of the buffer a read-only BIO reads from.
struct MemBio<'a>(*mut openssl_sys::BIO, PhantomData<&'a [u8]>);

impl MemBio<'static> {
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn new() -> CryptoResult<Self> {
        // SAFETY: `BIO_s_mem` returns a static method table; `BIO_new` takes it by pointer.
        let p = unsafe { openssl_sys::BIO_new(openssl_sys::BIO_s_mem()) };
        if p.is_null() {
            crypto_bail!("BIO_new failed");
        }
        Ok(Self(p, PhantomData))
    }
}

impl<'a> MemBio<'a> {
    /// A read-only BIO over `data`.
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn over(data: &'a [u8]) -> CryptoResult<Self> {
        let len = c_int::try_from(data.len())?;
        // SAFETY: the BIO only reads `len` bytes from `data`, which outlives it (enforced by `'a`).
        let p = unsafe { openssl_sys::BIO_new_mem_buf(data.as_ptr().cast::<c_void>(), len) };
        if p.is_null() {
            crypto_bail!("BIO_new_mem_buf failed");
        }
        Ok(Self(p, PhantomData))
    }

    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn read_all(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0_u8; 4096];
        loop {
            // SAFETY: `self.0` is a valid BIO and `buf` is writable for `buf.len()` bytes.
            let n =
                unsafe { openssl_sys::BIO_read(self.0, buf.as_mut_ptr().cast::<c_void>(), 4096) };
            let Ok(n) = usize::try_from(n) else { break };
            if n == 0 {
                break;
            }
            if let Some(chunk) = buf.get(..n) {
                out.extend_from_slice(chunk);
            }
        }
        out
    }
}

impl Drop for MemBio<'_> {
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn drop(&mut self) {
        // SAFETY: pointer came from `BIO_new`/`BIO_new_mem_buf` and is freed exactly once.
        unsafe { openssl_sys::BIO_free_all(self.0) };
    }
}

/// Add a string-typed signed attribute.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
fn add_attr(
    si: *mut CMS_SignerInfo,
    oid: &str,
    asn1_type: c_int,
    value: &[u8],
) -> CryptoResult<()> {
    let obj = Asn1Obj::new(oid)?;
    let len = c_int::try_from(value.len())?;
    // SAFETY: `si` is a live SignerInfo owned by the CMS under construction; `obj` is a valid
    // object; `value` is readable for `len` bytes (OpenSSL copies it).
    let ok = unsafe {
        super::cms_ffi::CMS_signed_add1_attr_by_OBJ(
            si,
            obj.0,
            asn1_type,
            value.as_ptr().cast::<c_void>(),
            len,
        )
    };
    if ok != 1 {
        crypto_bail!("CMS_signed_add1_attr_by_OBJ failed for {oid}");
    }
    Ok(())
}

/// Build a signed SCEP `pkiMessage` (RFC 8894 §3.2).
///
/// `inner_der` is the encapsulated content (the DER of the `pkcsPKIEnvelope`); when empty
/// (failed `CertRep`) the content is omitted.  The signer certificate is embedded and the
/// signature uses SHA-256.
///
/// # Errors
/// Fails when OpenSSL cannot build or sign the structure.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
pub fn build_signed_pkimessage(
    signer_cert: &X509Ref,
    signer_key: &PKeyRef<Private>,
    inner_der: &[u8],
    attrs: &ScepAttrs,
) -> CryptoResult<Vec<u8>> {
    let detached = inner_der.is_empty();
    let mut flags = CMS_PARTIAL | CMS_BINARY;
    if detached {
        flags |= CMS_DETACHED;
    }
    // SAFETY: all pointer arguments are null (certs-only partial structure, no data) which
    // `CMS_sign` accepts; the result is a new owned structure or null.
    let raw = unsafe {
        openssl_sys::CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            flags,
        )
    };
    if raw.is_null() {
        return Err(openssl::error::ErrorStack::get().into());
    }
    // SAFETY: `raw` is a freshly allocated, owned `CMS_ContentInfo`; `CmsContentInfo` frees it.
    let cms = unsafe { CmsContentInfo::from_ptr(raw) };

    // SAFETY: `cms`, `signer_cert`, `signer_key` are live; `EVP_sha256` returns a static MD.
    let si = unsafe {
        super::cms_ffi::CMS_add1_signer(
            cms.as_ptr(),
            signer_cert.as_ptr(),
            signer_key.as_ptr(),
            openssl_sys::EVP_sha256(),
            CMS_NOSMIMECAP | CMS_BINARY,
        )
    };
    if si.is_null() {
        return Err(openssl::error::ErrorStack::get().into());
    }

    add_attr(
        si,
        OID_TRANSACTION_ID,
        openssl_sys::V_ASN1_PRINTABLESTRING,
        attrs.transaction_id.as_bytes(),
    )?;
    add_attr(
        si,
        OID_MESSAGE_TYPE,
        openssl_sys::V_ASN1_PRINTABLESTRING,
        attrs.message_type.to_string().as_bytes(),
    )?;
    if let Some(s) = attrs.pki_status {
        add_attr(
            si,
            OID_PKI_STATUS,
            openssl_sys::V_ASN1_PRINTABLESTRING,
            s.to_string().as_bytes(),
        )?;
    }
    if let Some(f) = attrs.fail_info {
        add_attr(
            si,
            OID_FAIL_INFO,
            openssl_sys::V_ASN1_PRINTABLESTRING,
            f.to_string().as_bytes(),
        )?;
    }
    add_attr(
        si,
        OID_SENDER_NONCE,
        openssl_sys::V_ASN1_OCTET_STRING,
        &attrs.sender_nonce,
    )?;
    if let Some(n) = &attrs.recipient_nonce {
        add_attr(si, OID_RECIPIENT_NONCE, openssl_sys::V_ASN1_OCTET_STRING, n)?;
    }

    let data = MemBio::over(inner_der)?;
    // SAFETY: `cms` is a partial structure with its signer added; `data` outlives the call.
    let ok =
        unsafe { super::cms_ffi::CMS_final(cms.as_ptr(), data.0, ptr::null_mut(), CMS_BINARY) };
    if ok != 1 {
        return Err(openssl::error::ErrorStack::get().into());
    }
    Ok(cms.to_der()?)
}

/// Read one string-typed signed attribute from a `SignerInfo`.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
fn get_attr(si: *mut CMS_SignerInfo, oid: &str) -> CryptoResult<Option<Vec<u8>>> {
    let obj = Asn1Obj::new(oid)?;
    // SAFETY: `si` is a live SignerInfo and `obj` a valid object.
    let idx = unsafe { super::cms_ffi::CMS_signed_get_attr_by_OBJ(si, obj.0, -1) };
    if idx < 0 {
        return Ok(None);
    }
    // SAFETY: `idx` was returned by the lookup above for the same `si`.
    let attr = unsafe { super::cms_ffi::CMS_signed_get_attr(si, idx) };
    // SAFETY: `attr` is owned by `si` and valid for the duration of this call.
    Ok(unsafe { attribute_string_bytes(attr) })
}

fn parse_decimal_u8(oid_name: &str, v: &[u8]) -> CryptoResult<u8> {
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .ok_or_else(|| crypto_error!("SCEP attribute {oid_name} is not a small decimal number"))
}

fn parse_nonce(name: &str, v: &[u8]) -> CryptoResult<[u8; NONCE_LEN]> {
    <[u8; NONCE_LEN]>::try_from(v)
        .map_err(|e| crypto_error!("SCEP attribute {name} must be {NONCE_LEN} bytes: {e}"))
}

/// Parse and verify a signed SCEP `pkiMessage`.
///
/// Checks that exactly one `SignerInfo` is present and that its digest algorithm is SHA-256,
/// SHA-384 or SHA-512, verifies the CMS signature against the certificate embedded in the
/// message (no chain validation: trust is evaluated by the caller), and extracts the SCEP signed
/// attributes.
///
/// # Errors
/// Fails on malformed messages, a signer count different from one, a refused digest algorithm,
/// a missing mandatory attribute, or an invalid signature.
#[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
pub fn parse_signed_pkimessage(der: &[u8]) -> CryptoResult<ParsedPkiMessage> {
    let cms = CmsContentInfo::from_der(der)?;

    // SAFETY: `cms` is live; the returned stack is owned by it.
    let stack = unsafe { super::cms_ffi::CMS_get0_SignerInfos(cms.as_ptr()) };
    if stack.is_null() {
        crypto_bail!("SCEP pkiMessage is not a CMS SignedData");
    }
    // SAFETY: `stack` is a valid stack owned by `cms`.
    let count = unsafe { openssl_sys::OPENSSL_sk_num(stack) };
    if count != 1 {
        crypto_bail!("SCEP pkiMessage must contain exactly one SignerInfo, found {count}");
    }
    // SAFETY: index 0 < count.
    let si = unsafe { openssl_sys::OPENSSL_sk_value(stack, 0) }.cast::<CMS_SignerInfo>();

    let mut digest_alg: *mut c_void = ptr::null_mut();
    // SAFETY: `si` is live; only the digest out-parameter is requested (owned by `si`).
    unsafe {
        super::cms_ffi::CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut digest_alg,
            ptr::null_mut(),
        );
    }
    let mut digest_oid: *const openssl_sys::ASN1_OBJECT = ptr::null();
    if !digest_alg.is_null() {
        // SAFETY: `digest_alg` is the live `X509_ALGOR` of `si`; only the OID is requested.
        unsafe {
            openssl_sys::X509_ALGOR_get0(
                &raw mut digest_oid,
                ptr::null_mut(),
                ptr::null_mut(),
                digest_alg.cast(),
            );
        }
    }
    // SAFETY: `OBJ_obj2nid` accepts null (returns `NID_undef`); `digest_oid` is owned by `si`.
    let digest = Nid::from_raw(unsafe { openssl_sys::OBJ_obj2nid(digest_oid) });
    if !SIGNER_DIGESTS.contains(&digest) {
        crypto_bail!(
            "SCEP pkiMessage digest algorithm {} is not allowed (SHA-256, SHA-384 or SHA-512 \
             required)",
            digest.short_name().unwrap_or("unknown")
        );
    }

    // Signature verification (also resolves the signer certificate inside `si`).
    // SAFETY: `cms` is live; `CMS_get0_content` returns a pointer into it.
    let detached = unsafe {
        let pc = super::cms_ffi::CMS_get0_content(cms.as_ptr());
        pc.is_null() || (*pc).is_null()
    };
    let out = MemBio::new()?;
    let empty = MemBio::over(&[])?;
    // SAFETY: all BIOs are live; null `certs`/`store` select the embedded certificates and
    // skip chain verification (CMS_NO_SIGNER_CERT_VERIFY).
    let ok = unsafe {
        openssl_sys::CMS_verify(
            cms.as_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            if detached { empty.0 } else { ptr::null_mut() },
            out.0,
            CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY,
        )
    };
    if ok != 1 {
        return Err(openssl::error::ErrorStack::get().into());
    }
    let content = out.read_all();

    let mut signer: *mut openssl_sys::X509 = ptr::null_mut();
    // SAFETY: `si` is live; only the `signer` out-parameter is requested.
    unsafe {
        super::cms_ffi::CMS_SignerInfo_get0_algs(
            si,
            ptr::null_mut(),
            &raw mut signer,
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }
    if signer.is_null() {
        crypto_bail!("SCEP pkiMessage signer certificate not found in the message");
    }
    // SAFETY: `signer` is a valid X509 owned by `cms`; `to_owned` bumps its refcount.
    let signer_cert = unsafe { X509Ref::from_ptr(signer) }.to_owned();

    let required = |oid: &str, name: &str| -> CryptoResult<Vec<u8>> {
        get_attr(si, oid)?.ok_or_else(|| crypto_error!("SCEP attribute {name} is missing"))
    };
    let transaction_id = String::from_utf8(required(OID_TRANSACTION_ID, "transactionID")?)
        .map_err(|e| crypto_error!("SCEP transactionID is not valid text: {e}"))?;
    let message_type =
        parse_decimal_u8("messageType", &required(OID_MESSAGE_TYPE, "messageType")?)?;
    let sender_nonce = parse_nonce("senderNonce", &required(OID_SENDER_NONCE, "senderNonce")?)?;
    let pki_status = get_attr(si, OID_PKI_STATUS)?
        .map(|v| parse_decimal_u8("pkiStatus", &v))
        .transpose()?;
    let fail_info = get_attr(si, OID_FAIL_INFO)?
        .map(|v| parse_decimal_u8("failInfo", &v))
        .transpose()?;
    let recipient_nonce = get_attr(si, OID_RECIPIENT_NONCE)?
        .map(|v| parse_nonce("recipientNonce", &v))
        .transpose()?;

    Ok(ParsedPkiMessage {
        attrs: ScepAttrs {
            transaction_id,
            message_type,
            pki_status,
            fail_info,
            sender_nonce,
            recipient_nonce,
        },
        signer_cert,
        content,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // tests: a panic is the failure signal
mod tests {
    use std::ffi::{c_char, c_uint};

    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        lib_ctx::LibCtx,
        pkey::PKey,
        provider::Provider,
        rsa::Rsa,
        x509::{X509NameBuilder, X509Req},
    };

    use super::*;

    fn self_signed(cn: &str) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    fn csr(key: &PKey<Private>) -> Vec<u8> {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "device").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build().to_der().unwrap()
    }

    fn request_attrs() -> ScepAttrs {
        ScepAttrs {
            transaction_id: "ABCDEF0123456789".to_owned(),
            message_type: MESSAGE_TYPE_PKCS_REQ,
            pki_status: None,
            fail_info: None,
            sender_nonce: [7_u8; NONCE_LEN],
            recipient_nonce: None,
        }
    }

    #[test]
    fn pkimessage_round_trip_with_envelope() {
        let (client_cert, client_key) = self_signed("client");
        let (ca_cert, ca_key) = self_signed("ca");
        let csr_der = csr(&client_key);

        let envelope = envelope_for_recipient(&ca_cert, &csr_der).unwrap();
        let attrs = request_attrs();
        let msg = build_signed_pkimessage(&client_cert, &client_key, &envelope, &attrs).unwrap();

        let parsed = parse_signed_pkimessage(&msg).unwrap();
        assert_eq!(parsed.attrs, attrs);
        assert_eq!(
            parsed.signer_cert.to_der().unwrap(),
            client_cert.to_der().unwrap()
        );
        assert_eq!(parsed.content, envelope);
        let decrypted = decrypt_envelope(&parsed.content, &ca_key, &ca_cert).unwrap();
        assert_eq!(decrypted, csr_der);
    }

    #[test]
    fn cert_rep_failure_has_no_content_and_carries_status() {
        let (ca_cert, ca_key) = self_signed("ca");
        let attrs = ScepAttrs {
            transaction_id: "TX1".to_owned(),
            message_type: MESSAGE_TYPE_CERT_REP,
            pki_status: Some(PKI_STATUS_FAILURE),
            fail_info: Some(FAIL_INFO_BAD_REQUEST),
            sender_nonce: [1_u8; NONCE_LEN],
            recipient_nonce: Some([9_u8; NONCE_LEN]),
        };
        let msg = build_signed_pkimessage(&ca_cert, &ca_key, &[], &attrs).unwrap();
        let parsed = parse_signed_pkimessage(&msg).unwrap();
        assert_eq!(parsed.attrs, attrs);
        assert!(parsed.content.is_empty());
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (client_cert, client_key) = self_signed("client");
        let attrs = request_attrs();
        let payload = vec![0x42_u8; 64];
        let mut msg = build_signed_pkimessage(&client_cert, &client_key, &payload, &attrs).unwrap();
        // Flip a byte inside the encapsulated payload.
        let pos = msg
            .windows(payload.len())
            .position(|w| w == payload.as_slice())
            .unwrap();
        // (an untampered message would make `unwrap_err` below fail the test)
        if let Some(byte) = msg.get_mut(pos + 10) {
            *byte ^= 0xFF;
        }
        parse_signed_pkimessage(&msg).unwrap_err();
    }

    // Test-only `_ex` variants (absent from openssl-sys) to build fixtures in a chosen context.
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI declarations matching `cms.h`
    unsafe extern "C" {
        fn CMS_sign_ex(
            signcert: *mut openssl_sys::X509,
            pkey: *mut openssl_sys::EVP_PKEY,
            certs: *mut openssl_sys::stack_st_X509,
            data: *mut openssl_sys::BIO,
            flags: c_uint,
            libctx: *mut openssl_sys::OSSL_LIB_CTX,
            propq: *const c_char,
        ) -> *mut openssl_sys::CMS_ContentInfo;
        fn CMS_encrypt_ex(
            certs: *mut openssl_sys::stack_st_X509,
            data: *mut openssl_sys::BIO,
            cipher: *const openssl_sys::EVP_CIPHER,
            flags: c_uint,
            libctx: *mut openssl_sys::OSSL_LIB_CTX,
            propq: *const c_char,
        ) -> *mut openssl_sys::CMS_ContentInfo;
    }

    /// A library context with providers the build may not load by default (`default`, and
    /// `legacy` in non-FIPS builds), so that fixtures using refused algorithms can be built.
    struct FixtureCtx {
        _providers: Vec<Provider>,
        ctx: LibCtx,
    }

    impl FixtureCtx {
        fn new(providers: &[&str]) -> Self {
            let ctx = LibCtx::new().unwrap();
            let providers = providers
                .iter()
                .map(|name| Provider::load(Some(&ctx), name).unwrap())
                .collect();
            Self {
                _providers: providers,
                ctx,
            }
        }
    }

    /// A `pkiMessage` signed by every entry of `signers` with digest `md`, built in `ctx`
    /// (null: the default library context).
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn signed_by(
        ctx: *mut openssl_sys::OSSL_LIB_CTX,
        signers: &[(&X509, &PKey<Private>)],
        md: *const openssl_sys::EVP_MD,
    ) -> Vec<u8> {
        // SAFETY: null signer/data are valid for a partial structure; `ctx` is null or live.
        let raw = unsafe {
            CMS_sign_ex(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CMS_PARTIAL | CMS_BINARY,
                ctx,
                ptr::null(),
            )
        };
        assert!(!raw.is_null());
        // SAFETY: `raw` is an owned structure.
        let cms = unsafe { CmsContentInfo::from_ptr(raw) };
        for (c, k) in signers {
            // SAFETY: all handles are live.
            let si = unsafe {
                super::super::cms_ffi::CMS_add1_signer(
                    cms.as_ptr(),
                    c.as_ptr(),
                    k.as_ptr(),
                    md,
                    CMS_NOSMIMECAP | CMS_BINARY,
                )
            };
            assert!(!si.is_null());
            let attrs = request_attrs();
            add_attr(
                si,
                OID_TRANSACTION_ID,
                openssl_sys::V_ASN1_PRINTABLESTRING,
                attrs.transaction_id.as_bytes(),
            )
            .unwrap();
            add_attr(
                si,
                OID_MESSAGE_TYPE,
                openssl_sys::V_ASN1_PRINTABLESTRING,
                b"19",
            )
            .unwrap();
            add_attr(
                si,
                OID_SENDER_NONCE,
                openssl_sys::V_ASN1_OCTET_STRING,
                &attrs.sender_nonce,
            )
            .unwrap();
        }
        let data = MemBio::over(b"payload").unwrap();
        // SAFETY: `cms` partial structure, `data` live.
        assert_eq!(
            unsafe {
                super::super::cms_ffi::CMS_final(cms.as_ptr(), data.0, ptr::null_mut(), CMS_BINARY)
            },
            1
        );
        cms.to_der().unwrap()
    }

    /// An `EnvelopedData` of `b"csr"` addressed to `recipient` with `cipher` and the production
    /// key transport, built in `ctx` (null: the default library context).
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn envelope_with(
        ctx: *mut openssl_sys::OSSL_LIB_CTX,
        recipient: &X509,
        cipher: Cipher,
    ) -> Vec<u8> {
        // SAFETY: null certificates/data are valid for a partial structure; `ctx` is null or live.
        let raw = unsafe {
            CMS_encrypt_ex(
                ptr::null_mut(),
                ptr::null_mut(),
                cipher.as_ptr(),
                CMS_PARTIAL | CMS_BINARY,
                ctx,
                ptr::null(),
            )
        };
        assert!(!raw.is_null(), "{}", openssl::error::ErrorStack::get());
        // SAFETY: `raw` is an owned structure.
        seal_envelope(&unsafe { CmsContentInfo::from_ptr(raw) }, recipient, b"csr").unwrap()
    }

    /// An AES-128-CBC `EnvelopedData` of `b"csr"` with PKCS#1 v1.5 (`rsaEncryption`) key
    /// transport, OpenSSL's default, built in `ctx`.
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn pkcs1_envelope(ctx: &FixtureCtx, recipient: &X509) -> Vec<u8> {
        let mut certs = Stack::<X509>::new().unwrap();
        certs.push(recipient.clone()).unwrap();
        let data = MemBio::over(b"csr").unwrap();
        // SAFETY: all handles are live for the call; the result is owned.
        let raw = unsafe {
            CMS_encrypt_ex(
                certs.as_ptr(),
                data.0,
                Cipher::aes_128_cbc().as_ptr(),
                CMS_BINARY,
                ctx.ctx.as_ptr(),
                ptr::null(),
            )
        };
        assert!(!raw.is_null(), "{}", openssl::error::ErrorStack::get());
        // SAFETY: `raw` is an owned structure.
        unsafe { CmsContentInfo::from_ptr(raw) }.to_der().unwrap()
    }

    /// DER of the RSAES-OAEP and rsaEncryption (PKCS#1 v1.5) `OBJECT IDENTIFIER`s.
    const RSAES_OAEP_OID: [u8; 11] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07,
    ];
    const RSA_ENCRYPTION_OID: [u8; 11] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[cfg(not(feature = "non-fips"))]
    #[test]
    fn fips_envelopes_use_rsaes_oaep_only() {
        let (ca_cert, ca_key) = self_signed("ca");
        let envelope = envelope_for_recipient(&ca_cert, b"csr").unwrap();
        assert!(contains(&envelope, &RSAES_OAEP_OID));
        assert!(!contains(&envelope, &RSA_ENCRYPTION_OID));
        assert_eq!(
            decrypt_envelope(&envelope, &ca_key, &ca_cert).unwrap(),
            b"csr"
        );

        let ctx = FixtureCtx::new(&["default"]);
        let err = decrypt_envelope(&pkcs1_envelope(&ctx, &ca_cert), &ca_key, &ca_cert)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("key-transport algorithm rsaEncryption is not allowed"),
            "{err}"
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn non_fips_envelopes_keep_pkcs1_v15() {
        let (ca_cert, ca_key) = self_signed("ca");
        let envelope = envelope_for_recipient(&ca_cert, b"csr").unwrap();
        assert!(contains(&envelope, &RSA_ENCRYPTION_OID));
        assert!(!contains(&envelope, &RSAES_OAEP_OID));
        assert_eq!(
            decrypt_envelope(&envelope, &ca_key, &ca_cert).unwrap(),
            b"csr"
        );
        let ctx = FixtureCtx::new(&["default"]);
        assert_eq!(
            decrypt_envelope(&pkcs1_envelope(&ctx, &ca_cert), &ca_key, &ca_cert).unwrap(),
            b"csr"
        );
    }

    #[test]
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn multiple_signers_are_rejected() {
        let (c1, k1) = self_signed("one");
        let (c2, k2) = self_signed("two");
        // SAFETY: `EVP_sha256` returns a static method.
        let der = signed_by(ptr::null_mut(), &[(&c1, &k1), (&c2, &k2)], unsafe {
            openssl_sys::EVP_sha256()
        });
        let err = parse_signed_pkimessage(&der).unwrap_err().to_string();
        assert!(err.contains("exactly one SignerInfo"), "{err}");
    }

    #[test]
    #[expect(unsafe_code)] // SAFETY: OpenSSL FFI; justified at each unsafe block
    fn signer_digest_allow_list() {
        let ctx = FixtureCtx::new(&["default"]);
        let (cert, key) = self_signed("client");
        // SAFETY: the `EVP_*` digest getters return static methods.
        let (sha1, md5, sha384, sha512) = unsafe {
            (
                openssl_sys::EVP_sha1(),
                openssl_sys::EVP_md5(),
                openssl_sys::EVP_sha384(),
                openssl_sys::EVP_sha512(),
            )
        };
        for md in [sha1, md5] {
            let der = signed_by(ctx.ctx.as_ptr(), &[(&cert, &key)], md);
            let err = parse_signed_pkimessage(&der).unwrap_err().to_string();
            assert!(err.contains("digest algorithm"), "{err}");
        }
        for md in [sha384, sha512] {
            let der = signed_by(ctx.ctx.as_ptr(), &[(&cert, &key)], md);
            assert_eq!(
                parse_signed_pkimessage(&der).unwrap().attrs,
                request_attrs()
            );
        }
    }

    #[test]
    fn aes_cbc_envelopes_are_accepted() {
        let (ca_cert, ca_key) = self_signed("ca");
        for cipher in [
            Cipher::aes_128_cbc(),
            Cipher::aes_192_cbc(),
            Cipher::aes_256_cbc(),
        ] {
            let envelope = envelope_with(ptr::null_mut(), &ca_cert, cipher);
            assert_eq!(
                decrypt_envelope(&envelope, &ca_key, &ca_cert).unwrap(),
                b"csr"
            );
        }
    }

    #[test]
    fn des3_envelope_is_refused() {
        let ctx = FixtureCtx::new(&["default"]);
        let (ca_cert, ca_key) = self_signed("ca");
        let envelope = envelope_with(ctx.ctx.as_ptr(), &ca_cert, Cipher::des_ede3_cbc());
        let err = decrypt_envelope(&envelope, &ca_key, &ca_cert)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("content-encryption algorithm DES-EDE3-CBC is not allowed"),
            "{err}"
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn des_and_rc2_envelopes_are_refused() {
        let ctx = FixtureCtx::new(&["default", "legacy"]);
        let (ca_cert, ca_key) = self_signed("ca");
        for cipher in [Cipher::des_cbc(), Cipher::rc2_cbc()] {
            let envelope = envelope_with(ctx.ctx.as_ptr(), &ca_cert, cipher);
            let err = decrypt_envelope(&envelope, &ca_key, &ca_cert)
                .unwrap_err()
                .to_string();
            assert!(err.contains("is not allowed"), "{err}");
        }
    }

    #[test]
    fn certs_only_contains_all_certificates() {
        let (c1, _) = self_signed("one");
        let (c2, _) = self_signed("two");
        let der = certs_only_der(&[c1.clone(), c2.clone()]).unwrap();
        let p7 = openssl::pkcs7::Pkcs7::from_der(&der).unwrap();
        let empty = Stack::<X509>::new().unwrap();
        let certs = p7
            .signed()
            .unwrap()
            .certificates()
            .map(|s| s.iter().map(|c| c.to_der().unwrap()).collect::<Vec<_>>())
            .unwrap_or_default();
        drop(empty);
        assert_eq!(certs, vec![c1.to_der().unwrap(), c2.to_der().unwrap()]);
    }
}

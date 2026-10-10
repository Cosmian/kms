//! SCEP (RFC 8894) CMS helpers: signed `pkiMessage` construction / parsing and
//! the `pkcsPKIEnvelope` (`EnvelopedData`) layer.
//!
//! The OpenSSL safe wrapper does not expose custom signed attributes, so the
//! outer `pkiMessage` is built with the partial CMS API from [`super::cms_ffi`].
//!
//! Every `unsafe` block carries a `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::{
    ffi::{CString, c_int, c_void},
    ptr,
};

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    cms::{CMSOptions, CmsContentInfo},
    pkey::{PKeyRef, Private},
    stack::Stack,
    symm::Cipher,
    x509::{X509, X509Ref},
};

use super::cms_ffi::{
    CMS_BINARY, CMS_DETACHED, CMS_NO_SIGNER_CERT_VERIFY, CMS_NOSMIMECAP, CMS_PARTIAL,
    CMS_SignerInfo, attribute_string_bytes,
};
use crate::{crypto_bail, crypto_error, error::result::CryptoResult};

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
/// AES-128-CBC (RFC 8894 §3.5.2 `AES` capability).
///
/// # Errors
/// Fails when OpenSSL cannot build the structure.
pub fn envelope_for_recipient(recipient: &X509Ref, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
    let mut stack = Stack::<X509>::new()?;
    stack.push(recipient.to_owned())?;
    let cms =
        CmsContentInfo::encrypt(&stack, plaintext, Cipher::aes_128_cbc(), CMSOptions::BINARY)?;
    Ok(cms.to_der()?)
}

/// Decrypt a CMS `EnvelopedData` addressed to `cert` with its private key.
///
/// # Errors
/// Fails on malformed input or when the key does not match any recipient.
pub fn decrypt_envelope(
    envelope_der: &[u8],
    key: &PKeyRef<Private>,
    cert: &X509,
) -> CryptoResult<Vec<u8>> {
    let cms = CmsContentInfo::from_der(envelope_der)?;
    Ok(cms.decrypt(key, cert)?)
}

/// Owned `ASN1_OBJECT` created from a dotted OID.
struct Asn1Obj(*mut openssl_sys::ASN1_OBJECT);

impl Asn1Obj {
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
    fn drop(&mut self) {
        // SAFETY: pointer was returned by `OBJ_txt2obj` and is freed exactly once.
        unsafe { openssl_sys::ASN1_OBJECT_free(self.0) }
    }
}

/// Owned memory BIO.
struct MemBio(*mut openssl_sys::BIO);

impl MemBio {
    fn new() -> CryptoResult<Self> {
        // SAFETY: `BIO_s_mem` returns a static method table; `BIO_new` takes it by pointer.
        let p = unsafe { openssl_sys::BIO_new(openssl_sys::BIO_s_mem()) };
        if p.is_null() {
            crypto_bail!("BIO_new failed");
        }
        Ok(Self(p))
    }

    /// A read-only BIO over `data`; `data` MUST outlive the returned BIO.
    fn over(data: &[u8]) -> CryptoResult<Self> {
        let len = c_int::try_from(data.len())?;
        // SAFETY: the BIO only reads `len` bytes from `data`, which outlives it (caller contract).
        let p = unsafe { openssl_sys::BIO_new_mem_buf(data.as_ptr().cast::<c_void>(), len) };
        if p.is_null() {
            crypto_bail!("BIO_new_mem_buf failed");
        }
        Ok(Self(p))
    }

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

impl Drop for MemBio {
    fn drop(&mut self) {
        // SAFETY: pointer came from `BIO_new`/`BIO_new_mem_buf` and is freed exactly once.
        unsafe { openssl_sys::BIO_free_all(self.0) };
    }
}

/// Add a string-typed signed attribute.
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
/// Checks that exactly one `SignerInfo` is present, verifies the CMS signature against the
/// certificate embedded in the message (no chain validation: trust is evaluated by the
/// caller), and extracts the SCEP signed attributes.
///
/// # Errors
/// Fails on malformed messages, a signer count different from one, a missing mandatory
/// attribute, or an invalid signature.
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use openssl::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
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
        msg[pos + 10] ^= 0xFF;
        parse_signed_pkimessage(&msg).unwrap_err();
    }

    #[test]
    fn multiple_signers_are_rejected() {
        let (c1, k1) = self_signed("one");
        let (c2, k2) = self_signed("two");
        // Plain CMS signed data with two signers built through the partial API.
        // SAFETY: null pointers are valid for a partial structure with no data.
        let raw = unsafe {
            openssl_sys::CMS_sign(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CMS_PARTIAL | CMS_BINARY,
            )
        };
        assert!(!raw.is_null());
        // SAFETY: `raw` is an owned structure.
        let cms = unsafe { CmsContentInfo::from_ptr(raw) };
        for (c, k) in [(&c1, &k1), (&c2, &k2)] {
            // SAFETY: all handles are live.
            let si = unsafe {
                super::super::cms_ffi::CMS_add1_signer(
                    cms.as_ptr(),
                    c.as_ptr(),
                    k.as_ptr(),
                    openssl_sys::EVP_sha256(),
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
        let der = cms.to_der().unwrap();
        let err = parse_signed_pkimessage(&der).unwrap_err().to_string();
        assert!(err.contains("exactly one SignerInfo"), "{err}");
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

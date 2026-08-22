//! X.509 v2 CRL builder using OpenSSL FFI.
//!
//! The Rust `openssl` crate (v0.10) does not provide a CRL builder.
//! This module uses `openssl-sys` directly to construct a CRL per RFC 5280 §5.

use std::ptr;

use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    asn1::{Asn1Object, Asn1OctetString},
    pkey::{PKeyRef, Private},
    sha::Sha1,
    x509::{X509Crl, X509Extension, X509Ref},
};
use time::OffsetDateTime;

use crate::error::CryptoError;

/// RFC 5280 §5.3.1 `CRLReason` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CrlReasonCode {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // 7 is not used
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl CrlReasonCode {
    /// Returns the reason code as an `openssl_sys::BN_ULONG`.
    #[expect(clippy::as_conversions)]
    fn as_bn_ulong(self) -> openssl_sys::BN_ULONG {
        openssl_sys::BN_ULONG::from(self as u32)
    }
}

/// A single revoked certificate entry for inclusion in the CRL.
#[derive(Debug, Clone)]
pub struct RevokedEntry {
    /// DER-encoded serial number bytes (big-endian unsigned integer).
    pub serial_number: Vec<u8>,
    /// The date the certificate was revoked.
    pub revocation_date: OffsetDateTime,
    /// RFC 5280 §5.3.1 reason code. Omit (None) or Unspecified to not include the extension.
    pub reason_code: Option<CrlReasonCode>,
    /// RFC 5280 §5.3.2 invalidity date (when compromise actually occurred).
    pub invalidity_date: Option<OffsetDateTime>,
}

/// Build a DER-encoded X.509 v2 CRL signed by the given issuer.
///
/// # Arguments
/// * `issuer_cert` — The CA certificate (used for issuer name and Authority Key Identifier).
/// * `issuer_key` — The CA private key (must have `cRLSign` in keyUsage).
/// * `revoked_entries` — Certificates to list as revoked.
/// * `crl_number` — Monotonically increasing CRL sequence number (RFC 5280 §5.2.3).
/// * `validity_days` — Number of days until `nextUpdate` (from now).
///
/// # Returns
/// The signed CRL wrapped in the `openssl` crate's `X509Crl` type.
///
/// # Errors
/// Returns `CryptoError` on any OpenSSL failure.
#[expect(unsafe_code)]
pub fn build_crl(
    issuer_cert: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    revoked_entries: &[RevokedEntry],
    crl_number: u64,
    validity_days: u32,
) -> Result<X509Crl, CryptoError> {
    // SAFETY: All FFI calls check return values and free resources on error paths.
    // The CrlGuard ensures X509_CRL_free is called even on early returns.
    unsafe {
        let crl = openssl_sys::X509_CRL_new();
        if crl.is_null() {
            return Err(CryptoError::Default("X509_CRL_new failed".to_owned()));
        }
        let crl_guard = CrlGuard(crl);

        // Set version to v2 (integer value 1)
        if openssl_sys::X509_CRL_set_version(crl, 1) != 1 {
            return Err(CryptoError::Default(
                "X509_CRL_set_version failed".to_owned(),
            ));
        }

        // Set issuer name from the CA certificate's subject
        let issuer_name = openssl_sys::X509_get_subject_name(issuer_cert.as_ptr());
        if issuer_name.is_null() {
            return Err(CryptoError::Default(
                "X509_get_subject_name returned null".to_owned(),
            ));
        }
        if openssl_sys::X509_CRL_set_issuer_name(crl, issuer_name) != 1 {
            return Err(CryptoError::Default(
                "X509_CRL_set_issuer_name failed".to_owned(),
            ));
        }

        // Set thisUpdate = now
        let now_epoch = OffsetDateTime::now_utc().unix_timestamp();
        let this_update = openssl_sys::ASN1_TIME_set(ptr::null_mut(), now_epoch);
        if this_update.is_null() {
            return Err(CryptoError::Default(
                "ASN1_TIME_set (thisUpdate) failed".to_owned(),
            ));
        }
        let rc = openssl_sys::X509_CRL_set1_lastUpdate(crl, this_update);
        openssl_sys::ASN1_TIME_free(this_update);
        if rc != 1 {
            return Err(CryptoError::Default(
                "X509_CRL_set1_lastUpdate failed".to_owned(),
            ));
        }

        // Set nextUpdate = now + validity_days
        let next_epoch = now_epoch + i64::from(validity_days) * 86400;
        let next_update = openssl_sys::ASN1_TIME_set(ptr::null_mut(), next_epoch);
        if next_update.is_null() {
            return Err(CryptoError::Default(
                "ASN1_TIME_set (nextUpdate) failed".to_owned(),
            ));
        }
        let rc = openssl_sys::X509_CRL_set1_nextUpdate(crl, next_update);
        openssl_sys::ASN1_TIME_free(next_update);
        if rc != 1 {
            return Err(CryptoError::Default(
                "X509_CRL_set1_nextUpdate failed".to_owned(),
            ));
        }

        // Add revoked entries
        for entry in revoked_entries {
            add_revoked_entry(crl, entry)?;
        }

        // Sort entries by serial number (RFC 5280 recommends, some impls require)
        openssl_sys::X509_CRL_sort(crl);

        // Add Authority Key Identifier extension (RFC 5280 §5.2.1 — MUST, non-critical)
        add_aki_extension(crl, issuer_cert)?;

        // Add CRL Number extension (RFC 5280 §5.2.3 — MUST, non-critical)
        add_crl_number_extension(crl, crl_number)?;

        // Sign the CRL
        let md = signing_md(issuer_key);
        if openssl_sys::X509_CRL_sign(crl, issuer_key.as_ptr(), md) <= 0 {
            return Err(CryptoError::Default("X509_CRL_sign failed".to_owned()));
        }

        // Convert to the safe openssl crate type.
        // We must prevent the guard from freeing the CRL since X509Crl takes ownership.
        let owned_crl = X509Crl::from_ptr(crl);
        std::mem::forget(crl_guard);

        Ok(owned_crl)
    }
}

/// RAII guard for an owned `X509_CRL*` — frees on drop.
struct CrlGuard(*mut openssl_sys::X509_CRL);

impl Drop for CrlGuard {
    #[expect(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: pointer was either null-checked before wrapping or is handled by
        // X509_CRL_free which accepts null as a no-op.
        unsafe { openssl_sys::X509_CRL_free(self.0) }
    }
}

/// Add a single revoked certificate entry to the CRL.
#[expect(unsafe_code)]
unsafe fn add_revoked_entry(
    crl: *mut openssl_sys::X509_CRL,
    entry: &RevokedEntry,
) -> Result<(), CryptoError> {
    unsafe {
        let revoked = openssl_sys::X509_REVOKED_new();
        if revoked.is_null() {
            return Err(CryptoError::Default("X509_REVOKED_new failed".to_owned()));
        }

        // Set serial number
        let serial_len = i32::try_from(entry.serial_number.len()).map_err(|_e| {
            CryptoError::Default("serial number length exceeds i32::MAX".to_owned())
        })?;
        let bn = openssl_sys::BN_bin2bn(entry.serial_number.as_ptr(), serial_len, ptr::null_mut());
        if bn.is_null() {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default("BN_bin2bn failed".to_owned()));
        }
        let serial = openssl_sys::BN_to_ASN1_INTEGER(bn, ptr::null_mut());
        openssl_sys::BN_free(bn);
        if serial.is_null() {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default("BN_to_ASN1_INTEGER failed".to_owned()));
        }
        let rc = openssl_sys::X509_REVOKED_set_serialNumber(revoked, serial);
        openssl_sys::ASN1_INTEGER_free(serial);
        if rc != 1 {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default(
                "X509_REVOKED_set_serialNumber failed".to_owned(),
            ));
        }

        // Set revocation date
        let rev_epoch = entry.revocation_date.unix_timestamp();
        let rev_time = openssl_sys::ASN1_TIME_set(ptr::null_mut(), rev_epoch);
        if rev_time.is_null() {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default(
                "ASN1_TIME_set (revocationDate) failed".to_owned(),
            ));
        }
        // X509_REVOKED_set_revocationDate copies the value — we still free rev_time.
        let rc = openssl_sys::X509_REVOKED_set_revocationDate(revoked, rev_time);
        openssl_sys::ASN1_TIME_free(rev_time);
        if rc != 1 {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default(
                "X509_REVOKED_set_revocationDate failed".to_owned(),
            ));
        }

        // Add reason code extension (RFC 5280 §5.3.1) — non-critical, SHOULD be present
        // Omit if reason is Unspecified (conforming to RFC 5280 §5.3.1 recommendation).
        if let Some(reason) = entry.reason_code {
            if reason != CrlReasonCode::Unspecified {
                add_reason_code_extension(revoked, reason)?;
            }
        }

        // Add invalidity date extension (RFC 5280 §5.3.2) — non-critical
        if let Some(invalidity_date) = entry.invalidity_date {
            add_invalidity_date_extension(revoked, invalidity_date)?;
        }

        // X509_CRL_add0_revoked takes ownership of `revoked` on success
        if openssl_sys::X509_CRL_add0_revoked(crl, revoked) != 1 {
            openssl_sys::X509_REVOKED_free(revoked);
            return Err(CryptoError::Default(
                "X509_CRL_add0_revoked failed".to_owned(),
            ));
        }

        Ok(())
    }
}

/// Add `CRLReason` extension to a revoked entry.
///
/// `ASN1_ENUMERATED` is structurally identical to `ASN1_INTEGER` in OpenSSL.
/// Since openssl-sys 0.9 does not expose `ASN1_ENUMERATED_new`/`_set`, we
/// create an `ASN1_INTEGER` via `BN_to_ASN1_INTEGER` and cast. The i2d handler
/// for `NID_crl_reason` expects an `ASN1_ENUMERATED*` which works transparently.
#[expect(unsafe_code)]
unsafe fn add_reason_code_extension(
    revoked: *mut openssl_sys::X509_REVOKED,
    reason: CrlReasonCode,
) -> Result<(), CryptoError> {
    unsafe {
        let bn = openssl_sys::BN_new();
        if bn.is_null() {
            return Err(CryptoError::Default("BN_new (CRLReason) failed".to_owned()));
        }
        if openssl_sys::BN_set_word(bn, reason.as_bn_ulong()) != 1 {
            openssl_sys::BN_free(bn);
            return Err(CryptoError::Default(
                "BN_set_word (CRLReason) failed".to_owned(),
            ));
        }
        let asn1_int = openssl_sys::BN_to_ASN1_INTEGER(bn, ptr::null_mut());
        openssl_sys::BN_free(bn);
        if asn1_int.is_null() {
            return Err(CryptoError::Default(
                "BN_to_ASN1_INTEGER (CRLReason) failed".to_owned(),
            ));
        }
        let rc = openssl_sys::X509_REVOKED_add1_ext_i2d(
            revoked,
            openssl_sys::NID_crl_reason,
            asn1_int.cast(),
            0, // non-critical
            0, // flags: 0 = add new
        );
        openssl_sys::ASN1_INTEGER_free(asn1_int);
        if rc != 1 {
            return Err(CryptoError::Default(
                "X509_REVOKED_add1_ext_i2d (CRLReason) failed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Add invalidityDate extension to a revoked entry.
#[expect(unsafe_code)]
unsafe fn add_invalidity_date_extension(
    revoked: *mut openssl_sys::X509_REVOKED,
    date: OffsetDateTime,
) -> Result<(), CryptoError> {
    unsafe {
        let epoch = date.unix_timestamp();
        let asn1_time = openssl_sys::ASN1_TIME_set(ptr::null_mut(), epoch);
        if asn1_time.is_null() {
            return Err(CryptoError::Default(
                "ASN1_TIME_set (invalidityDate) failed".to_owned(),
            ));
        }
        let rc = openssl_sys::X509_REVOKED_add1_ext_i2d(
            revoked,
            openssl_sys::NID_invalidity_date,
            asn1_time.cast(),
            0, // non-critical
            0, // flags
        );
        openssl_sys::ASN1_TIME_free(asn1_time);
        if rc != 1 {
            return Err(CryptoError::Default(
                "X509_REVOKED_add1_ext_i2d (invalidityDate) failed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Add Authority Key Identifier extension to the CRL (RFC 5280 §5.2.1).
///
/// Builds the AKI DER structure manually to avoid relying on OpenSSL's
/// `X509V3_EXT_nconf_nid`, which uses `EVP_sha1()` when the issuer certificate
/// has no `SubjectKeyIdentifier` extension.  In FIPS mode (FIPS provider only) the
/// EVP SHA-1 digest is unavailable, causing that high-level call to fail.
///
/// Instead we compute the key identifier directly:
/// - If the issuer cert carries a `subjectKeyIdentifier` extension, its value is
///   reused verbatim (no hash required).
/// - Otherwise we hash the issuer's `SubjectPublicKeyInfo` DER with SHA-1 using the
///   low-level `openssl::sha::Sha1` API (bypasses the provider mechanism, works in
///   FIPS mode).
///
/// The encoded extension value is:
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///   keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL }
/// KeyIdentifier ::= OCTET STRING
/// ```
#[expect(unsafe_code)]
fn add_aki_extension(
    crl: *mut openssl_sys::X509_CRL,
    issuer_cert: &X509Ref,
) -> Result<(), CryptoError> {
    // ── Step 1: derive the key identifier bytes ──────────────────────────────
    let key_id: Vec<u8> = if let Some(ski) = issuer_cert.subject_key_id() {
        ski.as_slice().to_vec()
    } else {
        // Hash the full SubjectPublicKeyInfo DER.  The low-level Sha1 API does
        // not go through the OpenSSL provider infrastructure, so it works in
        // both FIPS and non-FIPS builds.
        let pk = issuer_cert
            .public_key()
            .map_err(|e| CryptoError::Default(format!("AKI: get public key: {e}")))?;
        let spki_der = pk
            .public_key_to_der()
            .map_err(|e| CryptoError::Default(format!("AKI: SPKI to DER: {e}")))?;
        let mut h = Sha1::default();
        h.update(&spki_der);
        h.finish().to_vec()
    };

    // ── Step 2: encode the AKI DER ───────────────────────────────────────────
    // [0] IMPLICIT (context-class, primitive, tag 0) wraps the key_id bytes.
    let mut tagged = vec![0x80_u8]; // context-specific primitive tag 0
    aki_write_length(&mut tagged, key_id.len())?;
    tagged.extend_from_slice(&key_id);

    // Outer SEQUENCE wraps the [0] value.
    let mut aki_der = vec![0x30_u8]; // SEQUENCE
    aki_write_length(&mut aki_der, tagged.len())?;
    aki_der.extend_from_slice(&tagged);

    // ── Step 3: create the X.509 extension and attach it to the CRL ─────────
    let oid = Asn1Object::from_str("2.5.29.35")
        .map_err(|e| CryptoError::Default(format!("AKI OID: {e}")))?;
    let val = Asn1OctetString::new_from_bytes(&aki_der)
        .map_err(|e| CryptoError::Default(format!("AKI value: {e}")))?;
    let ext = X509Extension::new_from_der(oid.as_ref(), false, val.as_ref())
        .map_err(|e| CryptoError::Default(format!("AKI extension: {e}")))?;

    // SAFETY: ext.as_ptr() is a valid non-null pointer for the duration of this call.
    let rc = unsafe { openssl_sys::X509_CRL_add_ext(crl, ext.as_ptr(), -1) };
    if rc != 1 {
        return Err(CryptoError::Default(
            "X509_CRL_add_ext (AKI) failed".to_owned(),
        ));
    }
    Ok(())
}

/// Write an ASN.1 DER length field into `buf` (short or long form).
///
/// Supports lengths up to 65 535.
// SAFETY: casts are guarded by explicit range checks immediately above each cast.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
fn aki_write_length(buf: &mut Vec<u8>, len: usize) -> Result<(), CryptoError> {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len <= 0xFF {
        buf.push(0x81_u8);
        buf.push(len as u8);
    } else if len <= 0xFFFF {
        buf.push(0x82_u8);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    } else {
        return Err(CryptoError::Default(format!(
            "AKI key identifier length {len} exceeds 65535"
        )));
    }
    Ok(())
}

/// Add CRL Number extension (RFC 5280 §5.2.3 — MUST, non-critical).
#[expect(unsafe_code)]
unsafe fn add_crl_number_extension(
    crl: *mut openssl_sys::X509_CRL,
    crl_number: u64,
) -> Result<(), CryptoError> {
    unsafe {
        let bn = openssl_sys::BN_new();
        if bn.is_null() {
            return Err(CryptoError::Default("BN_new failed".to_owned()));
        }
        // BN_set_word sets the BIGNUM to a u64 value
        if openssl_sys::BN_set_word(bn, crl_number) != 1 {
            openssl_sys::BN_free(bn);
            return Err(CryptoError::Default("BN_set_word failed".to_owned()));
        }
        let asn1_int = openssl_sys::BN_to_ASN1_INTEGER(bn, ptr::null_mut());
        openssl_sys::BN_free(bn);
        if asn1_int.is_null() {
            return Err(CryptoError::Default(
                "BN_to_ASN1_INTEGER (CRL Number) failed".to_owned(),
            ));
        }
        let rc = openssl_sys::X509_CRL_add1_ext_i2d(
            crl,
            openssl_sys::NID_crl_number,
            asn1_int.cast(),
            0, // non-critical
            0, // flags
        );
        openssl_sys::ASN1_INTEGER_free(asn1_int);
        if rc != 1 {
            return Err(CryptoError::Default(
                "X509_CRL_add1_ext_i2d (CRL Number) failed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Select the message digest for CRL signing based on the key type.
///
/// Mirrors the logic in `build_certificate.rs::signing_digest`.
#[expect(unsafe_code)]
fn signing_md(key: &PKeyRef<Private>) -> *const openssl_sys::EVP_MD {
    // SAFETY: EVP_sha256/EVP_md_null return static pointers — no allocation.
    unsafe {
        match key.id() {
            openssl::pkey::Id::RSA | openssl::pkey::Id::EC => openssl_sys::EVP_sha256(),
            // PQC algorithms (ML-DSA, SLH-DSA) use null digest — the algorithm
            // performs its own internal hashing.
            _ => openssl_sys::EVP_md_null(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use openssl::{
        pkey::PKey,
        x509::{X509, X509Crl},
    };
    use time::OffsetDateTime;

    use super::*;

    /// Helper: generate a self-signed CA certificate for testing.
    fn create_test_ca() -> (X509, openssl::pkey::PKey<Private>) {
        let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey from RSA");

        let mut name = openssl::x509::X509NameBuilder::new().expect("X509NameBuilder");
        name.append_entry_by_text("CN", "Test CA")
            .expect("append CN");
        let name = name.build();

        let mut builder = openssl::x509::X509Builder::new().expect("X509Builder");
        builder.set_version(2).expect("set_version"); // v3
        builder.set_subject_name(&name).expect("set_subject_name");
        builder.set_issuer_name(&name).expect("set_issuer_name");
        builder.set_pubkey(&pkey).expect("set_pubkey");

        // Validity
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("not_before");
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).expect("not_after");
        builder.set_not_before(&not_before).expect("set_not_before");
        builder.set_not_after(&not_after).expect("set_not_after");

        // Serial
        let serial = openssl::asn1::Asn1Integer::from_bn(
            openssl::bn::BigNum::from_u32(1).expect("BigNum").as_ref(),
        )
        .expect("Asn1Integer");
        builder
            .set_serial_number(&serial)
            .expect("set_serial_number");

        // Basic constraints + key usage
        let bc = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .ca()
            .build()
            .expect("BasicConstraints");
        builder.append_extension(bc).expect("append bc");

        let ku = openssl::x509::extension::KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .expect("KeyUsage");
        builder.append_extension(ku).expect("append ku");

        // Subject Key Identifier (needed for AKI derivation)
        let ski = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .expect("SKI");
        builder.append_extension(ski).expect("append ski");

        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .expect("sign");
        let cert = builder.build();

        (cert, pkey)
    }

    #[test]
    fn test_build_empty_crl() {
        let (cert, key) = create_test_ca();
        let crl = build_crl(&cert, &key, &[], 1, 7).expect("build_crl");

        // Verify the CRL can be parsed back from DER
        let der = crl.to_der().expect("to_der");
        let parsed = X509Crl::from_der(&der).expect("from_der");

        // Verify signature
        assert!(parsed.verify(&key).expect("verify signature"));
    }

    #[test]
    fn test_build_crl_with_entries() {
        let (cert, key) = create_test_ca();

        let entries = vec![
            RevokedEntry {
                serial_number: vec![0x01, 0x02, 0x03],
                revocation_date: OffsetDateTime::now_utc(),
                reason_code: Some(CrlReasonCode::KeyCompromise),
                invalidity_date: Some(OffsetDateTime::now_utc()),
            },
            RevokedEntry {
                serial_number: vec![0x0A, 0x0B],
                revocation_date: OffsetDateTime::now_utc(),
                reason_code: Some(CrlReasonCode::CessationOfOperation),
                invalidity_date: None,
            },
            RevokedEntry {
                serial_number: vec![0xFF],
                revocation_date: OffsetDateTime::now_utc(),
                reason_code: None, // unspecified — extension should be omitted
                invalidity_date: None,
            },
        ];

        let crl = build_crl(&cert, &key, &entries, 42, 30).expect("build_crl with entries");

        // Round-trip through DER
        let der = crl.to_der().expect("to_der");
        let parsed = X509Crl::from_der(&der).expect("from_der");

        // Verify signature
        assert!(parsed.verify(&key).expect("verify DER signature"));

        // Also verify PEM round-trip
        let pem = crl.to_pem().expect("to_pem");
        let parsed_pem = X509Crl::from_pem(&pem).expect("from_pem");
        assert!(parsed_pem.verify(&key).expect("verify PEM signature"));
    }
}

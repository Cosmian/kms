//! OID helpers built on `OpenSSL` NIDs.
//!
//! `rust-openssl` exposes well-known OIDs as [`Nid`] constants only: there is no `Nid` to
//! `Asn1Object` conversion and no `Nid` to dotted-string accessor. These helpers bridge that
//! gap so that no dotted OID has to be spelled out for an OID `OpenSSL` already knows.

use openssl::{asn1::Asn1Object, error::ErrorStack, nid::Nid};
use x509_parser::asn1_rs::Oid;

/// The [`Asn1Object`] of a NID.
///
/// `rust-openssl` has no `OBJ_nid2obj` wrapper; the short name round-trips through
/// `OBJ_txt2obj`, which resolves short names before dotted strings.
pub fn asn1_object(nid: Nid) -> Result<Asn1Object, ErrorStack> {
    Asn1Object::from_str(nid.short_name()?)
}

/// The NID of a dotted OID, or [`Nid::UNDEF`] when `OpenSSL` does not know it or `oid` is not
/// dotted-decimal (`OBJ_txt2obj` would also resolve names, and `Asn1Object::from_str` panics
/// on a NUL byte).
#[must_use]
pub fn nid_of(oid: &str) -> Nid {
    if oid.is_empty() || !oid.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Nid::UNDEF;
    }
    Asn1Object::from_str(oid).map_or(Nid::UNDEF, |obj| obj.nid())
}

/// The dotted-decimal string of a NID's OID, e.g. `Nid::SERVER_AUTH` -> `1.3.6.1.5.5.7.3.1`.
pub fn oid_string(nid: Nid) -> Result<String, ErrorStack> {
    let obj = asn1_object(nid)?;
    Ok(Oid::new(std::borrow::Cow::Borrowed(obj.as_slice())).to_id_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn nid_oid_round_trip() {
        for (nid, dotted) in [
            (Nid::SERVER_AUTH, "1.3.6.1.5.5.7.3.1"),
            (Nid::SUBJECT_ALT_NAME, "2.5.29.17"),
            (Nid::SECP256K1, "1.3.132.0.10"),
            (Nid::MS_UPN, "1.3.6.1.4.1.311.20.2.3"),
        ] {
            assert_eq!(oid_string(nid).unwrap(), dotted);
            assert_eq!(nid_of(dotted), nid);
            assert_eq!(asn1_object(nid).unwrap().nid(), nid);
        }
        assert_eq!(nid_of("1.3.6.1.4.1.16376.9.2.1"), Nid::UNDEF);
        // names and NUL bytes are not dotted OIDs
        assert_eq!(nid_of("subjectAltName"), Nid::UNDEF);
        assert_eq!(nid_of("2.5.29.17\0"), Nid::UNDEF);
        assert_eq!(nid_of(""), Nid::UNDEF);
    }
}

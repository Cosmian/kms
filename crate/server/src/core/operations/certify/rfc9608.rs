//! # RFC 9608 — No Revocation Available for X.509 Public Key Certificates
//!
//! <https://www.rfc-editor.org/rfc/rfc9608.html>
//!
//! **§2**: Defines the `id-ce-noRevAvail` extension (OID 2.5.29.56, `{ id-ce 56 }`).
//! When present, it signals to relying parties that no revocation information is
//! available for this certificate and they should not reject it for lack of a CRL
//! or OCSP response. Criticality MUST be FALSE; DER value is NULL (`'0500'H`).
//!
//! **§3**: This extension MUST NOT be present in CA public key certificates.
//!
//! **§4**: Updates RFC 5280 §6.1.3 certification path validation — implementations
//! should skip revocation checking for certificates carrying this extension.
//!
//! This module provides [`apply_extensions`] which conditionally appends
//! `id-ce-noRevAvail` to self-signed end-entity certificates that do not carry a
//! `crlDistributionPoints` extension.

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
use openssl::{
    asn1::{Asn1Object, Asn1OctetString},
    x509::{X509Builder, X509Extension},
};

use super::{extension_config_is_ca, issuer::Issuer};
use crate::result::KResult;

/// Conditionally append the RFC 9608 `id-ce-noRevAvail` extension.
///
/// The extension is added only when **all** of the following hold:
/// - The certificate is self-signed (`Issuer::PrivateKeyAndSubjectName`)
/// - No `crlDistributionPoints` was supplied in the user extension config (`!has_cdp`)
/// - The certificate is NOT a CA (RFC 9608 §3)
///
/// OID `2.5.29.56` (`{ id-ce 56 }`), non-critical, DER NULL value `0x05 0x00`.
pub(super) fn apply_extensions(
    x509_builder: &mut X509Builder,
    issuer: &Issuer,
    attributes: &Attributes,
    vendor_id: &str,
    has_cdp: bool,
) -> KResult<()> {
    let is_self_signed = matches!(issuer, Issuer::PrivateKeyAndSubjectName(..));
    let is_ca = extension_config_is_ca(attributes, vendor_id);
    if is_self_signed && !has_cdp && !is_ca {
        let oid = Asn1Object::from_str("2.5.29.56")?;
        let val = Asn1OctetString::new_from_bytes(&[0x05, 0x00])?;
        x509_builder.append_extension(X509Extension::new_from_der(
            oid.as_ref(),
            false,
            val.as_ref(),
        )?)?;
    }
    Ok(())
}

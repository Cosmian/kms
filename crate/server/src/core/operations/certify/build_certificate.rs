use std::{cmp::min, collections::HashSet, default::Default};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        extra::{VENDOR_ATTR_X509_EXTENSION, tagging::SYSTEM_TAG_CERTIFICATE},
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
        kmip_operations::Certify,
        kmip_types::{KeyFormatType, LinkType, VendorAttributeValue},
    },
    cosmian_kms_crypto::openssl::{
        openssl_certificate_to_kmip, openssl_x509_to_certificate_attributes, x509_extensions,
    },
};
use cosmian_logger::debug;
#[cfg(feature = "non-fips")]
use cosmian_logger::warn;
#[cfg(feature = "non-fips")]
use openssl::x509::extension::KeyUsage;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    hash::MessageDigest,
    pkey::Id,
    sha::Sha1,
    x509::X509,
};

use super::{issuer::Issuer, rfc9608, subject::Subject};
#[cfg(feature = "non-fips")]
use super::{rfc9881, rfc9909, rfc9935};
use crate::{
    error::KmsError,
    result::{KResult, KResultHelper},
};

const X509_VERSION3: i32 = 2;

pub(super) fn build_and_sign_certificate(
    vendor_id: &str,
    issuer: &Issuer,
    subject: &Subject,
    request: Certify,
) -> KResult<(Object, HashSet<String>, Attributes)> {
    debug!("Building and signing certificate");
    // recover the attributes
    let mut attributes = request.attributes.unwrap_or_default();
    // Set the object type
    attributes.object_type = Some(ObjectType::Certificate);

    // remove any link that helped identify the issuer
    // these will be properly re-added later
    attributes.remove_link(LinkType::CertificateLink);
    attributes.remove_link(LinkType::PrivateKeyLink);
    attributes.remove_link(LinkType::PublicKeyLink);

    // Create an X509 struct with the desired certificate information.
    let mut x509_builder = X509::builder()?;

    // Handle the subject name and public key
    x509_builder.set_version(X509_VERSION3)?;
    x509_builder.set_subject_name(subject.subject_name())?;
    x509_builder.set_pubkey(subject.public_key()?.as_ref())?;

    // Handle expiration dates
    // Create a new Asn1Time object for the current time
    let now = Asn1Time::days_from_now(0).context("could not get a date in ASN.1")?;
    // retrieve the number of days for the validity of the certificate
    let mut number_of_days =
        u32::try_from(attributes.remove_validity_days(vendor_id).unwrap_or(365))?;

    // the number of days cannot exceed that of the issuer certificate
    if let Some(issuer_not_after) = issuer.not_after() {
        let days = u32::try_from(now.diff(issuer_not_after)?.days)?;
        number_of_days = min(days, number_of_days);
    }
    x509_builder.set_not_before(now.as_ref())?;
    x509_builder.set_not_after(
        Asn1Time::days_from_now(number_of_days)
            .context("could not get a date in ASN.1")?
            .as_ref(),
    )?;

    // add subject extensions (from CSR or existing certificate)
    subject
        .extensions()?
        .into_iter()
        .try_for_each(|extension| x509_builder.append_extension(extension))?;

    // RFC 9881 §5 / RFC 9909 §6 / RFC 9935 §5: auto-add PQC keyUsage
    #[cfg(feature = "non-fips")]
    apply_pqc_key_usage(&mut x509_builder, subject, &attributes, vendor_id)?;

    // RFC 5280 §4.2: user-supplied extensions from vendor attribute CNF
    #[allow(unused_variables)]
    let (has_cdp, has_user_key_usage) =
        apply_user_extensions(&mut x509_builder, &mut attributes, vendor_id, issuer)?;

    // Warn when user-supplied keyUsage overrides RFC-mandated PQC keyUsage
    #[cfg(feature = "non-fips")]
    if has_user_key_usage && subject_pqc_algorithm(subject).is_some() {
        warn!(
            "User-supplied keyUsage in extension config overrides the RFC-mandated PQC keyUsage \
             extension (RFC 9881/9909/9935)"
        );
    }

    // RFC 9608 §2–§3: auto-add noRevAvail for self-signed end-entity certs
    apply_no_rev_avail(&mut x509_builder, issuer, &attributes, vendor_id, has_cdp)?;

    // The digest must match the *issuer's signing key* type, not the subject key.
    let digest = signing_digest(issuer.private_key());

    // Set the issuer name and private key
    x509_builder.set_issuer_name(issuer.subject_name())?;
    x509_builder.set_serial_number(create_subject_key_identifier_value(subject)?.as_ref())?;
    x509_builder.sign(issuer.private_key(), digest)?;

    let x509 = x509_builder.build();

    // Process the tags
    let mut tags = attributes.remove_tags(vendor_id).unwrap_or_default();
    if !tags.is_empty() {
        Attributes::check_user_tags(&tags)?;
    }
    // add subject tags if any
    tags.extend(subject.tags(vendor_id).iter().cloned());
    // add the certificate "system" tag
    tags.insert(SYSTEM_TAG_CERTIFICATE.to_owned());

    // link the certificate to the issuer certificate
    attributes.set_link(
        LinkType::CertificateLink,
        issuer.unique_identifier().clone().into(),
    );

    // remove cryptographic information from the certificate attributes
    attributes.cryptographic_algorithm = None;
    attributes.cryptographic_length = None;
    attributes.cryptographic_parameters = None;
    attributes.cryptographic_usage_mask = None;
    attributes.cryptographic_domain_parameters = None;
    // Set the key format type to X509
    attributes.key_format_type = Some(KeyFormatType::X509);

    // Add certificate attributes
    let certificate_attributes = openssl_x509_to_certificate_attributes(&x509);
    attributes.certificate_attributes = Some(certificate_attributes);

    Ok((
        openssl_certificate_to_kmip(&x509).map_err(KmsError::from)?,
        tags,
        attributes,
    ))
}

/// RFC 9881 (ML-DSA) / RFC 9935 (ML-KEM): extract the KMIP `CryptographicAlgorithm` from a
/// Subject that represents a fresh keypair or standalone public key. Returns `None` for
/// CSR-based and re-certification cases (they already carry RFC-compliant extensions).
#[cfg(feature = "non-fips")]
const fn subject_pqc_algorithm(subject: &Subject) -> Option<CryptographicAlgorithm> {
    match subject {
        Subject::PublicKeyAndSubjectName(_, owm, _) => {
            if let Object::PublicKey(pk) = owm.object() {
                pk.key_block.cryptographic_algorithm
            } else {
                None
            }
        }
        Subject::KeypairAndSubjectName(_, keypair, _) => {
            if let Object::PublicKey(pk) = &keypair.public_key_object {
                pk.key_block.cryptographic_algorithm
            } else {
                None
            }
        }
        Subject::X509Req(..) | Subject::Certificate(..) => None,
    }
}

/// Return `true` when the vendor extension-config attribute marks this certificate as a CA
/// (`basicConstraints=CA:TRUE` or `basicConstraints=critical,CA:TRUE`).
///
/// This is used in `build_and_sign_certificate` to decide whether to include the
/// `keyCertSign` and `cRLSign` bits in the RFC-mandated PQC `keyUsage` extension,
/// and to enforce RFC 9608 §3 (noRevAvail MUST NOT appear in CA certificates).
/// RFC 5280 §4.2.1.3 requires `keyCertSign` when `keyUsage` is present *and* the
/// certificate will be used to verify certificate signatures in path validation.
/// OpenSSL's `X509_verify_cert` enforces this check.
pub(super) fn extension_config_is_ca(attributes: &Attributes, vendor_id: &str) -> bool {
    attributes
        .vendor_attributes
        .as_ref()
        .and_then(|vas| {
            vas.iter().find(|va| {
                va.vendor_identification == vendor_id
                    && va.attribute_name == VENDOR_ATTR_X509_EXTENSION
            })
        })
        .and_then(|va| {
            if let VendorAttributeValue::ByteString(ref b) = va.attribute_value {
                Some(String::from_utf8_lossy(b).to_uppercase())
            } else {
                None
            }
        })
        .is_some_and(|upper| upper.contains("CA:TRUE"))
}

/// Shared helper: build the critical `keyUsage` extension for PQC **signing** algorithms
/// (ML-DSA per RFC 9881 §5, SLH-DSA per RFC 9909 §6).
///
/// - End-entity: `digitalSignature` (critical)
/// - CA (`is_ca=true`): `digitalSignature | keyCertSign | cRLSign` (critical)
///
/// Called by [`rfc9881::apply_extensions`] and [`rfc9909::apply_extensions`].
#[cfg(feature = "non-fips")]
pub(super) fn pqc_signing_key_usage(is_ca: bool) -> KResult<openssl::x509::X509Extension> {
    let mut ku = KeyUsage::new();
    ku.critical().digital_signature();
    if is_ca {
        // RFC 5280 §4.2.1.3: keyCertSign required for CA certs with keyUsage present.
        ku.key_cert_sign().crl_sign();
    }
    Ok(ku.build()?)
}

/// RFC 9881 §5 / RFC 9909 §6 / RFC 9935 §5 — auto-add the RFC-mandated critical keyUsage
/// extension for fresh PQC key certifications.
///
/// Dispatches to the per-RFC submodule based on the algorithm family.
/// CSR-based and re-certification cases already carry extensions from the original object,
/// so this only fires when `subject_pqc_algorithm` returns `Some`.
#[cfg(feature = "non-fips")]
fn apply_pqc_key_usage(
    x509_builder: &mut openssl::x509::X509Builder,
    subject: &Subject,
    attributes: &Attributes,
    vendor_id: &str,
) -> KResult<()> {
    if let Some(algo) = subject_pqc_algorithm(subject) {
        let is_ca = extension_config_is_ca(attributes, vendor_id);
        match algo {
            CryptographicAlgorithm::MLDSA_44
            | CryptographicAlgorithm::MLDSA_65
            | CryptographicAlgorithm::MLDSA_87 => {
                rfc9881::apply_extensions(x509_builder, is_ca)?;
            }
            CryptographicAlgorithm::SLHDSA_SHA2_128s
            | CryptographicAlgorithm::SLHDSA_SHA2_128f
            | CryptographicAlgorithm::SLHDSA_SHA2_192s
            | CryptographicAlgorithm::SLHDSA_SHA2_192f
            | CryptographicAlgorithm::SLHDSA_SHA2_256s
            | CryptographicAlgorithm::SLHDSA_SHA2_256f
            | CryptographicAlgorithm::SLHDSA_SHAKE_128s
            | CryptographicAlgorithm::SLHDSA_SHAKE_128f
            | CryptographicAlgorithm::SLHDSA_SHAKE_192s
            | CryptographicAlgorithm::SLHDSA_SHAKE_192f
            | CryptographicAlgorithm::SLHDSA_SHAKE_256s
            | CryptographicAlgorithm::SLHDSA_SHAKE_256f => {
                rfc9909::apply_extensions(x509_builder, is_ca)?;
            }
            CryptographicAlgorithm::MLKEM_512
            | CryptographicAlgorithm::MLKEM_768
            | CryptographicAlgorithm::MLKEM_1024
            | CryptographicAlgorithm::X25519MLKEM768
            | CryptographicAlgorithm::X448MLKEM1024
            | CryptographicAlgorithm::ConfigurableKEM => {
                rfc9935::apply_extensions(x509_builder)?;
            }
            _ => {} // RSA, EC, EdDSA — no automatic PQC keyUsage
        }
    }
    Ok(())
}

/// RFC 5280 §4.2 — apply user-supplied X.509v3 extensions from the vendor attribute CNF.
///
/// Returns a tuple `(has_cdp, has_key_usage)`:
/// - `has_cdp`: whether the user-supplied config contains a `crlDistributionPoints` entry
/// - `has_key_usage`: whether the user-supplied config contains a `keyUsage` entry
fn apply_user_extensions(
    x509_builder: &mut openssl::x509::X509Builder,
    attributes: &mut Attributes,
    vendor_id: &str,
    issuer: &Issuer,
) -> KResult<(bool, bool)> {
    if let Some(extensions) = attributes.remove_x509_extension_file(vendor_id) {
        let extensions_as_str = String::from_utf8(extensions)?;
        debug!("OpenSSL Extensions: {}", extensions_as_str);
        let has_cdp = extensions_as_str.contains("crlDistributionPoints");
        let has_key_usage = extensions_as_str.contains("keyUsage");
        let context = x509_builder.x509v3_context(issuer.certificate(), None);
        x509_extensions::parse_v3_ca_from_str(&extensions_as_str, &context)?
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))?;
        Ok((has_cdp, has_key_usage))
    } else {
        Ok((false, false))
    }
}

/// RFC 9608 §2–§3 — delegate to [`rfc9608::apply_extensions`].
fn apply_no_rev_avail(
    x509_builder: &mut openssl::x509::X509Builder,
    issuer: &Issuer,
    attributes: &Attributes,
    vendor_id: &str,
    has_cdp: bool,
) -> KResult<()> {
    rfc9608::apply_extensions(x509_builder, issuer, attributes, vendor_id, has_cdp)
}

/// Select the correct `MessageDigest` for signing based on the issuer key type.
///
/// RSA and EC (ECDSA) require an explicit external digest (SHA-256).
/// `EdDSA` and PQC algorithms (`ML-DSA`, `SLH-DSA`) handle their digest internally
/// and must receive a null digest.
fn signing_digest(key: &openssl::pkey::PKeyRef<openssl::pkey::Private>) -> MessageDigest {
    match key.id() {
        Id::RSA | Id::EC => MessageDigest::sha256(),
        _ => MessageDigest::null(),
    }
}

fn create_subject_key_identifier_value(subject: &Subject) -> KResult<Asn1Integer> {
    let pk = subject.public_key()?;
    let spki_der = pk.public_key_to_der()?;
    let mut sha1 = Sha1::default();
    sha1.update(&spki_der);
    let mut serial_number_bytes = sha1.finish().to_vec();

    // Ensure the serial number is always positive by clearing the high bit of the first byte.
    // This prevents ASN.1 DER encoding from adding a leading 0x00 byte for negative numbers,
    // which would make the serial number 21 bytes instead of 20 bytes.
    // RFC 5280 Section 4.1.2.2 allows serial numbers up to 20 octets.
    *serial_number_bytes
        .get_mut(0)
        .ok_or_else(|| KmsError::ServerError("SHA1 digest returned empty bytes".to_owned()))? &=
        0x7F;

    let serial_number = openssl::asn1::Asn1Integer::from_bn(
        openssl::bn::BigNum::from_slice(&serial_number_bytes)?.as_ref(),
    )?;
    Ok(serial_number)
}

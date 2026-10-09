//! Per-endpoint certificate templates.
//!
//! A [`CertTemplate`] constrains what a CSR submitted through an automated enrollment
//! protocol (EST RFC 7030, SCEP RFC 8894) may obtain: key type and size, Extended Key
//! Usages, Subject / SAN patterns and validity. `certify()` itself forwards a CSR as-is,
//! so these checks MUST run before the `Certify` request is built.

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_attributes::Attributes;
use openssl::{
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::X509Req,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use x509_parser::{
    extensions::GeneralName,
    prelude::{FromDer, ParsedExtension, X509CertificationRequest},
};

use crate::{error::KmsError, result::KResult};

/// OID of the Microsoft User Principal Name `otherName` SAN type.
const OID_UPN: &str = "1.3.6.1.4.1.311.20.2.3";

/// Well-known EKU names and their dotted OIDs (RFC 5280 §4.2.1.12).
const EKU_NAMES: &[(&str, &str)] = &[
    ("anyExtendedKeyUsage", "2.5.29.37.0"),
    ("serverAuth", "1.3.6.1.5.5.7.3.1"),
    ("clientAuth", "1.3.6.1.5.5.7.3.2"),
    ("codeSigning", "1.3.6.1.5.5.7.3.3"),
    ("emailProtection", "1.3.6.1.5.5.7.3.4"),
    ("timeStamping", "1.3.6.1.5.5.7.3.8"),
    ("OCSPSigning", "1.3.6.1.5.5.7.3.9"),
    ("msSmartcardLogin", "1.3.6.1.4.1.311.20.2.2"),
];

/// Issuance policy applied to CSRs received through one enrollment endpoint.
///
/// Regular expressions are **anchored** (`^(?:pattern)$`) before use, so a pattern must
/// describe the full value.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CertTemplate {
    /// Template name (informational; the key under `[templates.<name>]` is authoritative).
    pub name: String,
    /// Minimum accepted RSA modulus size in bits (RFC 8017).
    pub min_rsa_key_bits: u32,
    /// Accepted EC curves (e.g. `prime256v1`, `secp384r1`); empty accepts any curve.
    pub allowed_ec_curves: Vec<String>,
    /// Accepted / injected Extended Key Usages, dotted OIDs or names such as `clientAuth`.
    /// When non-empty and the CSR requests none, these are injected in the certificate.
    pub allowed_ekus: Vec<String>,
    /// Upper bound on the certificate validity, in days.
    pub max_validity_days: u32,
    /// Validity used when the enrollment protocol carries no requested validity.
    pub default_validity_days: u32,
    /// Regular expression every subject `CN` must match.
    pub subject_cn_regex: Option<String>,
    /// Regular expression every DNS SAN must match.
    pub san_dns_regex: Option<String>,
    /// Regular expression every rfc822Name SAN must match.
    pub san_email_regex: Option<String>,
    /// Regular expression every Microsoft UPN `otherName` SAN must match (RFC 5280 does
    /// not define the UPN; it is used by Windows MDM client certificates).
    pub san_upn_regex: Option<String>,
}

impl Default for CertTemplate {
    fn default() -> Self {
        Self {
            name: String::new(),
            min_rsa_key_bits: 2048,
            allowed_ec_curves: Vec::new(),
            allowed_ekus: Vec::new(),
            max_validity_days: 365,
            default_validity_days: 90,
            subject_cn_regex: None,
            san_dns_regex: None,
            san_email_regex: None,
            san_upn_regex: None,
        }
    }
}

fn invalid(msg: impl Into<String>) -> KmsError {
    KmsError::InvalidRequest(msg.into())
}

fn anchored(pattern: &str) -> KResult<Regex> {
    Regex::new(&format!("^(?:{pattern})$"))
        .map_err(|e| KmsError::InvalidRequest(format!("invalid template regex '{pattern}': {e}")))
}

/// Resolve an EKU name or dotted OID to a dotted OID.
fn eku_to_oid(name: &str) -> KResult<String> {
    if let Some((_, oid)) = EKU_NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name.trim()))
    {
        return Ok((*oid).to_owned());
    }
    let trimmed = name.trim();
    let is_dotted = trimmed.contains('.')
        && trimmed
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if is_dotted {
        Ok(trimmed.to_owned())
    } else {
        Err(invalid(format!("unknown extended key usage '{name}'")))
    }
}

/// Canonical lower-case key for an EC curve name, folding the common aliases.
fn canonical_curve(name: &str) -> String {
    match name.trim().to_ascii_lowercase().as_str() {
        "prime256v1" | "secp256r1" | "p-256" | "p256" => "prime256v1".to_owned(),
        "secp384r1" | "p-384" | "p384" => "secp384r1".to_owned(),
        "secp521r1" | "p-521" | "p521" => "secp521r1".to_owned(),
        other => other.to_owned(),
    }
}

/// Return the `basicConstraints` `cA` flag requested by a DER PKCS#10 CSR, or `None` when
/// the CSR carries no `basicConstraints` extension request.
pub(crate) fn csr_basic_constraints(csr_der: &[u8]) -> KResult<Option<bool>> {
    let (_, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("invalid CSR: {e}")))?;
    Ok(csr.requested_extensions().and_then(|mut exts| {
        exts.find_map(|ext| match ext {
            ParsedExtension::BasicConstraints(bc) => Some(bc.ca),
            _ => None,
        })
    }))
}

/// Result of parsing the interesting extension requests of a CSR.
#[derive(Default)]
struct CsrRequests {
    ekus: Option<Vec<String>>,
    dns: Vec<String>,
    emails: Vec<String>,
    upns: Vec<String>,
    /// SAN entries of a type for which the template has no pattern (URI, IP, …).
    other_san_types: Vec<&'static str>,
}

/// Human-readable name of a SAN entry type, for error messages.
const fn san_kind(name: &GeneralName<'_>) -> &'static str {
    match name {
        GeneralName::OtherName(..) => "otherName",
        GeneralName::URI(_) => "uniformResourceIdentifier",
        GeneralName::IPAddress(_) => "iPAddress",
        GeneralName::DirectoryName(_) => "directoryName",
        _ => "other",
    }
}

fn upn_from_other_name(value: &[u8]) -> Option<String> {
    use x509_parser::der_parser::parse_der;
    let (_, obj) = parse_der(value).ok()?;
    if let Ok(s) = obj.as_str() {
        return Some(s.to_owned());
    }
    // [0] EXPLICIT wrapper around the UTF8String
    let (_, inner) = parse_der(obj.as_slice().ok()?).ok()?;
    inner.as_str().ok().map(str::to_owned)
}

fn parse_csr_requests(csr_der: &[u8]) -> KResult<CsrRequests> {
    let (_, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("invalid CSR: {e}")))?;
    let mut out = CsrRequests::default();
    let Some(exts) = csr.requested_extensions() else {
        return Ok(out);
    };
    for ext in exts {
        match ext {
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let list = out.ekus.get_or_insert_with(Vec::new);
                for (set, name) in [
                    (eku.any, "anyExtendedKeyUsage"),
                    (eku.server_auth, "serverAuth"),
                    (eku.client_auth, "clientAuth"),
                    (eku.code_signing, "codeSigning"),
                    (eku.email_protection, "emailProtection"),
                    (eku.time_stamping, "timeStamping"),
                    (eku.ocsp_signing, "OCSPSigning"),
                ] {
                    if set {
                        list.push(eku_to_oid(name)?);
                    }
                }
                list.extend(
                    eku.other
                        .iter()
                        .map(x509_parser::asn1_rs::Oid::to_id_string),
                );
            }
            ParsedExtension::SubjectAlternativeName(san) => {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(d) => out.dns.push((*d).to_owned()),
                        GeneralName::RFC822Name(e) => out.emails.push((*e).to_owned()),
                        GeneralName::OtherName(oid, value) if oid.to_id_string() == OID_UPN => {
                            out.upns.push(
                                upn_from_other_name(value)
                                    .ok_or_else(|| invalid("malformed UPN SAN in CSR"))?,
                            );
                        }
                        other => out.other_san_types.push(san_kind(other)),
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

impl CertTemplate {
    /// Check that the template itself is well formed (regular expressions compile, EKUs
    /// resolve, validity bounds are consistent). Called when the configuration is loaded.
    pub(crate) fn validate(&self) -> KResult<()> {
        for p in [
            &self.subject_cn_regex,
            &self.san_dns_regex,
            &self.san_email_regex,
            &self.san_upn_regex,
        ]
        .into_iter()
        .flatten()
        {
            anchored(p)?;
        }
        for e in &self.allowed_ekus {
            eku_to_oid(e)?;
        }
        if self.max_validity_days == 0 {
            return Err(invalid(format!(
                "template '{}': max_validity_days must be > 0",
                self.name
            )));
        }
        Ok(())
    }

    /// Validity (days) to issue: the requested value or the template default, clamped to
    /// `max_validity_days`.
    #[must_use]
    pub(crate) fn effective_validity_days(&self, requested: Option<u32>) -> u32 {
        requested
            .unwrap_or(self.default_validity_days)
            .min(self.max_validity_days)
    }

    const fn any_san_regex(&self) -> bool {
        self.san_dns_regex.is_some()
            || self.san_email_regex.is_some()
            || self.san_upn_regex.is_some()
    }

    /// Validate `csr` against this template. Returns `KmsError::InvalidRequest` (HTTP 422)
    /// describing the first violation.
    pub(crate) fn validate_csr(&self, csr: &X509Req) -> KResult<()> {
        // Proof of possession of the private key (RFC 2986 §3, RFC 7030 §3.4).
        let public_key = csr
            .public_key()
            .map_err(|e| invalid(format!("CSR has no usable public key: {e}")))?;
        if !csr
            .verify(&public_key)
            .map_err(|e| invalid(format!("CSR signature check failed: {e}")))?
        {
            return Err(invalid(
                "CSR signature is invalid (proof of possession failed)",
            ));
        }
        self.check_public_key(&public_key)?;

        let csr_der = csr.to_der()?;
        if csr_basic_constraints(&csr_der)? == Some(true) {
            return Err(invalid("CSR must not request basicConstraints CA:TRUE"));
        }
        let requests = parse_csr_requests(&csr_der)?;
        self.check_ekus(requests.ekus.as_deref())?;
        self.check_subject(csr)?;
        self.check_sans(&requests)?;
        Ok(())
    }

    fn check_public_key(&self, public_key: &PKey<Public>) -> KResult<()> {
        match public_key.id() {
            Id::RSA => {
                let bits = public_key.bits();
                if bits < self.min_rsa_key_bits {
                    return Err(invalid(format!(
                        "RSA key size {bits} is below the template minimum of {}",
                        self.min_rsa_key_bits
                    )));
                }
            }
            Id::EC => {
                let ec = public_key.ec_key()?;
                let curve = ec
                    .group()
                    .curve_name()
                    .ok_or_else(|| invalid("EC key uses explicit (unnamed) curve parameters"))?;
                if !self.allowed_ec_curves.is_empty() {
                    let name = curve.short_name()?;
                    let wanted = canonical_curve(name);
                    if !self
                        .allowed_ec_curves
                        .iter()
                        .any(|c| canonical_curve(c) == wanted)
                    {
                        return Err(invalid(format!(
                            "EC curve '{name}' is not allowed by the template"
                        )));
                    }
                }
            }
            other => {
                return Err(invalid(format!(
                    "public key type {other:?} is not accepted for enrollment (RSA or EC only)"
                )));
            }
        }
        Ok(())
    }

    fn check_ekus(&self, requested: Option<&[String]>) -> KResult<()> {
        let Some(requested) = requested else {
            return Ok(());
        };
        if self.allowed_ekus.is_empty() {
            return Ok(());
        }
        let allowed = self
            .allowed_ekus
            .iter()
            .map(|e| eku_to_oid(e))
            .collect::<KResult<Vec<_>>>()?;
        for oid in requested {
            if !allowed.contains(oid) {
                return Err(invalid(format!(
                    "extended key usage {oid} is not allowed by the template"
                )));
            }
        }
        Ok(())
    }

    fn check_subject(&self, csr: &X509Req) -> KResult<()> {
        let Some(pattern) = &self.subject_cn_regex else {
            return Ok(());
        };
        let re = anchored(pattern)?;
        let mut seen = false;
        for entry in csr.subject_name().entries_by_nid(Nid::COMMONNAME) {
            seen = true;
            let cn = entry
                .data()
                .to_string()
                .map_err(|e| invalid(format!("invalid subject CN encoding: {e}")))?;
            if !re.is_match(&cn) {
                return Err(invalid(format!(
                    "subject CN '{cn}' does not match the template pattern"
                )));
            }
        }
        if !seen {
            return Err(invalid("subject has no CN but the template requires one"));
        }
        Ok(())
    }

    fn check_sans(&self, requests: &CsrRequests) -> KResult<()> {
        for (patt, values, what) in [
            (&self.san_dns_regex, &requests.dns, "DNS"),
            (&self.san_email_regex, &requests.emails, "email"),
            (&self.san_upn_regex, &requests.upns, "UPN"),
        ] {
            if let Some(p) = patt {
                let re = anchored(p)?;
                if let Some(bad) = values.iter().find(|v| !re.is_match(v)) {
                    return Err(invalid(format!(
                        "{what} SAN '{bad}' does not match the template pattern"
                    )));
                }
            }
        }
        // Whitelist semantics once SAN patterns are configured: SAN types without a pattern
        // (URI, IP, …) cannot be vetted and are refused.
        if self.any_san_regex() {
            if let Some(kind) = requests.other_san_types.first() {
                return Err(invalid(format!(
                    "SAN type {kind} is not allowed when the template restricts SAN values"
                )));
            }
            for (patt, values, what) in [
                (&self.san_dns_regex, &requests.dns, "DNS"),
                (&self.san_email_regex, &requests.emails, "email"),
                (&self.san_upn_regex, &requests.upns, "UPN"),
            ] {
                if patt.is_none() && !values.is_empty() {
                    return Err(invalid(format!(
                        "{what} SAN is not allowed by the template"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validate `csr` and write the template-driven issuance controls into the `Certify`
    /// attributes: the clamped validity and, when the CSR requests no EKU, the template EKUs.
    ///
    /// `requested_validity_days` is the validity asked for by the protocol, if any.
    pub(crate) fn apply(
        &self,
        csr: &X509Req,
        vendor_id: &str,
        requested_validity_days: Option<u32>,
        attributes: &mut Attributes,
    ) -> KResult<()> {
        self.validate_csr(csr)?;
        let days = i32::try_from(self.effective_validity_days(requested_validity_days))
            .map_err(|e| invalid(format!("validity out of range: {e}")))?;
        attributes.set_requested_validity_days(vendor_id, days);

        if !self.allowed_ekus.is_empty() {
            let csr_has_eku = parse_csr_requests(&csr.to_der()?)?.ekus.is_some();
            if !csr_has_eku {
                let oids = self
                    .allowed_ekus
                    .iter()
                    .map(|e| eku_to_oid(e))
                    .collect::<KResult<Vec<_>>>()?;
                attributes.set_x509_extension_file(
                    vendor_id,
                    format!("[v3_ca]\nextendedKeyUsage={}\n", oids.join(",")).into_bytes(),
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use openssl::{
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        pkey::Private,
        rsa::Rsa,
        stack::Stack,
        x509::{X509NameBuilder, X509Req, extension::ExtendedKeyUsage},
    };

    use super::*;

    fn csr_with(
        key: &PKey<Private>,
        cn: &str,
        eku: Option<ExtendedKeyUsage>,
        dns: Option<&str>,
    ) -> X509Req {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        let mut exts = Stack::new().unwrap();
        if let Some(e) = eku {
            exts.push(e.build().unwrap()).unwrap();
        }
        if let Some(d) = dns {
            let ctx = b.x509v3_context(None);
            exts.push(
                openssl::x509::extension::SubjectAlternativeName::new()
                    .dns(d)
                    .build(&ctx)
                    .unwrap(),
            )
            .unwrap();
        }
        if !exts.is_empty() {
            b.add_extensions(&exts).unwrap();
        }
        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn rsa(bits: u32) -> PKey<Private> {
        PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap()
    }

    fn client_auth() -> ExtendedKeyUsage {
        let mut e = ExtendedKeyUsage::new();
        e.client_auth();
        e
    }

    fn iot_template() -> CertTemplate {
        CertTemplate {
            name: "iot".to_owned(),
            allowed_ekus: vec!["clientAuth".to_owned()],
            allowed_ec_curves: vec!["prime256v1".to_owned()],
            subject_cn_regex: Some(r"[a-z0-9-]+\.iot\.example".to_owned()),
            san_dns_regex: Some(r"[a-z0-9-]+\.iot\.example".to_owned()),
            ..CertTemplate::default()
        }
    }

    #[test]
    fn accepts_conformant_csr() {
        let t = iot_template();
        let csr = csr_with(
            &rsa(2048),
            "dev1.iot.example",
            Some(client_auth()),
            Some("dev1.iot.example"),
        );
        t.validate_csr(&csr).unwrap();
    }

    #[test]
    fn rejects_weak_rsa_key() {
        let t = iot_template();
        let csr = csr_with(&rsa(1024), "dev1.iot.example", None, None);
        let err = t.validate_csr(&csr).unwrap_err().to_string();
        assert!(err.contains("below the template minimum"), "{err}");
    }

    #[test]
    fn rejects_disallowed_eku() {
        let t = iot_template();
        let mut e = ExtendedKeyUsage::new();
        e.server_auth();
        let csr = csr_with(&rsa(2048), "dev1.iot.example", Some(e), None);
        let err = t.validate_csr(&csr).unwrap_err().to_string();
        assert!(err.contains("not allowed by the template"), "{err}");
    }

    #[test]
    fn cn_regex_is_anchored() {
        let t = iot_template();
        for cn in ["evil.iot.example.attacker.net", "x"] {
            let csr = csr_with(&rsa(2048), cn, None, None);
            assert!(t.validate_csr(&csr).is_err(), "{cn} must be rejected");
        }
    }

    #[test]
    fn rejects_san_outside_pattern() {
        let t = iot_template();
        let csr = csr_with(
            &rsa(2048),
            "dev1.iot.example",
            None,
            Some("other.example.com"),
        );
        let err = t.validate_csr(&csr).unwrap_err().to_string();
        assert!(err.contains("DNS SAN"), "{err}");
    }

    #[test]
    fn rejects_disallowed_ec_curve() {
        let t = iot_template();
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let csr = csr_with(&key, "dev1.iot.example", None, None);
        assert!(t.validate_csr(&csr).is_err());
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        t.validate_csr(&csr_with(&key, "dev1.iot.example", None, None))
            .unwrap();
    }

    #[test]
    fn rejects_ca_basic_constraints() {
        let t = CertTemplate::default();
        let key = rsa(2048);
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "ca").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        let mut exts = Stack::new().unwrap();
        exts.push(
            openssl::x509::extension::BasicConstraints::new()
                .ca()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.add_extensions(&exts).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let err = t.validate_csr(&b.build()).unwrap_err().to_string();
        assert!(err.contains("CA:TRUE"), "{err}");
    }

    #[test]
    fn validity_is_clamped_to_maximum() {
        let t = CertTemplate {
            max_validity_days: 30,
            default_validity_days: 10,
            ..CertTemplate::default()
        };
        assert_eq!(t.effective_validity_days(None), 10);
        assert_eq!(t.effective_validity_days(Some(20)), 20);
        assert_eq!(t.effective_validity_days(Some(9999)), 30);
    }

    #[test]
    fn invalid_template_is_detected() {
        let t = CertTemplate {
            subject_cn_regex: Some("(".to_owned()),
            ..CertTemplate::default()
        };
        assert!(t.validate().is_err());
        let t = CertTemplate {
            allowed_ekus: vec!["notAnEku".to_owned()],
            ..CertTemplate::default()
        };
        assert!(t.validate().is_err());
    }
}

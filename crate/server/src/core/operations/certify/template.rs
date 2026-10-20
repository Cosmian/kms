//! Per-endpoint certificate templates.
//!
//! A [`CertTemplate`] constrains what a CSR submitted through an automated enrollment
//! protocol (EST RFC 7030, SCEP RFC 8894) may obtain: key type and size, Extended Key
//! Usages, Subject / SAN patterns and validity. `certify()` itself forwards a CSR as-is,
//! so these checks MUST run before the `Certify` request is built.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_attributes::Attributes,
    cosmian_kms_crypto::openssl::oid::{nid_of, oid_string},
};
use openssl::{
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::X509Req,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use x509_parser::{
    cri_attributes::ParsedCriAttribute,
    extensions::GeneralName,
    prelude::{FromDer, ParsedExtension, X509CertificationRequest},
};

use crate::{error::KmsError, result::KResult};

/// Well-known EKU names and their OIDs (RFC 5280 §4.2.1.12), as `OpenSSL` registers them.
const EKU_NAMES: &[(&str, Nid)] = &[
    ("anyExtendedKeyUsage", Nid::ANYEXTENDEDKEYUSAGE),
    ("serverAuth", Nid::SERVER_AUTH),
    ("clientAuth", Nid::CLIENT_AUTH),
    ("codeSigning", Nid::CODE_SIGN),
    ("emailProtection", Nid::EMAIL_PROTECT),
    ("timeStamping", Nid::TIME_STAMP),
    ("OCSPSigning", Nid::OCSP_SIGN),
    ("msSmartcardLogin", Nid::MS_SMARTCARD_LOGIN),
];

/// Extensions an enrollee may request: keyUsage, subjectAltName, basicConstraints (CA:FALSE
/// only, checked separately) and extendedKeyUsage. `Certify` copies every CSR extension into
/// the certificate, so anything else (nameConstraints, certificatePolicies,
/// crlDistributionPoints, ...) would let the enrollee write policy into a certificate signed by
/// the CA and is refused.
const ALLOWED_CSR_EXTENSIONS: &[Nid] = &[
    Nid::KEY_USAGE,
    Nid::SUBJECT_ALT_NAME,
    Nid::BASIC_CONSTRAINTS,
    Nid::EXT_KEY_USAGE,
];

/// Issuance policy applied to CSRs received through one enrollment endpoint.
///
/// Regular expressions are **anchored** (`^(?:pattern)$`) before use, so a pattern must
/// describe the full value.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CertTemplate {
    /// Template name (informational; the key under `[templates.<name>]` is authoritative).
    pub name: String,
    /// Minimum accepted RSA modulus size in bits (RFC 8017).
    pub min_rsa_key_bits: u32,
    /// Accepted EC curves (e.g. `prime256v1`, `secp384r1`). Must not be empty; the default is
    /// the NIST P-256/P-384/P-521 set.
    pub allowed_ec_curves: Vec<String>,
    /// Accepted / injected Extended Key Usages, dotted OIDs or names such as `clientAuth`.
    /// Must not be empty; the default is `clientAuth`. When the CSR requests none, these are
    /// injected in the certificate.
    pub allowed_ekus: Vec<String>,
    /// Upper bound on the certificate validity, in days.
    pub max_validity_days: u32,
    /// Validity used when the enrollment protocol carries no requested validity.
    pub default_validity_days: u32,
    /// Regular expression every subject `CN` must match.
    pub subject_cn_regex: Option<String>,
    /// Regular expression every DNS SAN must match. SANs are default-deny: without this
    /// pattern, a CSR carrying a DNS SAN is refused (see `allow_any_identity`).
    pub san_dns_regex: Option<String>,
    /// Regular expression every rfc822Name SAN must match; without it, email SANs are refused.
    pub san_email_regex: Option<String>,
    /// Regular expression every Microsoft UPN `otherName` SAN must match (RFC 5280 does
    /// not define the UPN; it is used by Windows MDM client certificates); without it, UPN SANs
    /// are refused.
    pub san_upn_regex: Option<String>,
    /// Accept any subject CN. A template must either set `subject_cn_regex` or opt in
    /// explicitly with `allow_any_identity = true`: the enrollment secret authenticates the
    /// device class, not the name it asks for. When `true`, the `serialNumber`, `UID` and
    /// `emailAddress` subject attributes (which relying parties may use to identify a user) are
    /// accepted too, and, if no `san_*_regex` is set, any SAN (including iPAddress and URI,
    /// which have no pattern and are otherwise always refused).
    pub allow_any_identity: bool,
}

impl Default for CertTemplate {
    fn default() -> Self {
        Self {
            name: String::new(),
            min_rsa_key_bits: 2048,
            allowed_ec_curves: ["prime256v1", "secp384r1", "secp521r1"]
                .map(str::to_owned)
                .to_vec(),
            allowed_ekus: vec!["clientAuth".to_owned()],
            max_validity_days: 365,
            default_validity_days: 90,
            subject_cn_regex: None,
            san_dns_regex: None,
            san_email_regex: None,
            san_upn_regex: None,
            allow_any_identity: false,
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
    if let Some((_, nid)) = EKU_NAMES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name.trim()))
    {
        return Ok(oid_string(*nid)?);
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
///
/// # Errors
///
/// Refuses an unparsable CSR, and a CSR whose extensions OpenSSL would copy from an attribute
/// this parser cannot read: `X509_REQ_get_extensions` (used by Certify) also reads the
/// Microsoft `msExtReq` attribute and an `extensionRequest` x509-parser could not decode.
pub(crate) fn csr_basic_constraints(csr_der: &[u8]) -> KResult<Option<bool>> {
    let (_, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("invalid CSR: {e}")))?;
    for attr in csr.certification_request_info.iter_attributes() {
        let oid = attr.oid.to_id_string();
        if matches!(nid_of(&oid), Nid::MS_EXT_REQ | Nid::EXT_REQ)
            && !matches!(
                attr.parsed_attribute(),
                ParsedCriAttribute::ExtensionRequest(_)
            )
        {
            return Err(invalid(format!(
                "CSR attribute {oid} requests extensions in a form that cannot be validated"
            )));
        }
    }
    Ok(csr.requested_extensions().and_then(|mut exts| {
        exts.find_map(|ext| match ext {
            ParsedExtension::BasicConstraints(bc) => Some(bc.ca),
            _ => None,
        })
    }))
}

/// Result of parsing the interesting extension requests of a CSR.
#[derive(Default, Debug)]
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
                        GeneralName::OtherName(oid, value)
                            if nid_of(&oid.to_id_string()) == Nid::MS_UPN =>
                        {
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

/// Refuse every CSR-requested extension that is not in [`ALLOWED_CSR_EXTENSIONS`], any
/// keyUsage that lets the certificate sign certificates or CRLs, and any duplicated
/// extensionRequest attribute or extension OID. `Certify` appends every extension while the
/// checks of this module read the first match, so a duplicate (e.g. `CA:FALSE` followed by
/// `CA:TRUE`) would evade them (RFC 5280 §4.2 forbids duplicate extensions anyway).
fn check_requested_extensions(csr_der: &[u8]) -> KResult<()> {
    let (_, csr) = X509CertificationRequest::from_der(csr_der)
        .map_err(|e| invalid(format!("invalid CSR: {e}")))?;
    let mut extension_requests = 0_usize;
    let mut seen = std::collections::HashSet::new();
    for attr in csr.certification_request_info.iter_attributes() {
        let ParsedCriAttribute::ExtensionRequest(requested) = attr.parsed_attribute() else {
            // OpenSSL (`X509_REQ_get_extensions`, used by Certify) copies the extensions of
            // the Microsoft `msExtReq` attribute too, and of an `extensionRequest` this
            // parser could not decode; neither can be vetted here, so refuse them.
            let oid = attr.oid.to_id_string();
            if matches!(nid_of(&oid), Nid::MS_EXT_REQ | Nid::EXT_REQ) {
                return Err(invalid(format!(
                    "CSR attribute {oid} requests extensions in a form that cannot be validated"
                )));
            }
            continue;
        };
        extension_requests += 1;
        if extension_requests > 1 {
            return Err(invalid(
                "CSR carries more than one extensionRequest attribute",
            ));
        }
        for ext in &requested.extensions {
            let oid = ext.oid.to_id_string();
            if !ALLOWED_CSR_EXTENSIONS.contains(&nid_of(&oid)) {
                return Err(invalid(format!(
                    "CSR extension {oid} is not allowed for enrollment"
                )));
            }
            if !seen.insert(oid.clone()) {
                return Err(invalid(format!("CSR requests extension {oid} twice")));
            }
            if let ParsedExtension::ParseError { .. } = ext.parsed_extension() {
                return Err(invalid(format!("CSR extension {oid} is not valid DER")));
            }
            if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                if ku.key_cert_sign() || ku.crl_sign() {
                    return Err(invalid(
                        "CSR keyUsage must not include keyCertSign or cRLSign",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// `certificatePolicies` OID (Cosmian arc) stamped on every certificate issued through EST or
/// SCEP. It marks the certificate as a device identity: `user_from_client_certificate` refuses
/// to turn such a certificate into a KMS user, whatever its CN, so a device cannot enroll the
/// name of an existing user and then authenticate to the KMS API with it.
pub(crate) const ENROLLED_CERTIFICATE_POLICY_OID: &str = "1.3.6.1.4.1.16376.9.2.1";

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
            // Compile the raw pattern too: wrapped only, `a)|(.*` would compile and match anything.
            Regex::new(p).map_err(|e| invalid(format!("invalid template regex '{p}': {e}")))?;
            anchored(p)?;
        }
        for e in &self.allowed_ekus {
            eku_to_oid(e)?;
        }
        if self.allowed_ekus.is_empty() || self.allowed_ec_curves.is_empty() {
            return Err(invalid(format!(
                "template '{}': allowed_ekus and allowed_ec_curves must not be empty",
                self.name
            )));
        }
        if self.min_rsa_key_bits < 2048 {
            return Err(invalid(format!(
                "template '{}': min_rsa_key_bits must be >= 2048 (SP 800-131A)",
                self.name
            )));
        }
        if self.default_validity_days == 0
            || self.default_validity_days > self.max_validity_days
            || i32::try_from(self.max_validity_days).is_err()
        {
            return Err(invalid(format!(
                "template '{}': require 0 < default_validity_days <= max_validity_days <= {}",
                self.name,
                i32::MAX
            )));
        }
        if self.subject_cn_regex.is_none() && !self.allow_any_identity {
            return Err(invalid(format!(
                "template '{}': set subject_cn_regex, or allow_any_identity = true to accept any \
                 subject name",
                self.name
            )));
        }
        Ok(())
    }

    const fn any_san_regex(&self) -> bool {
        self.san_dns_regex.is_some()
            || self.san_email_regex.is_some()
            || self.san_upn_regex.is_some()
    }

    /// Validate `csr` against this template. Returns `KmsError::InvalidRequest` (HTTP 422)
    /// describing the first violation, or the requests parsed from the CSR.
    fn validate_csr(&self, csr: &X509Req) -> KResult<CsrRequests> {
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
        check_requested_extensions(&csr_der)?;
        let requests = parse_csr_requests(&csr_der)?;
        self.check_ekus(requests.ekus.as_deref())?;
        self.check_subject(csr)?;
        self.check_sans(&requests)?;
        Ok(requests)
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
        if !self.allow_any_identity {
            // Attributes that relying parties map to a person or an account are not a device
            // identity: refuse them unless the template opts in.
            for nid in [Nid::SERIALNUMBER, Nid::USERID, Nid::PKCS9_EMAILADDRESS] {
                if csr.subject_name().entries_by_nid(nid).next().is_some() {
                    return Err(invalid(format!(
                        "subject attribute {} is not allowed by the template",
                        nid.short_name()?
                    )));
                }
            }
        }
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

    /// SANs are default-deny: a SAN type is accepted only when the template has a pattern for
    /// it, or when the template sets `allow_any_identity = true` and no `san_*_regex` at all.
    /// iPAddress, URI and other SAN types have no pattern, so only that opt-in accepts them.
    fn check_sans(&self, requests: &CsrRequests) -> KResult<()> {
        let any_san = self.allow_any_identity && !self.any_san_regex();
        for (patt, values, what, key) in [
            (&self.san_dns_regex, &requests.dns, "DNS", "san_dns_regex"),
            (
                &self.san_email_regex,
                &requests.emails,
                "email",
                "san_email_regex",
            ),
            (&self.san_upn_regex, &requests.upns, "UPN", "san_upn_regex"),
        ] {
            if let Some(p) = patt {
                let re = anchored(p)?;
                if let Some(bad) = values.iter().find(|v| !re.is_match(v)) {
                    return Err(invalid(format!(
                        "{what} SAN '{bad}' does not match the template pattern"
                    )));
                }
            } else if !any_san && !values.is_empty() {
                return Err(invalid(format!(
                    "{what} SAN is not allowed by the template (no {key})"
                )));
            }
        }
        if !any_san {
            if let Some(kind) = requests.other_san_types.first() {
                return Err(invalid(format!(
                    "SAN type {kind} is not allowed by the template (requires allow_any_identity \
                     = true and no san_*_regex)"
                )));
            }
        }
        Ok(())
    }

    /// Validate `csr` and write the template-driven issuance controls into the `Certify`
    /// attributes: the template validity and, when the CSR requests no EKU, the template EKUs.
    pub(crate) fn apply(
        &self,
        csr: &X509Req,
        vendor_id: &str,
        attributes: &mut Attributes,
    ) -> KResult<()> {
        let requests = self.validate_csr(csr)?;
        let days = i32::try_from(self.default_validity_days.min(self.max_validity_days))
            .map_err(|e| invalid(format!("validity out of range: {e}")))?;
        attributes.set_requested_validity_days(vendor_id, days);

        // Every enrolled certificate carries the marker policy, so that the KMS can refuse to
        // map it to a KMS user (see `user_from_client_certificate`). A CSR cannot request
        // certificatePolicies (`ALLOWED_CSR_EXTENSIONS`), so only the server sets it.
        let mut extensions =
            format!("[v3_ca]\ncertificatePolicies={ENROLLED_CERTIFICATE_POLICY_OID}\n");
        if requests.ekus.is_none() {
            let oids = self
                .allowed_ekus
                .iter()
                .map(|e| eku_to_oid(e))
                .collect::<KResult<Vec<_>>>()?;
            extensions = format!("{extensions}extendedKeyUsage={}\n", oids.join(","));
        }
        attributes.set_x509_extension_file(vendor_id, extensions.into_bytes());
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

    /// FIPS OpenSSL refuses to sign with a 1024-bit RSA key, so the weak CSR cannot be built there.
    #[cfg(feature = "non-fips")]
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
        assert!(t.validate_csr(&csr).err().is_some());
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
    fn raw_pattern_must_compile_on_its_own() {
        // `^(?:[a-z]+)|(.*)$` compiles and matches anything once wrapped.
        let t = CertTemplate {
            subject_cn_regex: Some(r"[a-z]+)|(.*".to_owned()),
            ..CertTemplate::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn unknown_keys_are_rejected_when_parsing_a_template() {
        toml::from_str::<CertTemplate>("max_validity_days = 30\n").unwrap();
        // a typo must not silently fall back to the permissive default
        let err = toml::from_str::<CertTemplate>("san_dns_regexp = \"x\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("san_dns_regexp"), "{err}");
    }

    #[test]
    fn weak_or_inconsistent_limits_are_detected() {
        let open = CertTemplate {
            allow_any_identity: true,
            ..CertTemplate::default()
        };
        for t in [
            CertTemplate {
                min_rsa_key_bits: 1024,
                ..open.clone()
            },
            CertTemplate {
                default_validity_days: 0,
                ..open.clone()
            },
            CertTemplate {
                default_validity_days: 400,
                max_validity_days: 365,
                ..open.clone()
            },
        ] {
            assert!(t.validate().is_err());
        }
        open.validate().unwrap();
    }

    /// A template must say which names it accepts: a CN pattern, or an explicit opt-in.
    #[test]
    fn template_without_cn_pattern_requires_explicit_opt_in() {
        assert!(CertTemplate::default().validate().is_err());
        CertTemplate {
            subject_cn_regex: Some("[a-z]+".to_owned()),
            ..CertTemplate::default()
        }
        .validate()
        .unwrap();
    }

    /// `serialNumber`, `UID` and `emailAddress` subject attributes are refused unless the
    /// template accepts any identity.
    #[test]
    fn person_identifying_subject_attributes_are_refused_by_default() {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let csr_with_attribute = |attribute: &str| {
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "dev1").unwrap();
            name.append_entry_by_text(attribute, "someone").unwrap();
            let mut b = X509Req::builder().unwrap();
            b.set_version(0).unwrap();
            b.set_pubkey(&key).unwrap();
            b.set_subject_name(&name.build()).unwrap();
            b.sign(&key, MessageDigest::sha256()).unwrap();
            b.build()
        };
        let strict = CertTemplate {
            subject_cn_regex: Some("dev[0-9]".to_owned()),
            ..CertTemplate::default()
        };
        let open = CertTemplate {
            allow_any_identity: true,
            ..CertTemplate::default()
        };
        for attribute in ["serialNumber", "UID", "emailAddress"] {
            let csr = csr_with_attribute(attribute);
            assert!(strict.validate_csr(&csr).is_err(), "{attribute}");
            open.validate_csr(&csr).unwrap();
        }
        // organisation attributes stay accepted
        strict.validate_csr(&csr_with_attribute("O")).unwrap();
    }

    #[test]
    fn invalid_template_is_detected() {
        let t = CertTemplate {
            subject_cn_regex: Some("(".to_owned()),
            ..CertTemplate::default()
        };
        assert!(t.validate().is_err());
        // Otherwise valid (identity opted in), so only the EKU can make it fail.
        let valid = CertTemplate {
            allow_any_identity: true,
            ..CertTemplate::default()
        };
        valid.validate().unwrap();
        let t = CertTemplate {
            allowed_ekus: vec!["notAnEku".to_owned()],
            ..valid
        };
        assert!(t.validate().is_err());
    }

    fn csr_with_extension(key: &PKey<Private>, ext: openssl::x509::X509Extension) -> X509Req {
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "dev").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        let mut exts = Stack::new().unwrap();
        exts.push(ext).unwrap();
        b.add_extensions(&exts).unwrap();
        b.sign(key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    #[test]
    fn rejects_policy_bearing_csr_extensions() {
        let t = CertTemplate::default();
        let key = rsa(2048);
        // certificatePolicies cannot be built by `X509Extension::new_nid` without a config
        // database: encode `SEQUENCE { SEQUENCE { OID 1.2.3.4 } }` by hand.
        let policies = openssl::x509::X509Extension::new_from_der(
            openssl::asn1::Asn1Object::from_str("2.5.29.32")
                .unwrap()
                .as_ref(),
            false,
            openssl::asn1::Asn1OctetString::new_from_bytes(&[
                0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04,
            ])
            .unwrap()
            .as_ref(),
        )
        .unwrap();
        let err = t
            .validate_csr(&csr_with_extension(&key, policies))
            .unwrap_err()
            .to_string();
        assert!(err.contains("2.5.29.32"), "{err}");
    }

    #[test]
    fn rejects_certificate_signing_key_usage() {
        let t = CertTemplate::default();
        let key = rsa(2048);
        let ku = openssl::x509::extension::KeyUsage::new()
            .key_cert_sign()
            .build()
            .unwrap();
        let err = t
            .validate_csr(&csr_with_extension(&key, ku))
            .unwrap_err()
            .to_string();
        assert!(err.contains("keyCertSign"), "{err}");
        let ku = openssl::x509::extension::KeyUsage::new()
            .digital_signature()
            .build()
            .unwrap();
        t.validate_csr(&csr_with_extension(&key, ku)).unwrap();
    }

    #[test]
    fn default_template_refuses_unlisted_eku() {
        let t = CertTemplate::default();
        let mut e = ExtendedKeyUsage::new();
        e.other("1.3.6.1.5.5.7.3.9");
        assert!(
            t.validate_csr(&csr_with_extension(&rsa(2048), e.build().unwrap()))
                .err()
                .is_some()
        );
    }

    /// FIPS OpenSSL cannot generate a secp256k1 key.
    #[cfg(feature = "non-fips")]
    #[test]
    fn default_template_refuses_non_nist_curve() {
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        assert!(
            CertTemplate::default()
                .validate_csr(&csr_with(&key, "dev", None, None))
                .err()
                .is_some()
        );
    }

    #[test]
    fn empty_allowlists_are_detected() {
        for t in [
            CertTemplate {
                allowed_ekus: Vec::new(),
                ..CertTemplate::default()
            },
            CertTemplate {
                allowed_ec_curves: Vec::new(),
                ..CertTemplate::default()
            },
        ] {
            assert!(t.validate().is_err());
        }
    }

    #[test]
    fn rejects_duplicate_basic_constraints() {
        let key = rsa(2048);
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "dev").unwrap();
        let mut b = X509Req::builder().unwrap();
        b.set_version(0).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_subject_name(&name.build()).unwrap();
        let mut exts = Stack::new().unwrap();
        // CA:FALSE first (what a first-match parser sees), CA:TRUE second.
        exts.push(
            openssl::x509::extension::BasicConstraints::new()
                .build()
                .unwrap(),
        )
        .unwrap();
        exts.push(
            openssl::x509::extension::BasicConstraints::new()
                .ca()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.add_extensions(&exts).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let err = CertTemplate::default()
            .validate_csr(&b.build())
            .unwrap_err()
            .to_string();
        assert!(err.contains("twice"), "{err}");
    }

    /// Minimal DER TLV encoder (lengths < 65536) for hand-built CSRs.
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(u8::try_from(n).unwrap()),
            n => out.extend([
                0x82,
                u8::try_from(n >> 8).unwrap(),
                u8::try_from(n & 0xff).unwrap(),
            ]),
        }
        out.extend_from_slice(content);
        out
    }

    /// A validly signed CSR whose single attribute (OID `attr_oid`, content bytes of the OID)
    /// requests `basicConstraints` with the given raw extension value.
    fn csr_with_raw_basic_constraints(attr_oid: &[u8], bc_value: &[u8]) -> X509Req {
        let key = rsa(2048);
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "dev").unwrap();
        let ext = tlv(
            0x30,
            &[
                tlv(0x06, &[0x55, 0x1D, 0x13]),
                tlv(0x01, &[0xFF]),
                tlv(0x04, bc_value),
            ]
            .concat(),
        );
        let attr = tlv(
            0x30,
            &[tlv(0x06, attr_oid), tlv(0x31, &tlv(0x30, &ext))].concat(),
        );
        let cri = tlv(
            0x30,
            &[
                tlv(0x02, &[0]),
                name.build().to_der().unwrap(),
                key.public_key_to_der().unwrap(),
                tlv(0xA0, &attr),
            ]
            .concat(),
        );
        let sig_alg = tlv(
            0x30,
            &[
                tlv(
                    0x06,
                    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
                ),
                tlv(0x05, &[]),
            ]
            .concat(),
        );
        let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &key).unwrap();
        let signature = signer.sign_oneshot_to_vec(&cri).unwrap();
        let der = tlv(
            0x30,
            &[cri, sig_alg, tlv(0x03, &[&[0][..], &signature].concat())].concat(),
        );
        X509Req::from_der(&der).unwrap()
    }

    const PKCS9_EXT_REQ: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
    const MS_EXT_REQ: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0E];

    /// OpenSSL copies `msExtReq` extensions into the certificate (`X509_REQ_get_extensions`);
    /// the validator must not let a `CA:TRUE` request through that way.
    #[test]
    fn rejects_ms_ext_req_attribute() {
        // basicConstraints { cA TRUE }
        let csr = csr_with_raw_basic_constraints(&MS_EXT_REQ, &[0x30, 0x03, 0x01, 0x01, 0xFF]);
        // the premise of the attack: OpenSSL (used by Certify) does read this attribute
        assert_eq!(csr.extensions().unwrap().len(), 1);
        let err = CertTemplate::default()
            .validate_csr(&csr)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be validated"), "{err}");
    }

    /// Control: the hand-built CSR with a well-formed CA:TRUE is refused by the CA check, so
    /// the msExtReq test fails for the reason it claims rather than a malformed fixture.
    #[test]
    fn hand_built_csr_fixture_is_parsed() {
        let csr = csr_with_raw_basic_constraints(&PKCS9_EXT_REQ, &[0x30, 0x03, 0x01, 0x01, 0xFF]);
        let err = CertTemplate::default()
            .validate_csr(&csr)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("CA") || err.contains("basicConstraints"),
            "{err}"
        );
    }

    /// SPIRE `sign_intermediate` relies on `csr_basic_constraints` alone, so it must refuse an
    /// `msExtReq` attribute whatever it requests; the standard attribute is still read.
    #[test]
    fn csr_basic_constraints_refuses_ms_ext_req() {
        let ca_true: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];
        for bc in [ca_true, &[0x30, 0x00]] {
            let der = csr_with_raw_basic_constraints(&MS_EXT_REQ, bc)
                .to_der()
                .unwrap();
            assert_eq!(csr_basic_constraints(&der).ok(), None);
        }
        let der = csr_with_raw_basic_constraints(&PKCS9_EXT_REQ, ca_true)
            .to_der()
            .unwrap();
        assert_eq!(csr_basic_constraints(&der).ok(), Some(Some(true)));
    }

    /// A CSR with CN `dev` and one SAN extension built by `add`.
    fn csr_with_san(
        key: &PKey<Private>,
        add: impl FnOnce(
            &mut openssl::x509::extension::SubjectAlternativeName,
        ) -> &mut openssl::x509::extension::SubjectAlternativeName,
    ) -> X509Req {
        let b = X509Req::builder().unwrap();
        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        add(&mut san);
        let ext = san.build(&b.x509v3_context(None)).unwrap();
        csr_with_extension(key, ext)
    }

    /// SANs are default-deny: a template without `san_*_regex` (e.g. CN-only, as the wizard
    /// writes) refuses every SAN, without echoing the CSR value, and still accepts a CSR
    /// without SANs.
    #[test]
    fn cn_only_template_refuses_every_san() {
        let key = rsa(2048);
        let cn_only = CertTemplate {
            subject_cn_regex: Some("dev".to_owned()),
            ..CertTemplate::default()
        };
        cn_only.validate().unwrap();
        cn_only
            .validate_csr(&csr_with(&key, "dev", None, None))
            .unwrap();
        for (csr, expected) in [
            (
                csr_with_san(&key, |s| s.dns("victim.bank.example")),
                "DNS SAN",
            ),
            (
                csr_with_san(&key, |s| s.email("ceo@bank.example")),
                "email SAN",
            ),
            (csr_with_san(&key, |s| s.ip("10.0.0.1")), "iPAddress"),
            (
                csr_with_san(&key, |s| s.uri("spiffe://bank.example/admin")),
                "uniformResourceIdentifier",
            ),
        ] {
            let err = cn_only.validate_csr(&csr).unwrap_err().to_string();
            assert!(err.contains(expected), "{err}");
            assert!(
                !err.contains("bank.example") && !err.contains("10.0.0.1"),
                "{err}"
            );
        }
    }

    /// `allow_any_identity` alone accepts any SAN type; once a `san_*_regex` is set, SAN types
    /// without a pattern are refused again.
    #[test]
    fn any_identity_accepts_sans_only_without_san_patterns() {
        let key = rsa(2048);
        let open = CertTemplate {
            allow_any_identity: true,
            ..CertTemplate::default()
        };
        let dns_only = CertTemplate {
            san_dns_regex: Some("dev".to_owned()),
            ..open.clone()
        };
        open.validate_csr(&csr_with_san(&key, |s| s.dns("dev")))
            .unwrap();
        dns_only
            .validate_csr(&csr_with_san(&key, |s| s.dns("dev")))
            .unwrap();
        for csr in [
            csr_with_san(&key, |s| s.ip("10.0.0.1")),
            csr_with_san(&key, |s| s.uri("urn:dev")),
            csr_with_san(&key, |s| s.email("dev@example.com")),
        ] {
            open.validate_csr(&csr).unwrap();
            assert!(dns_only.validate_csr(&csr).err().is_some());
        }
    }
}

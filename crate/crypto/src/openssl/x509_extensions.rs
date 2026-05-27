use std::path::PathBuf;

use cosmian_logger::warn;
use ini::Ini;
use openssl::{
    asn1::{Asn1Object, Asn1OctetString},
    nid::Nid,
    x509::{
        X509Extension, X509v3Context,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};

use crate::{crypto_bail, error::CryptoError};

/// X509 Extension section parser.
/// The expected format of file for extensions be like:
///
/// ```cnf
/// [ v3_ca ]
/// basicConstraints=CA:TRUE,pathlen:0
/// keyUsage=keyCertSign,digitalSignature
/// extendedKeyUsage=emailProtection
/// crlDistributionPoints=URI:http://cse.example.com/crl.pem
/// ```
///
/// Warning: this naïve parser doesn't parse long form and internal links, such as:
///
/// ```cnf
/// [ v3_ca ]
/// basicConstraints=critical,@bs_section
///
/// [bs_section]
/// CA=true
/// pathlen=1
/// ```
pub fn parse_v3_ca_from_file(
    extension_file: &PathBuf,
    x509_context: &X509v3Context,
) -> Result<Vec<X509Extension>, CryptoError> {
    let conf = Ini::load_from_file(extension_file).map_err(|e| {
        CryptoError::NotSupported(format!(
            "cannot read x509 extension file: `{}`. Reason: {e}",
            extension_file.display()
        ))
    })?;
    parse_v3_ca(&conf, x509_context)
}

pub fn parse_v3_ca_from_str(
    conf: &str,
    x509_context: &X509v3Context,
) -> Result<Vec<X509Extension>, CryptoError> {
    let conf = Ini::load_from_str(conf).map_err(|e| {
        CryptoError::NotSupported(format!(
            "cannot read x509 extension str: `{conf:?}`.\nReason: {e}"
        ))
    })?;
    parse_v3_ca(&conf, x509_context)
}

pub fn parse_v3_ca(
    conf: &Ini,
    x509_context: &X509v3Context,
) -> Result<Vec<X509Extension>, CryptoError> {
    let v3_ca = conf.section(Some("v3_ca")).ok_or_else(|| {
        CryptoError::NotSupported(
            "unable to find `v3_ca` parag from X.509 extension content".to_owned(),
        )
    })?;

    let mut extensions = Vec::new();
    for (key, value) in v3_ca {
        match key {
            "subjectKeyIdentifier" => {
                if value.contains("critical") {
                    extensions.push(SubjectKeyIdentifier::new().critical().build(x509_context)?);
                } else {
                    extensions.push(SubjectKeyIdentifier::new().build(x509_context)?);
                }
            }
            "keyUsage" => {
                let mut ku = KeyUsage::new();
                for value in value.trim().split(',') {
                    match value {
                        "critical" => ku.critical(),
                        "digitalSignature" => ku.digital_signature(),
                        "nonRepudiation" => ku.non_repudiation(),
                        "keyEncipherment" => ku.key_encipherment(),
                        "dataEncipherment" => ku.data_encipherment(),
                        "keyAgreement" => ku.key_agreement(),
                        "keyCertSign" => ku.key_cert_sign(),
                        "crlSign" => ku.crl_sign(),
                        "encipherOnly" => ku.encipher_only(),
                        "decipherOnly" => ku.decipher_only(),
                        _ => {
                            crypto_bail!("not supported `keyUsage` extension's value: `{value}`");
                        }
                    };
                }
                extensions.push(ku.build()?);
            }
            "subjectAltName" => {
                let mut san = SubjectAlternativeName::new();
                value.trim().split(',').try_for_each(|value| {
                    match value {
                        "critical" => san.critical(),
                        // `email:my@example.com`
                        _ if value.starts_with("email") => san.email(colon_split(value, "email")?),
                        // `URI:http://my.example.com/`
                        _ if value.starts_with("URI") => san.uri(colon_split(value, "URI")?),
                        // `DNS:mail.example.com`
                        _ if value.starts_with("DNS") => san.dns(colon_split(value, "DNS")?),
                        // `IP:192.168.1.1`
                        // `IP:13::16`
                        _ if value.starts_with("IP") => san.ip(colon_split(value, "IP")?),
                        // `RID:1.2.3.4`
                        _ if value.starts_with("RID") => san.rid(colon_split(value, "RID")?),
                        // "otherName" => {
                        //     // otherName:1.2.3.4
                        //     let other_name_value = colon_split(value, "otherName")?;
                        //     // must encode content to DER ASN.1 ...
                        //     san.other_name2(oid, content)
                        // }
                        _ => {
                            crypto_bail!(
                                "not supported `subjectAltName` extension's value: {value}"
                            );
                        }
                    };
                    Ok::<_, CryptoError>(())
                })?;
                extensions.push(san.build(x509_context)?);
            }
            "privateKeyUsagePeriod" => {
                #[expect(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::PRIVATE_KEY_USAGE_PERIOD,
                    value,
                )?);
            }
            "issuerAltName" => {
                #[expect(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::ISSUER_ALT_NAME,
                    value,
                )?);
            }
            "basicConstraints" => {
                let mut bc = BasicConstraints::new();
                value.trim().split(',').try_for_each(|value| {
                    match value {
                        "critical" => bc.critical(),
                        "CA:true" | "CA:TRUE" => bc.ca(),
                        _ if value.starts_with("pathlen") => {
                            let pathlen =
                                colon_split(value, "pathlen")?.parse::<u32>().map_err(|e| {
                                    CryptoError::NotSupported(format!(
                                        "unable to convert Basic Constraints pathlen to `u32` \
                                         value: `{value}`. Reason: {e}"
                                    ))
                                })?;
                            bc.pathlen(pathlen)
                        }
                        _ => {
                            warn!("ignored `basicConstraints` extension's value: {value}");
                            &mut bc
                        }
                    };
                    Ok::<_, CryptoError>(())
                })?;
                extensions.push(bc.build()?);
            }
            "nameConstraints" => {
                #[expect(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::NAME_CONSTRAINTS,
                    value,
                )?);
            }
            "crlDistributionPoints" => {
                #[expect(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::CRL_DISTRIBUTION_POINTS,
                    value,
                )?);
            }
            "certificatePolicies" => {
                extensions.push(build_certificate_policies_extension(value)?);
            }
            "extendedKeyUsage" => {
                let mut eku = ExtendedKeyUsage::new();
                value.trim().split(',').try_for_each(|value| {
                    match value {
                        "critical" => eku.critical(),
                        "serverAuth" => eku.server_auth(),
                        "clientAuth" => eku.client_auth(),
                        "codeSigning" => eku.code_signing(),
                        "emailProtection" => eku.email_protection(),
                        "timeStamping" => eku.time_stamping(),
                        "OCSPSigning" => eku.other("OCSPSigning"),
                        "ipsecIKE" => eku.other("ipsecIKE"),
                        "msCodeInd" => eku.ms_code_ind(),
                        "msCodeCom" => eku.ms_code_com(),
                        "msCTLSign" => eku.ms_ctl_sign(),
                        "msEFS" => eku.ms_efs(),
                        "nsSGC" => eku.ns_sgc(),
                        "msSGC" => eku.ms_sgc(),
                        _ => {
                            crypto_bail!(
                                "not supported `extendedKeyUsage` extension's value: {value}"
                            );
                        }
                    };
                    Ok::<_, CryptoError>(())
                })?;
                extensions.push(eku.build()?);
            }
            "authorityKeyIdentifier" => {
                let mut aki = AuthorityKeyIdentifier::new();
                value.trim().split(',').try_for_each(|value| {
                    match value {
                        "critical" => aki.critical(),
                        "issuer:always" => aki.issuer(true),
                        "issuer" => aki.issuer(false),
                        "keyid:always" => aki.keyid(true),
                        "keyid" => aki.keyid(false),
                        _ => {
                            crypto_bail!(
                                "not supported `authorityKeyIdentifier` extension's value: {value}"
                            );
                        }
                    };
                    Ok::<_, CryptoError>(())
                })?;
                extensions.push(aki.build(x509_context)?);
            }
            "authorityInfoAccess" => {
                // OID 1.3.6.1.5.5.7.1.1 — Authority Information Access
                // Value format: "OCSP;URI:http://ocsp.example.com/,caIssuers;URI:http://ca.example.com/ca.crt"
                #[expect(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::INFO_ACCESS,
                    value,
                )?);
            }
            "noRevAvail" => {
                // id-ce-noRevAvail (RFC 9608 §2), OID { id-ce 56 } = 2.5.29.56.
                // OpenSSL does not register this OID in its extension table, so we build
                // the extension directly using new_from_der().
                // Criticality MUST be FALSE; DER encoding is '0500'H (NULL).
                let oid = Asn1Object::from_str("2.5.29.56")?;
                let val = Asn1OctetString::new_from_bytes(&[0x05, 0x00])?;
                extensions.push(X509Extension::new_from_der(
                    oid.as_ref(),
                    false,
                    val.as_ref(),
                )?);
            }
            _ => {
                return Err(CryptoError::Default(format!(
                    "`{key}` is not a valid X.509 extension key property"
                )));
            }
        }
    }

    Ok(extensions)
}

/// Build a `certificatePolicies` X.509v3 extension (OID 2.5.29.32) from an OpenSSL
/// `x509v3_config`-style value string, **without** requiring an OpenSSL config database.
///
/// OpenSSL's built-in `certificatePolicies` parser (`r2i_certpol`) requires `ctx->db` to be
/// non-NULL even for bare OIDs, because it calls `policy_section()` internally. The x509v3
/// context created by `X509Builder::x509v3_context` is always constructed without a config
/// database in our call-site, so delegating to `X509Extension::new_nid` with `None` always
/// triggers "no config database". This function parses the value natively and emits the
/// correct DER without any OpenSSL conf dependency.
///
/// # Supported syntax
///
/// ```text
/// certificatePolicies = [critical,] OID [, CPS:url | CPS.N:url] [, OID ...]
/// ```
///
/// * `critical` – marks the extension as critical (may appear anywhere before the first OID).
/// * `OID` – a dotted-decimal policy OID, e.g. `1.3.6.1.4.1.16376.9.1.1.1.0`.
/// * `CPS:url` – inline CPS (Certification Practice Statement) qualifier.
/// * `CPS.N:url` – same with a numeric suffix (section-style numbering accepted by OpenSSL
///   config files); the `.N` part is ignored and treated like plain `CPS:`.
///
/// # Errors
///
/// Returns an error for unknown qualifier tokens or malformed OID notation.
fn build_certificate_policies_extension(value: &str) -> Result<X509Extension, CryptoError> {
    let mut critical = false;
    // Each entry: (policy_oid_dotted, cps_urls)
    let mut policies: Vec<(String, Vec<String>)> = Vec::new();

    for token in value.split(',') {
        let token = token.trim();
        if token.eq_ignore_ascii_case("critical") {
            critical = true;
        } else if is_dotted_oid(token) {
            policies.push((token.to_owned(), Vec::new()));
        } else if let Some(url) = strip_cps_qualifier(token) {
            let last = policies.last_mut().ok_or_else(|| {
                CryptoError::NotSupported(
                    "certificatePolicies: CPS qualifier appears before any policy OID".to_owned(),
                )
            })?;
            last.1.push(url.to_owned());
        } else {
            return Err(CryptoError::NotSupported(format!(
                "certificatePolicies: unsupported token `{token}`. \
                 Accepted: `critical`, a dotted OID, `CPS:url`, or `CPS.N:url`"
            )));
        }
    }

    if policies.is_empty() {
        return Err(CryptoError::NotSupported(
            "certificatePolicies: at least one policy OID is required".to_owned(),
        ));
    }

    // Encode SEQUENCE OF PolicyInformation
    let mut policies_content = Vec::new();
    // id-qt-cps OID bytes (1.3.6.1.5.5.7.2.1) – pre-encoded for efficiency
    let cps_oid_der = der_encode_oid("1.3.6.1.5.5.7.2.1")?;

    for (oid_str, cps_urls) in &policies {
        let oid_der = der_encode_oid(oid_str)?;

        let policy_info_inner = if cps_urls.is_empty() {
            oid_der
        } else {
            let mut qualifiers_content = Vec::new();
            for url in cps_urls {
                // PolicyQualifierInfo ::= SEQUENCE { policyQualifierId OID, qualifier IA5String }
                let ia5_der = der_encode_ia5string(url);
                let pqi_inner: Vec<u8> = [cps_oid_der.as_slice(), ia5_der.as_slice()].concat();
                qualifiers_content.extend_from_slice(&der_encode_sequence(&pqi_inner));
            }
            // PolicyInformation ::= SEQUENCE { policyIdentifier OID, policyQualifiers SEQUENCE }
            [
                oid_der.as_slice(),
                der_encode_sequence(&qualifiers_content).as_slice(),
            ]
            .concat()
        };
        policies_content.extend_from_slice(&der_encode_sequence(&policy_info_inner));
    }

    // extnValue OCTET STRING wraps the DER of SEQUENCE OF PolicyInformation
    let ext_value_der = der_encode_sequence(&policies_content);
    let ext_oid = Asn1Object::from_str("2.5.29.32")?;
    let octet_string = Asn1OctetString::new_from_bytes(&ext_value_der)?;
    X509Extension::new_from_der(ext_oid.as_ref(), critical, octet_string.as_ref())
        .map_err(CryptoError::from)
}

/// Returns `true` when `s` looks like a dotted-decimal OID
/// (starts with a digit, contains only ASCII digits and `.`).
fn is_dotted_oid(s: &str) -> bool {
    !s.is_empty()
        && s.starts_with(|c: char| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// If `token` is `CPS:url` or `CPS.N:url` (section-style numbering), returns the URL part.
fn strip_cps_qualifier(token: &str) -> Option<&str> {
    let rest = token.strip_prefix("CPS")?;
    // "CPS:url" — direct
    if let Some(url) = rest.strip_prefix(':') {
        return Some(url);
    }
    // "CPS.N:url" — skip the numeric ".N" suffix
    let after_dot = rest.strip_prefix('.')?;
    let colon = after_dot.find(':')?;
    // Verify the part before ':' is all digits (the index N)
    if after_dot[..colon].chars().all(|c| c.is_ascii_digit()) {
        return after_dot.get(colon + 1..);
    }
    None
}

// ── Minimal DER encoding helpers ─────────────────────────────────────────────

/// Encode a DER length field (short-form or two-octet long-form).
///
/// Certificate-extension values are always < 64 KiB. The `if` branches
/// guarantee the casts are always in range; the allows suppress the
/// false-positive truncation and silent-conversion lints.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
fn der_encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Wrap `content` in a DER SEQUENCE (tag `0x30`).
fn der_encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_encode_length(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode a dotted-decimal OID string as a DER OID TLV (tag `0x06`).
fn der_encode_oid(oid_str: &str) -> Result<Vec<u8>, CryptoError> {
    let components: Vec<u64> = oid_str
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CryptoError::NotSupported(format!("invalid OID `{oid_str}`: {e}")))?;

    // Split off the first two arcs — both are required by the OID grammar.
    let (first, remainder) = components.split_first().ok_or_else(|| {
        CryptoError::NotSupported(format!("OID `{oid_str}` must have at least two components"))
    })?;
    let (second, rest) = remainder.split_first().ok_or_else(|| {
        CryptoError::NotSupported(format!("OID `{oid_str}` must have at least two components"))
    })?;

    let mut content = Vec::new();
    // First two arcs are merged: value = 40 * first + second
    content.extend_from_slice(&der_encode_base128(first * 40 + second));
    for &arc in rest {
        content.extend_from_slice(&der_encode_base128(arc));
    }

    let mut out = vec![0x06]; // OID tag
    out.extend_from_slice(&der_encode_length(content.len()));
    out.extend_from_slice(&content);
    Ok(out)
}

/// Encode `n` in base-128 big-endian (DER OID arc encoding).
/// `n & 0x7F` is always ≤ 127 and fits in `u8`; the allow suppresses the
/// false-positive silent-conversion lint.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
fn der_encode_base128(mut n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x00];
    }
    let mut bytes = Vec::new();
    while n > 0 {
        bytes.push((n & 0x7F) as u8);
        n >>= 7;
    }
    bytes.reverse();
    // Set the high bit on every byte except the last
    if let Some((_, all_but_last)) = bytes.split_last_mut() {
        for b in all_but_last {
            *b |= 0x80;
        }
    }
    bytes
}

/// Encode a string as a DER `IA5String` (tag `0x16`).
fn der_encode_ia5string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = vec![0x16]; // IA5String tag
    out.extend_from_slice(&der_encode_length(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

/// Within a value, there can be properties (ie: `email:test@example.com`).
/// This function extracts the property value, by splitting the input `value` (ie: `prop_name:val`) and returning `val`
fn colon_split<'a>(value: &'a str, property_name: &str) -> Result<&'a str, CryptoError> {
    let (_, val) = value
        .split_once(&format!("{property_name}:"))
        .ok_or_else(|| {
            CryptoError::NotSupported(format!(
                "unable to parse `{property_name}` from value: `{value}`"
            ))
        })?;
    Ok(val)
}

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use cosmian_logger::{info, log_init};
    use ini::Ini;
    use openssl::{
        conf::{Conf, ConfMethod},
        x509::X509,
    };
    use x509_parser::{
        der_parser::oid,
        extensions::{ParsedExtension, X509ExtensionParser},
        nom::Parser as _,
        prelude::*,
    };

    use super::{colon_split, is_dotted_oid, parse_v3_ca_from_str, strip_cps_qualifier};

    #[test]
    fn test_split() {
        let split = colon_split("email:dummy@gmail.com", "email").unwrap();
        assert_eq!(split, "dummy@gmail.com");
        colon_split("email:dummy@gmail.com", "emails").unwrap_err();
    }

    #[test]
    fn test_parse_ext_file() {
        log_init(option_env!("RUST_LOG"));

        let ext_file = r"[ v3_ca ]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:http://cse.example.com/crl.pem";

        let mut x509_builder = X509::builder().unwrap();
        let x509_context = x509_builder.x509v3_context(None, None);

        let parsed_exts = parse_v3_ca_from_str(ext_file, &x509_context).unwrap();
        assert_eq!(parsed_exts.len(), 4);

        let parsed_exts_der = parsed_exts
            .iter()
            .map(|x| x.to_der().unwrap())
            .collect::<Vec<_>>();

        let exts_with_x509_parser = parsed_exts_der
            .iter()
            .map(|x| X509ExtensionParser::new().parse(x).unwrap().1)
            .collect::<Vec<_>>();

        parsed_exts
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))
            .unwrap();

        let x509 = x509_builder.build();
        let crl_distribution_point = x509.as_ref().crl_distribution_points().unwrap();
        let stack = crl_distribution_point
            .iter()
            .next()
            .unwrap()
            .distpoint()
            .unwrap()
            .fullname()
            .unwrap();
        assert_eq!(
            stack.get(0).unwrap().uri(),
            Some("http://cse.example.com/crl.pem")
        );

        let cert_as_txt = x509.as_ref().to_text().unwrap();
        let cert = String::from_utf8_lossy(&cert_as_txt);

        let cert_ = r"            X509v3 Basic Constraints: 
                CA:TRUE, pathlen:0
            X509v3 Key Usage: 
                Digital Signature, Certificate Sign
            X509v3 Extended Key Usage: 
                E-mail Protection
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:http://cse.example.com/crl.pem
    Signature Algorithm: NULL
    Signature Value:

";
        assert_eq!(
            cert.split_once("X509v3 extensions:\n")
                .unwrap()
                .1
                .replace('\n', ""),
            cert_.replace('\n', "")
        );

        for ext in &exts_with_x509_parser {
            info!("\n\next: {:?}", ext);
            info!("value is: {:?}", String::from_utf8(ext.value.to_vec()));
        }

        // BasicConstraints
        let bc = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.19))
            .unwrap();
        assert!(!bc.critical);
        assert_eq!(
            bc.parsed_extension(),
            &ParsedExtension::BasicConstraints(BasicConstraints {
                ca: true,
                path_len_constraint: Some(0)
            })
        );

        // KeyUsage
        let ku: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.15))
            .unwrap();
        assert!(!ku.critical);
        assert_eq!(
            ku.parsed_extension(),
            &ParsedExtension::KeyUsage(KeyUsage { flags: 33 })
        );

        // ExtendedKeyUsage
        let eku: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.37))
            .unwrap();
        assert!(!eku.critical);
        assert_eq!(
            eku.parsed_extension(),
            &ParsedExtension::ExtendedKeyUsage(ExtendedKeyUsage {
                any: false,
                server_auth: false,
                client_auth: false,
                code_signing: false,
                email_protection: true,
                time_stamping: false,
                ocsp_signing: false,
                other: vec![]
            })
        );

        // CRLDistributionPoints
        let crl_dp: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.31))
            .unwrap();
        assert!(!crl_dp.critical);
        assert_eq!(
            crl_dp.parsed_extension(),
            &ParsedExtension::CRLDistributionPoints(CRLDistributionPoints {
                points: vec![CRLDistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![
                        GeneralName::URI("http://cse.example.com/crl.pem")
                    ])),
                    reasons: None,
                    crl_issuer: None
                }]
            })
        );
    }

    /// Following documentation, these are used extensions by Gmail:
    /// - Key Usage (required, critical)
    /// - Extended Key Usage (required, either)
    /// - Basic Constraints (required, critical)
    /// - Certificate Policies (optional)
    /// - CRL Distribution Points (required)
    ///
    /// see: <https://support.google.com/a/answer/7300887?fl=1&sjid=2466928410660190479-NA#zippy=%2Croot-ca%2Cintermediate-ca-certificates-other-than-from-issuing-intermediate-ca%2Cintermediate-ca-certificate-that-issues-the-end-entity>
    #[test]
    fn test_parse_extensions_gmail() {
        log_init(option_env!("RUST_LOG"));

        let ext_file = r"[ v3_ca ]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:http://cse.example.com/crl.pem
certificatePolicies=2.5.29.32
";

        let conf = Conf::new(ConfMethod::default()).unwrap();
        let mut x509_builder = X509::builder().unwrap();
        let x509_context = x509_builder.x509v3_context(None, Some(conf.as_ref()));

        let parsed_exts = parse_v3_ca_from_str(ext_file, &x509_context).unwrap();
        assert_eq!(parsed_exts.len(), 5);

        let parsed_exts_der = parsed_exts
            .iter()
            .map(|x| x.to_der().unwrap())
            .collect::<Vec<_>>();

        let exts_with_x509_parser = parsed_exts_der
            .iter()
            .map(|x| X509ExtensionParser::new().parse(x).unwrap().1)
            .collect::<Vec<_>>();

        parsed_exts
            .into_iter()
            .try_for_each(|extension| x509_builder.append_extension(extension))
            .unwrap();

        for ext in &exts_with_x509_parser {
            info!("\n\next: {:?}", ext);
            info!("value is: {:?}", String::from_utf8(ext.value.to_vec()));
        }

        // BasicConstraints
        let bc = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.19))
            .unwrap();
        assert!(bc.critical);
        assert_eq!(
            bc.parsed_extension(),
            &ParsedExtension::BasicConstraints(BasicConstraints {
                ca: true,
                path_len_constraint: Some(0)
            })
        );

        // KeyUsage
        let ku: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.15))
            .unwrap();
        assert!(ku.critical);
        assert_eq!(
            ku.parsed_extension(),
            &ParsedExtension::KeyUsage(KeyUsage { flags: 33 })
        );

        // ExtendedKeyUsage
        let eku: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.37))
            .unwrap();
        assert!(!eku.critical);
        assert_eq!(
            eku.parsed_extension(),
            &ParsedExtension::ExtendedKeyUsage(ExtendedKeyUsage {
                any: false,
                server_auth: false,
                client_auth: false,
                code_signing: false,
                email_protection: true,
                time_stamping: false,
                ocsp_signing: false,
                other: vec![]
            })
        );

        // CRLDistributionPoints
        let crl_dp: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.31))
            .unwrap();
        assert!(!crl_dp.critical);
        assert_eq!(
            crl_dp.parsed_extension(),
            &ParsedExtension::CRLDistributionPoints(CRLDistributionPoints {
                points: vec![CRLDistributionPoint {
                    distribution_point: Some(DistributionPointName::FullName(vec![
                        GeneralName::URI("http://cse.example.com/crl.pem")
                    ])),
                    reasons: None,
                    crl_issuer: None
                }]
            })
        );

        // CertificatePolicies
        let cert_policies: &X509Extension<'_> = exts_with_x509_parser
            .iter()
            .find(|x| x.oid == oid!(2.5.29.32))
            .unwrap();
        assert!(!cert_policies.critical);
        assert_eq!(
            cert_policies.parsed_extension(),
            &ParsedExtension::CertificatePolicies(vec![PolicyInformation {
                policy_id: oid!(2.5.29.32),
                policy_qualifiers: None
            }])
        );
    }

    /// Non-regression: the "OK" CNF (without CPS qualifier) must parse successfully.
    #[test]
    fn test_certificate_policies_cnf_ok() {
        log_init(option_env!("RUST_LOG"));

        let cnf_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/scripts/test/certificatePolicies/v3_ca_ok.cnf"
        );
        let cnf_content = std::fs::read_to_string(cnf_path).unwrap();

        let builder = X509::builder().unwrap();
        let ctx = builder.x509v3_context(None, None);
        let result = parse_v3_ca_from_str(&cnf_content, &ctx);
        assert!(
            result.is_ok(),
            "v3_ca_ok.cnf should parse successfully, got: {:?}",
            result.err()
        );
        // Should produce 3 extensions: basicConstraints, subjectKeyIdentifier, keyUsage
        assert_eq!(result.unwrap().len(), 3);
    }

    /// Non-regression: the "KO" CNF (with CPS.1:url qualifier) now SUCCEEDS after the fix.
    ///
    /// Before the fix this test asserted `result.is_err()` (the old code used
    /// `X509Extension::new_nid` which requires an OpenSSL config database).
    /// After the fix (`build_certificate_policies_extension` native DER encoder),
    /// parsing succeeds — proving the fix works.
    #[test]
    fn test_certificate_policies_cnf_ko_now_succeeds_with_fix() {
        log_init(option_env!("RUST_LOG"));

        let cnf_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/scripts/test/certificatePolicies/v3_ca_ko.cnf"
        );
        let cnf_content = std::fs::read_to_string(cnf_path).unwrap();

        let builder = X509::builder().unwrap();
        let ctx = builder.x509v3_context(None, None);
        let result = parse_v3_ca_from_str(&cnf_content, &ctx);

        // NEW BEHAVIOR (after fix): parsing succeeds
        assert!(
            result.is_ok(),
            "v3_ca_ko.cnf should now SUCCEED with the fix, got: {:?}",
            result.err()
        );
        // Should produce 4 extensions: basicConstraints, subjectKeyIdentifier, keyUsage, certificatePolicies
        assert_eq!(result.unwrap().len(), 4);
    }

    /// Verify that `certificatePolicies` with a CPS qualifier (both `CPS:url` and the
    /// section-numbering variant `CPS.N:url`) is correctly parsed and encoded **without**
    /// an OpenSSL config database — which is the real-world scenario in the KMS server.
    ///
    /// Regression test for the customer bug where
    /// `certificatePolicies=1.3.6.1.4.1.16376.9.1.1.1.0,CPS.1:http://...` triggered
    /// `error:11000088:X509 V3 routines:do_ext_nconf:no config database`.
    #[test]
    #[allow(
        clippy::items_after_statements,
        clippy::panic,
        clippy::indexing_slicing
    )]
    fn test_certificate_policies_with_cps_qualifier() {
        const CPS_URL: &str = "http://pkipubpc.cnp.recouv/pc_acoss_reseau_des_urssaf_v4.pdf";
        const POLICY_OID: &str = "1.3.6.1.4.1.16376.9.1.1.1.0";
        const ID_QT_CPS: &str = "1.3.6.1.5.5.7.2.1";

        log_init(option_env!("RUST_LOG"));

        // — Test 1: bare OID, no conf database (the context has no conf).
        let ext_bare = format!("[ v3_ca ]\ncertificatePolicies={POLICY_OID}\n");
        let builder = X509::builder().unwrap();
        // Deliberately no Conf — mirrors the production path in apply_user_extensions.
        let ctx = builder.x509v3_context(None, None);
        let exts = parse_v3_ca_from_str(&ext_bare, &ctx).unwrap();
        assert_eq!(exts.len(), 1);
        let der = exts[0].to_der().unwrap();
        let (_, parsed) = X509ExtensionParser::new().parse(&der).unwrap();
        assert!(!parsed.critical);
        assert!(
            matches!(
                parsed.parsed_extension(),
                ParsedExtension::CertificatePolicies(_)
            ),
            "expected CertificatePolicies, got {:?}",
            parsed.parsed_extension()
        );

        // — Test 2: CPS.N:url (section-numbering variant used by the customer PKI).
        let ext_cps_numbered =
            format!("[ v3_ca ]\ncertificatePolicies={POLICY_OID},CPS.1:{CPS_URL}\n");
        let ctx2 = builder.x509v3_context(None, None);
        let exts2 = parse_v3_ca_from_str(&ext_cps_numbered, &ctx2).unwrap();
        assert_eq!(exts2.len(), 1);
        let der2 = exts2[0].to_der().unwrap();
        let (_, parsed2) = X509ExtensionParser::new().parse(&der2).unwrap();
        assert!(!parsed2.critical);
        let policies2 = match parsed2.parsed_extension() {
            ParsedExtension::CertificatePolicies(p) => p,
            other => panic!("expected CertificatePolicies, got {other:?}"),
        };
        assert_eq!(policies2.len(), 1);
        assert_eq!(policies2[0].policy_id.to_id_string(), POLICY_OID);
        let qualifiers2 = policies2[0].policy_qualifiers.as_ref().unwrap();
        assert_eq!(qualifiers2.len(), 1);
        // OID 1.3.6.1.5.5.7.2.1 = id-qt-cps
        assert_eq!(qualifiers2[0].policy_qualifier_id.to_id_string(), ID_QT_CPS);
        // qualifier bytes are DER IA5String (0x16 len bytes): verify URL is embedded
        let q2 = qualifiers2[0].qualifier;
        assert!(q2.len() >= 2 && q2[0] == 0x16, "expected IA5String tag");
        let url2 = std::str::from_utf8(&q2[2..]).unwrap();
        assert_eq!(url2, CPS_URL);

        // — Test 3: plain CPS:url (without numbered suffix).
        let ext_cps_plain = format!("[ v3_ca ]\ncertificatePolicies={POLICY_OID},CPS:{CPS_URL}\n");
        let ctx3 = builder.x509v3_context(None, None);
        let exts3 = parse_v3_ca_from_str(&ext_cps_plain, &ctx3).unwrap();
        assert_eq!(exts3.len(), 1);
        let der3 = exts3[0].to_der().unwrap();
        let (_, parsed3) = X509ExtensionParser::new().parse(&der3).unwrap();
        let policies3 = match parsed3.parsed_extension() {
            ParsedExtension::CertificatePolicies(p) => p,
            other => panic!("expected CertificatePolicies, got {other:?}"),
        };
        let qualifiers3 = policies3[0].policy_qualifiers.as_ref().unwrap();
        let q3 = qualifiers3[0].qualifier;
        assert!(q3.len() >= 2 && q3[0] == 0x16, "expected IA5String tag");
        let url3 = std::str::from_utf8(&q3[2..]).unwrap();
        assert_eq!(url3, CPS_URL, "CPS URL mismatch in plain CPS: form");

        // — Test 4: critical flag.
        let ext_critical =
            format!("[ v3_ca ]\ncertificatePolicies=critical,{POLICY_OID},CPS:{CPS_URL}\n");
        let ctx4 = builder.x509v3_context(None, None);
        let exts4 = parse_v3_ca_from_str(&ext_critical, &ctx4).unwrap();
        let der4 = exts4[0].to_der().unwrap();
        let (_, parsed4) = X509ExtensionParser::new().parse(&der4).unwrap();
        assert!(parsed4.critical, "expected critical extension");
    }

    #[test]
    fn test_is_dotted_oid() {
        assert!(is_dotted_oid("1.3.6.1.4.1.16376.9.1.1.1.0"));
        assert!(is_dotted_oid("2.5.29.32"));
        assert!(!is_dotted_oid("critical"));
        assert!(!is_dotted_oid("CPS:url"));
        assert!(!is_dotted_oid(""));
    }

    #[test]
    fn test_strip_cps_qualifier() {
        assert_eq!(
            strip_cps_qualifier("CPS:http://example.com"),
            Some("http://example.com")
        );
        assert_eq!(
            strip_cps_qualifier("CPS.1:http://example.com"),
            Some("http://example.com")
        );
        assert_eq!(
            strip_cps_qualifier("CPS.42:http://example.com"),
            Some("http://example.com")
        );
        assert_eq!(strip_cps_qualifier("critical"), None);
        assert_eq!(strip_cps_qualifier("1.2.3.4"), None);
    }

    /// Demonstrates that the **old** code path — `X509Extension::new_nid` with `None` as
    /// config — fails for `certificatePolicies` values that contain a `CPS.N:url` qualifier.
    ///
    /// This mirrors the customer error:
    ///   `error:11000088:X509 V3 routines:do_ext_nconf:no config database`
    ///
    /// The new implementation (`build_certificate_policies_extension`) replaces this
    /// error-prone call with a hand-crafted DER encoder that requires no OpenSSL config.
    #[test]
    #[allow(deprecated, clippy::expect_used)]
    fn test_old_new_nid_fails_for_cps_syntax() {
        use openssl::{nid::Nid, x509::X509Extension as OpenSslX509Extension};

        // Read the customer's CNF fixture that triggered the production bug.
        let cnf_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.github/scripts/test/certificatePolicies/v3_ca_ko.cnf"
        );
        let cnf_content =
            std::fs::read_to_string(cnf_path).expect("v3_ca_ko.cnf should be readable");
        let ini = Ini::load_from_str(&cnf_content).expect("v3_ca_ko.cnf should be valid INI");
        let cps_value = ini
            .section(Some("v3_ca"))
            .and_then(|s| s.get("certificatePolicies"))
            .expect("certificatePolicies key missing from [v3_ca]");

        let builder = X509::builder().unwrap();
        // Deliberately no Conf — mirrors the production path in apply_user_extensions.
        let ctx = builder.x509v3_context(None, None);

        // The old API cannot resolve CPS.1:url without a config database; it must return an error.
        let result =
            OpenSslX509Extension::new_nid(None, Some(&ctx), Nid::CERTIFICATE_POLICIES, cps_value);
        assert!(
            result.is_err(),
            "Expected X509Extension::new_nid to fail for CPS.1:url syntax without conf, but it succeeded"
        );
    }
}

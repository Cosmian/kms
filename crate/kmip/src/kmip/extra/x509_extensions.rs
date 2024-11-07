use std::path::PathBuf;

use ini::Ini;
use openssl::{
    nid::Nid,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Extension, X509v3Context,
    },
};
use tracing::warn;

use crate::{error::KmipError, kmip::kmip_operations::ErrorReason, kmip_bail};

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
) -> Result<Vec<X509Extension>, KmipError> {
    let conf = Ini::load_from_file(extension_file).map_err(|e| {
        KmipError::NotSupported(format!(
            "cannot read x509 extension file: `{extension_file:?}`. Reason: {e}"
        ))
    })?;
    parse_v3_ca(&conf, x509_context)
}

pub fn parse_v3_ca_from_str(
    conf: &str,
    x509_context: &X509v3Context,
) -> Result<Vec<X509Extension>, KmipError> {
    let conf = Ini::load_from_str(conf).map_err(|e| {
        KmipError::NotSupported(format!(
            "cannot read x509 extension str: `{conf:?}`.\nReason: {e}"
        ))
    })?;
    parse_v3_ca(&conf, x509_context)
}

pub fn parse_v3_ca(
    conf: &Ini,
    x509_context: &X509v3Context,
) -> Result<Vec<X509Extension>, KmipError> {
    let v3_ca = conf.section(Some("v3_ca")).ok_or_else(|| {
        KmipError::NotSupported(
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
                            kmip_bail!("not supported `keyUsage` extension's value: `{value}`");
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
                            kmip_bail!("not supported `subjectAltName` extension's value: {value}");
                        }
                    };
                    Ok::<_, KmipError>(())
                })?;
                extensions.push(san.build(x509_context)?);
            }
            "privateKeyUsagePeriod" => {
                #[allow(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::PRIVATE_KEY_USAGE_PERIOD,
                    value,
                )?);
            }
            "issuerAltName" => {
                #[allow(deprecated)]
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
                                    KmipError::NotSupported(format!(
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
                    Ok::<_, KmipError>(())
                })?;
                extensions.push(bc.build()?);
            }
            "nameConstraints" => {
                #[allow(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::NAME_CONSTRAINTS,
                    value,
                )?);
            }
            "crlDistributionPoints" => {
                #[allow(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::CRL_DISTRIBUTION_POINTS,
                    value,
                )?);
            }
            "certificatePolicies" => {
                #[allow(deprecated)]
                extensions.push(X509Extension::new_nid(
                    None,
                    Some(x509_context),
                    Nid::CERTIFICATE_POLICIES,
                    value,
                )?);
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
                            kmip_bail!(
                                "not supported `extendedKeyUsage` extension's value: {value}"
                            );
                        }
                    };
                    Ok::<_, KmipError>(())
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
                            kmip_bail!(
                                "not supported `authorityKeyIdentifier` extension's value: {value}"
                            );
                        }
                    };
                    Ok::<_, KmipError>(())
                })?;
                extensions.push(aki.build(x509_context)?);
            }
            // "authorityInfoAccess" => {
            //     #[allow(deprecated)]
            //     X509Extension::new_nid(
            //         None,
            //         Some(x509_context),
            //         Nid::????,
            //         value,
            //     )?
            // }
            // "proxyCertificationInformation" => {
            //     #[allow(deprecated)]
            //     X509Extension::new_nid(
            //         None,
            //         Some(x509_context),
            //         Nid::????,
            //         value,
            //     )?
            // }
            _ => {
                return Err(KmipError::InvalidKmipObject(
                    ErrorReason::Invalid_Attribute,
                    format!("`{key}` is not a valid X.509 extension key property"),
                ))
            }
        }
    }

    Ok(extensions)
}

/// Within a value, there can be properties (ie: `email:test@example.com`).
/// This function extracts the property value, by splitting the input `value` (ie: `prop_name:val`) and returning `val`
fn colon_split<'a>(value: &'a str, property_name: &str) -> Result<&'a str, KmipError> {
    let (_, val) = value
        .split_once(&format!("{property_name}:"))
        .ok_or_else(|| {
            KmipError::NotSupported(format!(
                "unable to parse `{property_name}` from value: `{value}`"
            ))
        })?;
    Ok(val)
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use cosmian_logger::log_init;
    use openssl::{
        conf::{Conf, ConfMethod},
        x509::X509,
    };
    use tracing::info;
    use x509_parser::{
        der_parser::oid,
        extensions::{ParsedExtension, X509ExtensionParser},
        nom::Parser as _,
        prelude::*,
    };

    use super::{colon_split, parse_v3_ca_from_str};

    #[test]
    fn test_split() {
        let split = colon_split("email:dummy@gmail.com", "email").unwrap();
        assert_eq!(split, "dummy@gmail.com");
        colon_split("email:dummy@gmail.com", "emails").unwrap_err();
    }

    #[test]
    fn test_parse_ext_file() {
        log_init(Some("info,hyper=info,reqwest=info"));

        let ext_file = r"[ v3_ca ]
basicConstraints=CA:TRUE,pathlen:0
keyUsage=keyCertSign,digitalSignature
extendedKeyUsage=emailProtection
crlDistributionPoints=URI:http://cse.example.com/crl.pem
";

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
        assert_eq!(cert.split_once("X509v3 extensions:\n").unwrap().1, cert_);

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
        log_init(Some("info,hyper=info,reqwest=info"));

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
}

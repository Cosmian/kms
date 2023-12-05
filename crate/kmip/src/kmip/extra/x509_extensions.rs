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

use crate::{error::KmipError, kmip::kmip_operations::ErrorReason};

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
//
//  [bs_section]
//  CA=true
//  pathlen=1
/// ```
pub fn parse_v3_ca(
    extension_file: &PathBuf,
    x509_context: &X509v3Context,
) -> Result<Vec<openssl::x509::X509Extension>, KmipError> {
    let conf = Ini::load_from_file(extension_file).map_err(|e| {
        KmipError::NotSupported(format!(
            "cannot read x509 extension file: `{extension_file:?}`. Reason: {e}"
        ))
    })?;
    let v3_ca = conf.section(Some("v3_ca")).ok_or_else(|| {
        KmipError::NotSupported(
            "unable to find `v3_ca` parag from X.509 extension content".to_string(),
        )
    })?;

    v3_ca
        .iter()
        .map(|(key, value)| {
            Ok(match key {
                "subjectKeyIdentifier" => {
                    if value.contains("critical") {
                        SubjectKeyIdentifier::new().critical().build(x509_context)?
                    } else {
                        SubjectKeyIdentifier::new().build(x509_context)?
                    }
                }
                "keyUsage" => {
                    let mut ku = KeyUsage::new();
                    value.trim().split(',').for_each(|value| {
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
                                warn!("ignored `keyUsage` extension's value: `{value}`");
                                &mut ku
                            }
                        };
                    });
                    ku.build()?
                }
                "subjectAltName" => {
                    let mut san = SubjectAlternativeName::new();
                    value.trim().split(',').try_for_each(|value| {
                        match value {
                            "critical" => san.critical(),
                            // `email:my@example.com`
                            _ if value.starts_with("email") => {
                                san.email(colon_split(value, "email")?)
                            }
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
                                warn!("ignored `subjectAltName` extension's value: {value}");
                                &mut san
                            }
                        };
                        Ok::<_, KmipError>(())
                    })?;
                    san.build(x509_context)?
                }
                "privateKeyUsagePeriod" =>
                {
                    #[allow(deprecated)]
                    X509Extension::new_nid(
                        None,
                        Some(x509_context),
                        Nid::PRIVATE_KEY_USAGE_PERIOD,
                        value,
                    )?
                }
                "issuerAltName" =>
                {
                    #[allow(deprecated)]
                    X509Extension::new_nid(None, Some(x509_context), Nid::ISSUER_ALT_NAME, value)?
                }
                "basicConstraints" => {
                    let mut bc = BasicConstraints::new();
                    value.trim().split(',').try_for_each(|value| {
                        match value {
                            "critical" => bc.critical(),
                            "CA:true" => bc.ca(),
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
                    bc.build()?
                }
                "nameConstraints" =>
                {
                    #[allow(deprecated)]
                    X509Extension::new_nid(None, Some(x509_context), Nid::NAME_CONSTRAINTS, value)?
                }
                "crlDistributionPoints" =>
                {
                    #[allow(deprecated)]
                    X509Extension::new_nid(
                        None,
                        Some(x509_context),
                        Nid::CRL_DISTRIBUTION_POINTS,
                        value,
                    )?
                }
                "certificatePolicies" =>
                {
                    #[allow(deprecated)]
                    X509Extension::new_nid(
                        None,
                        Some(x509_context),
                        Nid::CERTIFICATE_POLICIES,
                        value,
                    )?
                }
                "extendedKeyUsage" => {
                    let mut eku = ExtendedKeyUsage::new();
                    value.trim().split(',').try_for_each(|value| {
                        match value {
                            "critical" => eku.critical(),
                            "serverAuth" => eku.server_auth(),
                            "clientAuth" => eku.server_auth(),
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
                                warn!("ignored `extendedKeyUsage` extension's value: {value}");
                                &mut eku
                            }
                        };
                        Ok::<_, KmipError>(())
                    })?;
                    eku.build()?
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
                                warn!(
                                    "ignored `authorityKeyIdentifier` extension's value: {value}"
                                );
                                &mut aki
                            }
                        };
                        Ok::<_, KmipError>(())
                    })?;
                    aki.build(x509_context)?
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
            })
        })
        .collect::<Result<Vec<_>, KmipError>>()
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

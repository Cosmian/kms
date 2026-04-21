use clap::ValueEnum;
#[cfg(feature = "non-fips")]
use cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters;
use cosmian_kmip::{
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::Certify,
        kmip_types::{
            CertificateAttributes, CertificateRequestType, CryptographicAlgorithm,
            CryptographicDomainParameters, KeyFormatType, LinkType, LinkedObjectIdentifier,
            RecommendedCurve, UniqueIdentifier,
        },
    },
    time_normalize,
};
use strum::EnumString;

use crate::error::UtilsError;

/// The algorithm to use for the keypair generation
#[derive(ValueEnum, Clone, Copy, EnumString, Debug)]
#[strum(serialize_all = "kebab-case")]
pub enum Algorithm {
    #[cfg(feature = "non-fips")]
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    #[cfg(feature = "non-fips")]
    Ed25519,
    #[cfg(feature = "non-fips")]
    Ed448,
    #[cfg(feature = "non-fips")]
    RSA1024,
    RSA2048,
    RSA3072,
    RSA4096,
    // PQC signing algorithms (non-FIPS only)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-dsa-44")]
    #[value(name = "ml-dsa-44")]
    MlDsa44,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-dsa-65")]
    #[value(name = "ml-dsa-65")]
    MlDsa65,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-dsa-87")]
    #[value(name = "ml-dsa-87")]
    MlDsa87,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-128s")]
    #[value(name = "slh-dsa-sha2-128s")]
    SlhDsaSha2128s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-128f")]
    #[value(name = "slh-dsa-sha2-128f")]
    SlhDsaSha2128f,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-192s")]
    #[value(name = "slh-dsa-sha2-192s")]
    SlhDsaSha2192s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-192f")]
    #[value(name = "slh-dsa-sha2-192f")]
    SlhDsaSha2192f,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-256s")]
    #[value(name = "slh-dsa-sha2-256s")]
    SlhDsaSha2256s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-sha2-256f")]
    #[value(name = "slh-dsa-sha2-256f")]
    SlhDsaSha2256f,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-128s")]
    #[value(name = "slh-dsa-shake-128s")]
    SlhDsaShake128s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-128f")]
    #[value(name = "slh-dsa-shake-128f")]
    SlhDsaShake128f,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-192s")]
    #[value(name = "slh-dsa-shake-192s")]
    SlhDsaShake192s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-192f")]
    #[value(name = "slh-dsa-shake-192f")]
    SlhDsaShake192f,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-256s")]
    #[value(name = "slh-dsa-shake-256s")]
    SlhDsaShake256s,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "slh-dsa-shake-256f")]
    #[value(name = "slh-dsa-shake-256f")]
    SlhDsaShake256f,
    // ML-KEM and hybrid KEM algorithms (subject key for CA-issued certificates, non-FIPS only)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-512")]
    #[value(name = "ml-kem-512")]
    MlKem512,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-768")]
    #[value(name = "ml-kem-768")]
    MlKem768,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-1024")]
    #[value(name = "ml-kem-1024")]
    MlKem1024,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "x25519-ml-kem-768")]
    #[value(name = "x25519-ml-kem-768")]
    X25519MlKem768,
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "x448-ml-kem-1024")]
    #[value(name = "x448-ml-kem-1024")]
    X448MlKem1024,
    /// ML-KEM-512 hybridized with P-256 (`ConfigurableKEM`)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-512-p256")]
    #[value(name = "ml-kem-512-p256")]
    MlKem512P256,
    /// ML-KEM-768 hybridized with P-256 (`ConfigurableKEM`)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-768-p256")]
    #[value(name = "ml-kem-768-p256")]
    MlKem768P256,
    /// ML-KEM-512 hybridized with Curve25519 (`ConfigurableKEM`)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-512-curve25519")]
    #[value(name = "ml-kem-512-curve25519")]
    MlKem512Curve25519,
    /// ML-KEM-768 hybridized with Curve25519 (`ConfigurableKEM`)
    #[cfg(feature = "non-fips")]
    #[strum(serialize = "ml-kem-768-curve25519")]
    #[value(name = "ml-kem-768-curve25519")]
    MlKem768Curve25519,
}

#[expect(clippy::too_many_arguments)]
pub fn build_certify_request(
    vendor_id: &str,
    certificate_id: &Option<String>,
    certificate_signing_request_format: &Option<String>,
    certificate_signing_request: &Option<Vec<u8>>,
    public_key_id_to_certify: &Option<String>,
    certificate_id_to_re_certify: &Option<String>,
    generate_key_pair: bool,
    subject_name: &Option<String>,
    algorithm: Algorithm,
    issuer_private_key_id: &Option<String>,
    issuer_certificate_id: &Option<String>,
    number_of_days: usize,
    certificate_extensions: &Option<Vec<u8>>,
    tags: &[String],
) -> Result<Certify, UtilsError> {
    let mut attributes = Attributes {
        object_type: Some(ObjectType::Certificate),
        ..Attributes::default()
    };

    // set the issuer certificate id
    if let Some(issuer_certificate_id) = &issuer_certificate_id {
        attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(issuer_certificate_id.clone()),
        );
    }

    // set the issuer private key id
    if let Some(issuer_private_key_id) = &issuer_private_key_id {
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(issuer_private_key_id.clone()),
        );
    }

    // set the number of requested days
    attributes.set_requested_validity_days(
        vendor_id,
        i32::try_from(number_of_days).map_err(|_e| {
            UtilsError::Default("number of days must be a positive integer".to_owned())
        })?,
    );

    // A certificate id has been provided
    if let Some(certificate_id) = &certificate_id {
        attributes.unique_identifier = Some(UniqueIdentifier::TextString(certificate_id.clone()));
    }

    attributes.activation_date = Some(time_normalize()?);
    attributes.set_tags(vendor_id, tags)?;

    let mut certificate_request_value = None;
    let mut certificate_request_type = None;
    let mut unique_identifier = None;

    if let Some(certificate_signing_request) = &certificate_signing_request {
        certificate_request_value = Some(certificate_signing_request.clone());
        certificate_request_type = match certificate_signing_request_format.as_deref() {
            Some("der") => Some(CertificateRequestType::PKCS10),
            _ => Some(CertificateRequestType::PEM),
        };
    } else if let Some(public_key_to_certify) = &public_key_id_to_certify {
        attributes.certificate_attributes = Some(CertificateAttributes::parse_subject_line(
            subject_name.as_ref().ok_or_else(|| {
                UtilsError::Default(
                    "subject name is required when certifying a public key".to_owned(),
                )
            })?,
        )?);
        unique_identifier = Some(UniqueIdentifier::TextString(public_key_to_certify.clone()));
    } else if let Some(certificate_id_to_renew) = &certificate_id_to_re_certify {
        unique_identifier = Some(UniqueIdentifier::TextString(
            certificate_id_to_renew.clone(),
        ));
    } else if generate_key_pair {
        attributes.certificate_attributes = Some(CertificateAttributes::parse_subject_line(
            subject_name.as_ref().ok_or_else(|| {
                UtilsError::Default("subject name is required when generating a keypair".to_owned())
            })?,
        )?);
        match algorithm {
            #[cfg(feature = "non-fips")]
            Algorithm::RSA1024 => {
                rsa_algorithm(&mut attributes, 1024);
            }
            Algorithm::RSA2048 => {
                rsa_algorithm(&mut attributes, 2048);
            }
            Algorithm::RSA3072 => {
                rsa_algorithm(&mut attributes, 3072);
            }
            Algorithm::RSA4096 => {
                rsa_algorithm(&mut attributes, 4096);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::NistP192 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::EC,
                    RecommendedCurve::P192,
                );
            }
            Algorithm::NistP224 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::EC,
                    RecommendedCurve::P224,
                );
            }
            Algorithm::NistP256 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::EC,
                    RecommendedCurve::P256,
                );
            }
            Algorithm::NistP384 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::EC,
                    RecommendedCurve::P384,
                );
            }
            Algorithm::NistP521 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::EC,
                    RecommendedCurve::P521,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::Ed25519 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::Ed25519,
                    RecommendedCurve::CURVEED25519,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::Ed448 => {
                ec_algorithm(
                    &mut attributes,
                    CryptographicAlgorithm::Ed448,
                    RecommendedCurve::CURVEED448,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlDsa44 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLDSA_44);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlDsa65 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLDSA_65);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlDsa87 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLDSA_87);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2128s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_128s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2128f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_128f);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2192s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_192s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2192f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_192f);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2256s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_256s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaSha2256f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHA2_256f);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake128s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_128s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake128f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_128f);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake192s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_192s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake192f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_192f);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake256s => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_256s);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::SlhDsaShake256f => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::SLHDSA_SHAKE_256f);
            }
            // ML-KEM and hybrid KEM — used as subject key (must be CA-signed, not self-signed)
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem512 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLKEM_512);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem768 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLKEM_768);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem1024 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::MLKEM_1024);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::X25519MlKem768 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::X25519MLKEM768);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::X448MlKem1024 => {
                pqc_algorithm(&mut attributes, CryptographicAlgorithm::X448MLKEM1024);
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem512P256 => {
                configurable_kem_algorithm(
                    &mut attributes,
                    RecommendedCurve::P256,
                    CryptographicAlgorithm::MLKEM_512,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem768P256 => {
                configurable_kem_algorithm(
                    &mut attributes,
                    RecommendedCurve::P256,
                    CryptographicAlgorithm::MLKEM_768,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem512Curve25519 => {
                configurable_kem_algorithm(
                    &mut attributes,
                    RecommendedCurve::CURVE25519,
                    CryptographicAlgorithm::MLKEM_512,
                );
            }
            #[cfg(feature = "non-fips")]
            Algorithm::MlKem768Curve25519 => {
                configurable_kem_algorithm(
                    &mut attributes,
                    RecommendedCurve::CURVE25519,
                    CryptographicAlgorithm::MLKEM_768,
                );
            }
        }
    } else {
        return Err(UtilsError::Default(
            "Supply a certificate signing request, a public key id or an existing certificate id \
             or request a keypair to be generated"
                .to_owned(),
        ));
    }

    if let Some(extension_file) = certificate_extensions {
        attributes.set_x509_extension_file(vendor_id, extension_file.clone());
    }

    Ok(Certify {
        unique_identifier,
        attributes: Some(attributes),
        certificate_request_value,
        certificate_request_type,
        ..Certify::default()
    })
}

fn ec_algorithm(
    attributes: &mut Attributes,
    cryptographic_algorithm: CryptographicAlgorithm,
    recommended_curve: RecommendedCurve,
) {
    attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
    attributes.cryptographic_domain_parameters = Some(CryptographicDomainParameters {
        recommended_curve: Some(recommended_curve),
        ..CryptographicDomainParameters::default()
    });
    attributes.key_format_type = Some(KeyFormatType::ECPrivateKey);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

fn rsa_algorithm(attributes: &mut Attributes, cryptographic_length: i32) {
    attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::RSA);
    attributes.cryptographic_length = Some(cryptographic_length);
    attributes.cryptographic_domain_parameters = None;
    attributes.cryptographic_parameters = None;
    attributes.key_format_type = Some(KeyFormatType::TransparentRSAPrivateKey);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

#[cfg(feature = "non-fips")]
fn pqc_algorithm(attributes: &mut Attributes, cryptographic_algorithm: CryptographicAlgorithm) {
    attributes.cryptographic_algorithm = Some(cryptographic_algorithm);
    attributes.cryptographic_length = None;
    attributes.cryptographic_domain_parameters = None;
    attributes.cryptographic_parameters = None;
    attributes.key_format_type = Some(KeyFormatType::PKCS8);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

/// Set attributes for a `ConfigurableKEM` key pair (hybrid ML-KEM + classical curve).
/// Used when certifying a subject key that is a configurable hybrid KEM.
#[cfg(feature = "non-fips")]
fn configurable_kem_algorithm(
    attributes: &mut Attributes,
    recommended_curve: RecommendedCurve,
    kem_algorithm: CryptographicAlgorithm,
) {
    attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::ConfigurableKEM);
    attributes.cryptographic_length = None;
    attributes.cryptographic_domain_parameters = Some(CryptographicDomainParameters {
        recommended_curve: Some(recommended_curve),
        ..CryptographicDomainParameters::default()
    });
    attributes.cryptographic_parameters = Some(CryptographicParameters {
        cryptographic_algorithm: Some(kem_algorithm),
        ..CryptographicParameters::default()
    });
    attributes.key_format_type = Some(KeyFormatType::ConfigurableKEMSecretKey);
    attributes.object_type = Some(ObjectType::PrivateKey);
}

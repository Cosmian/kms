use clap::ValueEnum;
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
}

#[expect(clippy::too_many_arguments)]
pub fn build_certify_request(
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
    attributes.set_requested_validity_days(i32::try_from(number_of_days).map_err(|_e| {
        UtilsError::Default("number of days must be a positive integer".to_owned())
    })?);

    // A certificate id has been provided
    if let Some(certificate_id) = &certificate_id {
        attributes.unique_identifier = Some(UniqueIdentifier::TextString(certificate_id.clone()));
    }

    attributes.activation_date = Some(time_normalize()?);
    attributes.set_tags(tags)?;

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
        }
    } else {
        return Err(UtilsError::Default(
            "Supply a certificate signing request, a public key id or an existing certificate id \
             or request a keypair to be generated"
                .to_owned(),
        ));
    }

    if let Some(extension_file) = certificate_extensions {
        attributes.set_x509_extension_file(extension_file.clone());
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

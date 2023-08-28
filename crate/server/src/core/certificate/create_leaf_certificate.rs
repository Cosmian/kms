use std::{collections::HashSet, str::FromStr};

use cosmian_crypto_core::reexport::x509_cert::{builder::Profile, name::Name};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Certify, CertifyResponse},
    kmip_types::{CertificateType, RecommendedCurve},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::{
        certificate::attributes::{ca_from_attributes, subject_from_attributes},
        curve_25519::kmip_requests::ec_create_key_pair_request,
    },
    tagging::{check_user_tags, get_tags},
};
use tracing::{debug, trace};

use super::KMS;
use crate::{
    core::certificate::{
        build_public_key, ca_signing_key::CASigningKey, create_subca_certificate::create_ca_chain,
    },
    error::KmsError,
    result::KResult,
};

pub(crate) async fn create_certificate(
    request: &Certify,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    let attributes = request.attributes.as_ref().ok_or(KmsError::InvalidRequest(
        "Attributes are mandatory".to_string(),
    ))?;
    debug!("Certify attributes: {:?}", &attributes);

    // Check all required input elements from request
    // - tags
    // - ca name
    // - subject name

    // Retrieve and update tags
    let tags = get_tags(attributes);
    check_user_tags(&tags)?;

    // Get CA from attributes
    let ca = ca_from_attributes(attributes)?;
    trace!("CA on input: {:?}", &ca);

    // Get Subject CN from attributes
    let subject = subject_from_attributes(attributes)?;
    trace!("subject on input: {:?}", &subject);

    // Create the chain: CA and all subCAs (public key + certificate)
    trace!("Create the CA chain: {ca:?}");
    let last_ca_signing_key = create_ca_chain(&ca, &tags, kms, owner, params).await?;

    // Finally create the leaf certificate
    trace!("Last subCA (or CA): {ca}");
    create_leaf_certificate(&last_ca_signing_key, &subject, &tags, kms, owner, params).await
}

async fn create_leaf_certificate(
    last_ca_signing_key: &CASigningKey,
    subject: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    debug!("Creating Leaf certificate: {}", last_ca_signing_key.ca);
    let mut tags = tags.clone();
    tags.insert(format!("CA={}", last_ca_signing_key.ca));

    // Set certificate as a leaf certificate
    let profile = Profile::Leaf {
        issuer: Name::from_str(&format!("CN={}", last_ca_signing_key.ca)).map_err(|e| {
            KmsError::InvalidRequest(format!(
                "Leaf certificate error: cannot convert CA to Name: {e:?}",
            ))
        })?,
        enable_key_agreement: true,
        enable_key_encipherment: true,
    };

    // Build ca signing key pair
    debug!("Build key pair instance");
    let signer = last_ca_signing_key
        .build_key_pair(kms, owner, params)
        .await?;

    trace!("--> CA: {}, Subject: {subject}", last_ca_signing_key.ca);

    // By default, we recreate the crypto keypair when creating a new certificate
    let create_response = kms
        .create_key_pair(
            ec_create_key_pair_request(&tags, RecommendedCurve::CURVEED25519)?,
            owner,
            params,
        )
        .await?;

    let public_key = build_public_key(
        &create_response.public_key_unique_identifier,
        kms,
        owner,
        params,
    )
    .await?;

    debug!("new certificate: profile: {:?}", &profile);
    let certificate =
        cosmian_crypto_core::build_certificate(&signer, &public_key, profile, subject)?;

    let pem = certificate.to_pem()?;
    debug!("new certificate: pem: {pem}");

    // Save new certificate in database. Keep also the public key link. This link uses tags instead of a proper KMIP structure since KMIP Certificate structure does not support attribute.
    let object = Object::Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: pem.as_bytes().to_vec(),
    };
    debug!("certify: tags: {tags:?}");

    let uuid = kms
        .db
        .create(
            Some(certificate.uuid.to_string()),
            owner,
            &object,
            &tags,
            params,
        )
        .await?;
    debug!("Created KMS Object with id {uuid}",);

    Ok(CertifyResponse {
        unique_identifier: uuid,
    })
}

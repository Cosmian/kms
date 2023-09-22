use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    build_certificate_profile, X25519PublicKey, X25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::kmip_operations::{Certify, CertifyResponse};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::certificate::attributes::{
        ca_subject_common_names_from_attributes, subject_common_name_from_attributes,
    },
    tagging::{check_user_tags, get_tags},
};
use tracing::{debug, trace};

use super::KMS;
use crate::{
    core::certificate::{
        ca_signing_key::CASigningKey, create_ca_certificate::create_ca_chain,
        create_key_pair_and_certificate,
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

    // Get the full CA chain Subject Common Names separated by slashes.
    // If no CA/SubCA certificate exists, the KMS server will create them.
    // Example:
    // - "CA Root/Sub CA"
    // -> "CA Root" is the Subject Common Name of the root CA
    // -> "Sub CA" is the Subject Common Name of the intermediate CA
    let ca_subject_common_names = ca_subject_common_names_from_attributes(attributes)?;
    trace!(
        "CA Subject Common Names on input: {:?}",
        &ca_subject_common_names
    );

    // Get Subject CN from attributes for the desired future Certificate
    let subject = subject_common_name_from_attributes(attributes)?;
    trace!("subject on input: {:?}", &subject);

    // Create the chain: CA and all subCAs (public key + certificate)
    trace!("Create the CA chain is missing: {ca_subject_common_names:?}");
    let last_ca_signing_key =
        create_ca_chain(&ca_subject_common_names, &tags, kms, owner, params).await?;

    // Finally create the leaf certificate
    debug!(
        "Last subCA (or CA): {}",
        last_ca_signing_key.ca_subject_common_name
    );
    create_leaf_certificate(&last_ca_signing_key, &subject, &tags, kms, owner, params).await
}

async fn create_leaf_certificate(
    last_ca_signing_key: &CASigningKey,
    subject_common_name: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CertifyResponse> {
    debug!(
        "Creating Leaf certificate CN = {subject_common_name} and issuer {}",
        last_ca_signing_key.ca_subject_common_name
    );

    // Set certificate as a leaf certificate
    let profile =
        build_certificate_profile(&last_ca_signing_key.ca_subject_common_name, true, true)?;

    Ok(
        create_key_pair_and_certificate::<X25519PublicKey, X25519_PUBLIC_KEY_LENGTH>(
            subject_common_name,
            Some(last_ca_signing_key),
            profile,
            tags,
            false,
            kms,
            owner,
            params,
        )
        .await?
        .1,
    )
}

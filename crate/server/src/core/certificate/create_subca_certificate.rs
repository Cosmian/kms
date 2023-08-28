use std::{collections::HashSet, str::FromStr};

use cosmian_crypto_core::reexport::x509_cert::{builder::Profile, name::Name};
use cosmian_kmip::kmip::{
    kmip_objects::{Object, ObjectType},
    kmip_operations::Locate,
    kmip_types::{
        Attributes, CertificateType, CryptographicAlgorithm, KeyFormatType, RecommendedCurve,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::{
        certificate::attributes::ca_as_vendor_attribute,
        curve_25519::kmip_requests::ec_create_key_pair_request,
    },
    tagging::set_tags,
};
use tracing::debug;

use super::ca_signing_key::CASigningKey;
use crate::{
    core::{certificate::build_public_key, KMS},
    error::KmsError,
    result::KResult,
};

const KMS_CA: &str = "ca";

/// Locate all the user decryption keys associated with the master private key
/// and for the given policy attributes
async fn locate_ca_signing_key(
    ca: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Option<Vec<String>>> {
    // Convert the policy attributes to vendor attributes
    let vendor_attributes = Some(vec![ca_as_vendor_attribute(ca)?]);

    // Search the user decryption keys that need to be refreshed
    let mut search_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ECDH),
        key_format_type: Some(KeyFormatType::TransparentECPrivateKey),
        vendor_attributes,
        object_type: Some(ObjectType::PrivateKey),
        ..Attributes::default()
    };
    set_tags(&mut search_attributes, [KMS_CA, &format!("CA={ca}")])?;
    debug!("Search attributes: CA: {ca}");

    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::default()
    };
    let locate_response = kms.locate(locate_request, owner, params).await?;
    Ok(locate_response.unique_identifiers)
}

#[allow(clippy::too_many_arguments)]
async fn _create_ca(
    ca: &str,
    ca_signing_key: Option<CASigningKey>,
    subca: &str,
    profile: &Profile,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    let mut tags = tags.clone();
    tags.insert(KMS_CA.to_string());

    match profile {
        Profile::Root => {
            debug!("Creating Root CA certificate: {ca}",);
            tags.insert(format!("CA={ca}"));
        }
        _ => {
            debug!("Creating SubCA certificate: {subca}",);
            tags.insert(format!("CA={subca}"));
            tags.insert(format!("CA_parent={ca}"));
        }
    };

    // Let's create the key pair for the CA or subCA
    let create_response = kms
        .create_key_pair(
            ec_create_key_pair_request(&tags, RecommendedCurve::CURVEED25519)?,
            owner,
            params,
        )
        .await?;

    // Create the key pair instance in case of a Root CA
    // Otherwise, take the one in argument
    let signing_key = match profile {
        Profile::Root => (
            CASigningKey::new(
                ca,
                &create_response.private_key_unique_identifier,
                &create_response.public_key_unique_identifier,
            )
            .await?,
            ca,
            create_response.public_key_unique_identifier,
        ),
        _ => (
            ca_signing_key.expect("expected CA signing key here"),
            subca,
            create_response.public_key_unique_identifier,
        ),
    };

    let public_key = build_public_key(&signing_key.2, kms, owner, params).await?;

    // Build ca signing key pair
    debug!("Build key pair instance");
    let signer = signing_key.0.build_key_pair(kms, owner, params).await?;

    debug!("new certificate: profile: {:?}", &profile);
    let certificate = cosmian_crypto_core::build_certificate(
        &signer,
        &public_key,
        profile.clone(),
        signing_key.1,
    )
    .map_err(|e| KmsError::InvalidRequest(format!("Build CA certificate failed: {e}")))?;

    let pem = certificate
        .to_pem()
        .map_err(|e| KmsError::InvalidRequest(format!("Generate PEM failed: {e}")))?;
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
    debug!("Certificate created with identifier: {uuid}");

    Ok(signing_key.0)
}

async fn create_root_ca(
    ca: &str,
    profile: &Profile,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    _create_ca(ca, None, "", profile, tags, kms, owner, params).await
}

#[allow(clippy::too_many_arguments)]
async fn create_subca(
    ca: &str,
    ca_signing_key: CASigningKey,
    subca: &str,
    profile: &Profile,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    _create_ca(
        ca,
        Some(ca_signing_key),
        subca,
        profile,
        tags,
        kms,
        owner,
        params,
    )
    .await
}

async fn locate_or_create_ca_signing_key(
    ca: &str,
    subca: Option<&str>,
    profile: &Profile,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    // Find CA signing key
    let signing_keys_uids = locate_ca_signing_key(ca, kms, owner, params).await?;

    let Some(signing_keys_uids) = signing_keys_uids else {
        return create_root_ca(ca, profile, tags, kms, owner, params).await
    };

    match signing_keys_uids.len() {
        0 if matches!(profile, Profile::Root) => {
            create_root_ca(ca, profile, tags, kms, owner, params).await
        }
        0 => Err(KmsError::ConversionError(format!(
            "Internal error: Profile root expected here for this CA: {ca}",
        ))),
        1 => {
            let signing_key_uid = signing_keys_uids
                .first()
                .expect("first with non-zero length");
            debug!(
                "Found signing key matching CA name ({ca}) with unique identifier: \
                 {signing_key_uid}",
            );

            let ca_signing_key =
                CASigningKey::from_private_key_uid(ca, signing_key_uid, kms, owner, params).await?;

            let Some(subca) = subca else {
                return Ok(ca_signing_key)
            };

            let Some(subca_signing_keys_uids) =
                locate_ca_signing_key(subca, kms, owner, params).await?
            else {
                return create_subca(ca, ca_signing_key, subca, profile, tags, kms, owner, params)
                    .await
            };

            match subca_signing_keys_uids.len() {
                0 => {
                    create_subca(ca, ca_signing_key, subca, profile, tags, kms, owner, params).await
                }
                1 => {
                    let signing_key_uid = subca_signing_keys_uids
                        .first()
                        .expect("first with non-zero length");
                    debug!("Found signing key UID: {signing_key_uid} matching CA {subca}",);

                    CASigningKey::from_private_key_uid(subca, signing_key_uid, kms, owner, params)
                        .await
                }
                _ => Err(KmsError::ConversionError(format!(
                    "Internal error: more than 1 signing key for this SubCA: {ca}",
                ))),
            }
        }
        _ => Err(KmsError::ConversionError(format!(
            "Internal error: more than 1 signing key for this CA: {ca}",
        ))),
    }
}

pub(crate) async fn create_ca_chain(
    ca: &str,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<CASigningKey> {
    // Split all CA and subCAs
    let cas = ca.split('/').collect::<Vec<_>>();
    let mut last_ca_signing_key = CASigningKey::default();

    // in this loop the condition could be removed with the help of `Iterator::advance_by`
    // see: https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.advance_by
    for (index, current_ca) in cas.iter().enumerate() {
        if index == 0 {
            debug!("[0]: Creating the root CA certificate: CA: {current_ca}");
            last_ca_signing_key = locate_or_create_ca_signing_key(
                current_ca,
                None,
                &Profile::Root,
                tags,
                kms,
                owner,
                params,
            )
            .await?;
        } else {
            let ca = &cas[index - 1];
            debug!("[{index}]: Creating the subCA certificate: CA: {ca}, subCA: {current_ca}");
            let profile = Profile::SubCA {
                issuer: Name::from_str(&format!("CN={ca}")).map_err(|e| {
                    KmsError::InvalidRequest(format!(
                        "SubCA certificate error: cannot convert CA {ca} to Name: {e:?}",
                    ))
                })?,
                path_len_constraint: None,
            };

            last_ca_signing_key = locate_or_create_ca_signing_key(
                ca,
                Some(current_ca),
                &profile,
                tags,
                kms,
                owner,
                params,
            )
            .await?;
        }
    }

    debug!("Return from create_ca_chain: {last_ca_signing_key:?}");

    Ok(last_ca_signing_key)
}

use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    build_certificate,
    reexport::{pkcs8::EncodePublicKey, x509_cert::builder::Profile},
    FixedSizeCBytes,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{CertifyResponse, CreateKeyPairResponse, Get},
    kmip_types::{CertificateType, RecommendedCurve},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams, crypto::curve_25519::kmip_requests::ec_create_key_pair_request,
};
use tracing::{debug, trace};

use self::ca_signing_key::CASigningKey;
use super::KMS;
use crate::{
    core::certificate::create_ca_certificate::{
        locate_ca_certificate, locate_ca_certificate_by_spki,
    },
    error::KmsError,
    result::KResult,
};

pub const DEFAULT_EXPIRATION_TIME: u64 = 6;

pub(crate) mod ca_signing_key;
pub(crate) mod create_ca_certificate;
pub(crate) mod create_leaf_certificate;
pub(crate) mod parsing;
pub(crate) mod verify;

async fn get_fixed_size_key_bytes<const LENGTH: usize>(
    unique_identifier: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<[u8; LENGTH]> {
    let bytes = kms
        .get(Get::from(unique_identifier), owner, params)
        .await?
        .object
        .key_block()?
        .key_bytes()?;
    let fixed_size_array: [u8; LENGTH] = bytes[..].try_into()?;
    Ok(fixed_size_array)
}

async fn get_public_key<PublicKey, const LENGTH: usize>(
    public_key_uid: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<PublicKey>
where
    PublicKey: FixedSizeCBytes<LENGTH>,
{
    trace!("Getting public key bytes in order to create new instance");
    let public_key_array = get_fixed_size_key_bytes(public_key_uid, kms, owner, params).await?;
    let public_key = PublicKey::try_from_bytes(public_key_array).map_err(|e| {
        KmsError::ConversionError(format!("X25519/Ed25519 Public key from bytes failed: {e}"))
    })?;
    Ok(public_key)
}

async fn locate_by_common_name_and_get_certificate_bytes(
    ca: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    // From the issuer name, recover the KMIP certificate object
    let certificate_id = locate_ca_certificate(ca, kms, owner, params).await?;
    debug!("Certificate identifier: {}", certificate_id);
    let get_response = kms.get(Get::from(certificate_id), owner, params).await?;
    match get_response.object {
        Object::Certificate {
            certificate_value, ..
        } => Ok(certificate_value),
        _ => Err(KmsError::Certificate(
            "Invalid object type: Expected Certificate".to_string(),
        )),
    }
}

async fn locate_by_spki_and_get_certificate_bytes(
    ca_subject_name: &str,
    spki: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Vec<u8>> {
    // From the issuer name, recover the KMIP certificate object
    let certificate_id =
        locate_ca_certificate_by_spki(ca_subject_name, spki, kms, owner, params).await?;
    debug!("Certificate identifier: {}", certificate_id);
    let get_response = kms.get(Get::from(certificate_id), owner, params).await?;
    match get_response.object {
        Object::Certificate {
            certificate_value, ..
        } => Ok(certificate_value),
        _ => Err(KmsError::Certificate(
            "Invalid object type: Expected Certificate".to_string(),
        )),
    }
}

/// The function `link_key_pair_to_certificate` links an existing private/public key
/// pair with a certificate by updating the key objects in a key management system
/// (KMS) database.
///
/// Arguments:
///
/// * `certificate_uid`: A unique identifier for the certificate.
/// * `create_key_pair_response`: The `create_key_pair_response` parameter is used to retrieve the unique identifiers of
/// the private and public keys that were created when generating the key pair.
/// These unique identifiers are needed to link the key pair with the certificate.
/// * `tags`: The `tags` parameter is a `HashSet` of strings that represents the tags
/// associated with the key pair and certificate. These tags are used to identify
/// and categorize the key pair and certificate in the Key Management System (KMS)
/// database.
/// * `kms`: The `kms` object represents the Key Management Service. It is used to perform operations
/// related to key management, such as retrieving keys and updating key objects in a
/// database.
/// * `owner`: The `owner` parameter is a string that represents the owner of the
/// key pair and certificate. It is used to specify the owner when making requests
/// to the Key Management Service (KMS) and the database.
/// * `params`: The `params` parameter is an optional `ExtraDatabaseParams` struct
/// that contains additional parameters for the database update operation. It is
/// passed to the `kms.db.update_object()` function.
///
/// Returns:
///
/// Nothing
async fn link_key_pair_to_certificate(
    certificate_uid: &str,
    create_key_pair_response: &CreateKeyPairResponse,
    tags: &HashSet<String>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let mut tags = tags.clone();
    tags.insert(format!("_cert_uid={certificate_uid}"));
    debug!(
        "Link existing private/public key with certificate uuid: {certificate_uid} using tags: \
         {tags:?}"
    );
    let private_key_block = kms
        .get(
            Get::from(&create_key_pair_response.private_key_unique_identifier),
            owner,
            params,
        )
        .await?
        .object
        .key_block()?
        .clone();

    // Update private key object
    let private_key_object = Object::PrivateKey {
        key_block: private_key_block,
    };
    kms.db
        .update_object(
            &create_key_pair_response.private_key_unique_identifier,
            &private_key_object,
            Some(&tags),
            params,
        )
        .await?;

    let public_key_block = kms
        .get(
            Get::from(&create_key_pair_response.public_key_unique_identifier),
            owner,
            params,
        )
        .await?
        .object
        .key_block()?
        .clone();

    // Update public key object
    let public_key_object = Object::PublicKey {
        key_block: public_key_block,
    };
    kms.db
        .update_object(
            &create_key_pair_response.public_key_unique_identifier,
            &public_key_object,
            Some(&tags),
            params,
        )
        .await?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// This whole-in-one function generates a key pair and a
/// certificate, and saves them in a database.
///
/// Arguments:
///
/// * `subject_common_name`: The `subject_common_name` parameter is a string that
/// represents the common name (CN) attribute of the subject in the certificate. It
/// is typically used to identify the entity (e.g., a person or a server) for which
/// the certificate is issued.
/// * `ca_signing_key`: The `ca_signing_key` parameter is an optional reference to a
/// `CASigningKey` object. It represents the signing key used for certificate
/// authority (CA) operations. If the `profile` is `Profile::Root`, a new CA signing
/// key pair is created using the provided `subject
/// * `profile`: The `profile` parameter is of type `Profile` and represents the
/// type of certificate profile to be used. It can have one of the following values:
/// * `tags`: The `tags` parameter is a reference to a `HashSet<String>` that
/// contains tags associated with the key pair and certificate. Tags are used to
/// categorize and organize objects in the database.
/// * `is_ca`: A boolean flag indicating whether the certificate being created is a
/// CA (Certificate Authority) certificate.
/// * `kms`: The `kms` parameter is an instance of the `KMS` struct, which
/// represents a Key Management System. It is used to interact with the KMS and
/// perform operations such as creating key pairs, signing certificates, and storing
/// objects in the KMS database.
/// * `owner`: The `owner` parameter represents the owner of the key pair and
/// certificate. It is a string that identifies the owner or entity that will have
/// control over the generated key pair and certificate.
/// * `params`: The `params` parameter is an optional reference to
/// `ExtraDatabaseParams`. It is used to provide additional parameters for creating
/// the key pair and certificate in the database.
///
/// Returns:
///
/// a tuple containing two values: a `CreateKeyPairResponse` and a
/// `CertifyResponse`.
async fn create_key_pair_and_certificate<PublicKey, const LENGTH: usize>(
    subject_common_name: &str,
    ca_signing_key: Option<&CASigningKey>,
    profile: Profile,
    tags: &HashSet<String>,
    is_ca: bool,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<(CreateKeyPairResponse, CertifyResponse)>
where
    PublicKey: FixedSizeCBytes<LENGTH> + EncodePublicKey,
{
    let recommended_curve = if is_ca {
        RecommendedCurve::CURVEED25519
    } else {
        RecommendedCurve::CURVE25519
    };

    // By default, we recreate the crypto keypair when creating a new certificate
    let create_response = kms
        .create_key_pair(
            ec_create_key_pair_request(tags, recommended_curve)?,
            owner,
            params,
        )
        .await?;
    debug!("Build key pair {create_response:?}");

    let public_key = get_public_key::<PublicKey, LENGTH>(
        &create_response.public_key_unique_identifier,
        kms,
        owner,
        params,
    )
    .await?;

    // Build ca signing key pair
    let (signing_key, issuer) = if matches!(profile, Profile::Root) {
        // Build ca signing key pair
        (
            CASigningKey::new(
                subject_common_name,
                &create_response.private_key_unique_identifier,
                &create_response.public_key_unique_identifier,
            )
            .key_pair(kms, owner, params)
            .await?,
            subject_common_name,
        )
    } else {
        let ca_signing_key = ca_signing_key.ok_or(KmsError::InvalidRequest(
            "CA Signing key is MANDATORY".to_string(),
        ))?;
        (
            ca_signing_key.key_pair(kms, owner, params).await?,
            ca_signing_key.ca_subject_common_name.as_str(),
        )
    };

    let certificate = build_certificate::<PublicKey>(
        &signing_key,
        &public_key,
        profile.clone(),
        subject_common_name,
        DEFAULT_EXPIRATION_TIME,
    )?;

    let pem = certificate.to_pem()?;
    debug!("new certificate: pem: {pem} with profile: {:?}", &profile);

    // Save new certificate in database. Keep also link with key pair. This link uses tags instead of a proper KMIP structure since KMIP Certificate structure does not support attribute.
    let object = Object::Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: pem.as_bytes().to_vec(),
    };

    let mut cert_tags = tags.clone();
    if is_ca {
        cert_tags.insert(format!("_ca_parent={issuer}"));
        cert_tags.insert(format!("_ca={subject_common_name}"));
    }
    let key_pair_tags = cert_tags.clone();
    cert_tags.insert("_cert".to_string());
    cert_tags.insert(format!("_cert_spki={}", hex::encode(certificate.spki()?)));

    let certificate_uid = kms
        .db
        .create(
            Some(certificate.uuid.to_string()),
            owner,
            &object,
            &cert_tags,
            params,
        )
        .await?;
    debug!("Created KMS Object with id {certificate_uid} with tags: {cert_tags:?}");

    link_key_pair_to_certificate(
        &certificate_uid,
        &create_response,
        &key_pair_tags,
        kms,
        owner,
        params,
    )
    .await?;

    Ok((
        create_response,
        CertifyResponse {
            unique_identifier: certificate_uid,
        },
    ))
}

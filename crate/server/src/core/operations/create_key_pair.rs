use cosmian_kms_server_database::reexport::cosmian_kmip::time_normalize;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::kem::kem_keygen;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::reexport::cosmian_cover_crypt::api::Covercrypt;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::operation::{
    create_secp_key_pair, create_x448_key_pair, create_x25519_key_pair
};
use cosmian_kms_server_database::reexport::{cosmian_kmip, cosmian_kms_crypto::crypto::{
    elliptic_curves::operation::{
        create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair
    }, rsa::operation::create_rsa_key_pair, KeyPair
}};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::{ cosmian_kms_crypto::crypto::{
    cover_crypt::master_keys::create_master_keypair
}};
use cosmian_kms_server_database::reexport::cosmian_kms_interfaces::{AtomicOperation};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::State::{Active,PreActive};
#[cfg(feature = "non-fips")]
use cosmian_logger::warn;
use cosmian_logger::{debug, info, trace};
use uuid::Uuid;
use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission, wrapping::wrap_and_cache},
    error::KmsError,
    kms_bail,
    result::KResult,
};
use crate::core::operations::digest::digest;

pub(crate) async fn create_key_pair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &str,
    privileged_users: Option<Vec<String>>,
) -> KResult<CreateKeyPairResponse> {
    debug!("Create key pair: {request}");

    // To create a key pair, check that the user has `Create` access right
    // The `Create` right implicitly grants permission for Create, Import, and Register operations.
    if let Some(users) = privileged_users {
        let has_permission = user_has_permission(
            owner,
            None,
            &cosmian_kmip::kmip_2_1::KmipOperation::Create,
            kms,
        )
        .await?;

        if !has_permission && !users.iter().any(|u| u == owner) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    if request.common_protection_storage_masks.is_some()
        || request.private_protection_storage_masks.is_some()
        || request.public_protection_storage_masks.is_some()
    {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // generate uids and create the key pair and tags
    let sk_uid = request
        .private_key_attributes
        .as_ref() // Convert Option to Option reference
        .and_then(|attrs| attrs.unique_identifier.as_ref()) // Safely access unique_identifier
        .map_or_else(
            || Uuid::new_v4().to_string(),
            std::string::ToString::to_string,
        );
    let pk_uid = sk_uid.clone() + "_pk";
    // Capture requested ActivationDate values BEFORE moving the request into key generation
    // Private key: prefer private_key_attributes.activation_date then fallback to common_attributes.activation_date
    let requested_sk_activation_date = request
        .private_key_attributes
        .as_ref()
        .and_then(|att| att.activation_date)
        .or_else(|| {
            request
                .common_attributes
                .as_ref()
                .and_then(|att| att.activation_date)
        });
    // Public key: prefer activation_date then fallback to common_attributes.activation_date
    let requested_pk_activation_date = request
        .public_key_attributes
        .as_ref()
        .and_then(|att| att.activation_date)
        .or_else(|| {
            request
                .common_attributes
                .as_ref()
                .and_then(|att| att.activation_date)
        });

    let key_pair = generate_key_pair(request, &sk_uid, &pk_uid)?;

    trace!("sk_uid: {sk_uid}, pk_uid: {pk_uid}");
    let now = time_normalize()?;

    let mut private_key = key_pair.private_key().to_owned();
    // Set lifecycle fields and copy the attributes before the key gets wrapped
    let private_key_attributes = {
        let digest = digest(&private_key)?;
        let attributes = private_key.attributes_mut()?;
        // Determine State based on requested InitialDate or ActivationDate (if provided)
        let activation_allows_active = requested_sk_activation_date.is_some_and(|d| d <= now);
        let state = if activation_allows_active {
            Active
        } else {
            PreActive
        };
        attributes.state = Some(state);
        // update the digest
        attributes.digest = digest;
        // Set InitialDate only if provided in the request (no auto-setting)
        attributes.initial_date = Some(now);
        // Set ActivationDate only if provided in the request (no auto-setting)
        if state == Active {
            attributes.activation_date = Some(now);
        }

        // Ensure ObjectType is set for private key
        attributes.object_type = Some(ObjectType::PrivateKey);
        // update original creation date
        attributes.original_creation_date = Some(now);
        // update the last change date
        attributes.last_change_date = Some(now);
        attributes.clone()
    };
    trace!(
        "Private key attributes after lifecycle update: {}",
        private_key_attributes
    );
    let private_key_tags = private_key_attributes.get_tags();
    let cryptographic_algorithm = private_key_attributes.cryptographic_algorithm;

    Box::pin(wrap_and_cache(
        kms,
        owner,
        &UniqueIdentifier::TextString(sk_uid.clone()),
        &mut private_key,
    ))
    .await?;

    let mut public_key = key_pair.public_key().to_owned();
    // Set lifecycle fields and copy the attributes before the key gets wrapped
    let public_key_attributes = {
        let digest = digest(&public_key)?;
        let attributes = public_key.attributes_mut()?;
        // Determine State based on requested InitialDate or ActivationDate (if provided)
        let activation_allows_active = requested_pk_activation_date.is_some_and(|d| d <= now);
        let state = if activation_allows_active {
            Active
        } else {
            PreActive
        };
        attributes.state = Some(state);
        // update the digest
        attributes.digest = digest;
        // Set InitialDate only if provided in the request (no auto-setting)
        // Zero milliseconds for KMIP serialization compatibility
        let now_stored = time_normalize()?;
        attributes.initial_date = Some(now_stored);
        // Set ActivationDate only if provided in the request (no auto-setting)
        if state == Active {
            attributes.activation_date = Some(now_stored);
        }
        // Ensure ObjectType is set for public key
        attributes.object_type = Some(ObjectType::PublicKey);
        // update original creation date
        attributes.original_creation_date = Some(now);
        // update the last change date
        attributes.last_change_date = Some(now);
        attributes.clone()
    };
    trace!(
        "Public key attributes after lifecycle update: {}",
        public_key_attributes
    );
    let public_key_tags = public_key_attributes.get_tags();
    Box::pin(wrap_and_cache(
        kms,
        owner,
        &UniqueIdentifier::TextString(pk_uid.clone()),
        &mut public_key,
    ))
    .await?;

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            private_key.clone(),
            private_key_attributes,
            private_key_tags,
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            public_key.clone(),
            public_key_attributes,
            public_key_tags,
        )),
    ];
    let ids = kms.database.atomic(owner, &operations).await?;

    let sk_uid = ids
        .first()
        .ok_or_else(|| KmsError::ServerError("Private key id not available".to_owned()))?;
    let pk_uid = ids
        .get(1)
        .ok_or_else(|| KmsError::ServerError("Public key id not available".to_owned()))?;

    info!(
        uid = sk_uid,
        user = owner,
        "Created Key Pair with cryptographic algorithm {:?}",
        cryptographic_algorithm
    );

    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(sk_uid.to_owned()),
        public_key_unique_identifier: UniqueIdentifier::TextString(pk_uid.to_owned()),
    })
}

/// Generate a key pair and the corresponding system tags.
/// Generate FIPS-140-3 compliant Key Pair for key agreement and digital signature.
///
/// Sources:
/// - NIST.SP.800-56Ar3 - Appendix D.
/// - NIST.SP.800-186 - Section 3.1.2 table 2.
///
/// The tags will contain the user tags and the following:
///  - "_sk" for the private key
///  - "_pk" for the public key
///  - the KMIP cryptographic algorithm in lower case prepended with "_"
///
/// Only Covercrypt master keys can be created using this function
pub(super) fn generate_key_pair(
    request: CreateKeyPair,
    private_key_uid: &str,
    public_key_uid: &str,
) -> KResult<KeyPair> {
    trace!("Internal create key pair");

    let common_attributes = request.common_attributes.unwrap_or_default();

    // Check that the cryptographic algorithm is specified.
    let cryptographic_algorithm =
        if let Some(cryptographic_algorithm) = &common_attributes.cryptographic_algorithm {
            *cryptographic_algorithm
        } else if let Some(cryptographic_algorithm) = &request
            .private_key_attributes
            .as_ref()
            .and_then(|att| att.cryptographic_algorithm)
        {
            *cryptographic_algorithm
        } else if let Some(cryptographic_algorithm) = &request
            .public_key_attributes
            .as_ref()
            .and_then(|att| att.cryptographic_algorithm)
        {
            *cryptographic_algorithm
        } else {
            kms_bail!(KmsError::InvalidRequest(
                "the cryptographic algorithm must be specified for key pair creation".to_owned()
            ))
        };

    trace!("cryptographic_algorithm: {cryptographic_algorithm}");

    // Generate the key pair based on the cryptographic algorithm.
    let key_pair = match cryptographic_algorithm {
        // EC, ECDSA and ECDH possess the same FIPS restrictions for curves.
        CryptographicAlgorithm::EC
        | CryptographicAlgorithm::ECDH
        | CryptographicAlgorithm::ECDSA => {
            let domain_parameters = common_attributes
                .cryptographic_domain_parameters
                .unwrap_or_default();
            let curve = domain_parameters.recommended_curve.unwrap_or_default();
            trace!("curve: {curve}");
            match curve {
                #[cfg(feature = "non-fips")]
                // Generate a P-192 Key Pair. Not FIPS-140-3 compliant. **This curve is for
                // legacy-use only** as it provides less than 112 bits of security.
                //
                // Sources:
                // - NIST.SP.800-186 - Section 3.2.1.1
                RecommendedCurve::P192 => create_approved_ecc_key_pair(
                    private_key_uid,
                    public_key_uid,
                    curve,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                RecommendedCurve::P224
                | RecommendedCurve::P256
                | RecommendedCurve::P384
                | RecommendedCurve::P521 => create_approved_ecc_key_pair(
                    private_key_uid,
                    public_key_uid,
                    curve,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::SECP224K1 | RecommendedCurve::SECP256K1 => create_secp_key_pair(
                    private_key_uid,
                    public_key_uid,
                    curve,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::CURVE25519 => create_x25519_key_pair(
                    private_key_uid,
                    public_key_uid,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::CURVE448 => create_x448_key_pair(
                    private_key_uid,
                    public_key_uid,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                RecommendedCurve::CURVEED25519 => {
                    #[cfg(not(feature = "non-fips"))]
                    // Ed25519 not allowed for ECDH nor ECDSA.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    {
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             Elliptic Curves operations in FIPS mode"
                                .to_owned()
                        ))
                    }
                    #[cfg(feature = "non-fips")]
                    {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                            || cryptographic_algorithm == CryptographicAlgorithm::ECDH
                            || cryptographic_algorithm == CryptographicAlgorithm::EC
                        {
                            kms_bail!(KmsError::NotSupported(
                                "Edwards curve can't be created for EC or ECDSA".to_owned()
                            ))
                        }
                        warn!(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed25519_key_pair(
                            private_key_uid,
                            public_key_uid,
                            common_attributes,
                            request.private_key_attributes,
                            request.public_key_attributes,
                        )
                    }
                }
                RecommendedCurve::CURVEED448 => {
                    #[cfg(not(feature = "non-fips"))]
                    {
                        // Ed448 not allowed for ECDH nor ECDSA.
                        // see NIST.SP.800-186 - Section 3.1.2 table 2.
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             Elliptic Curves operations in FIPS mode"
                                .to_owned()
                        ))
                    }
                    #[cfg(feature = "non-fips")]
                    {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                            || cryptographic_algorithm == CryptographicAlgorithm::EC
                            || cryptographic_algorithm == CryptographicAlgorithm::ECDH
                        {
                            kms_bail!(KmsError::NotSupported(
                                "Edwards curve can't be created for EC or ECDSA".to_owned()
                            ))
                        }
                        warn!(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             ECDH. Creating anyway."
                        );
                        create_ed448_key_pair(
                            private_key_uid,
                            public_key_uid,
                            common_attributes,
                            request.private_key_attributes,
                            request.public_key_attributes,
                        )
                    }
                }

                other => kms_bail!(KmsError::NotSupported(format!(
                    "Generation of Key Pair for curve: {other:?}, is not supported"
                ))),
            }
        }
        CryptographicAlgorithm::RSA => {
            let key_size_in_bits = u32::try_from(
                common_attributes
                    .cryptographic_length
                    .ok_or_else(|| KmsError::InvalidRequest("RSA key size: error".to_owned()))?,
            )?;
            debug!("RSA key pair generation: size in bits: {key_size_in_bits}");

            create_rsa_key_pair(
                private_key_uid,
                public_key_uid,
                common_attributes,
                request.private_key_attributes,
                request.public_key_attributes,
            )
        }
        CryptographicAlgorithm::Ed25519 => create_ed25519_key_pair(
            private_key_uid,
            public_key_uid,
            common_attributes,
            request.private_key_attributes,
            request.public_key_attributes,
        ),
        CryptographicAlgorithm::Ed448 => create_ed448_key_pair(
            private_key_uid,
            public_key_uid,
            common_attributes,
            request.private_key_attributes,
            request.public_key_attributes,
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::ConfigurableKEM => kem_keygen(
            private_key_uid.to_owned(),
            request.private_key_attributes,
            public_key_uid.to_owned(),
            request.public_key_attributes,
            common_attributes,
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::CoverCrypt => {
            let sensitive = request
                .private_key_attributes
                .as_ref()
                .or(Some(&common_attributes))
                .and_then(|att| att.sensitive)
                .unwrap_or_default();

            create_master_keypair(
                &Covercrypt::default(),
                private_key_uid.to_owned(),
                public_key_uid,
                common_attributes,
                request.private_key_attributes,
                request.public_key_attributes,
                sensitive,
            )
        }
        other => {
            kms_bail!(KmsError::NotSupported(format!(
                "The creation of a keypair for algorithm: {other:?} is not supported"
            )))
        }
    }?;
    Ok(key_pair)
}

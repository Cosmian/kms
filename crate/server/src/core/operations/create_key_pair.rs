use std::sync::Arc;

use cosmian_cover_crypt::api::Covercrypt;
use cosmian_kmip::kmip_2_1::{
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
};
#[cfg(not(feature = "fips"))]
use cosmian_kms_crypto::crypto::elliptic_curves::operation::{
    create_x25519_key_pair, create_x448_key_pair,
};
use cosmian_kms_crypto::crypto::{
    cover_crypt::master_keys::create_master_keypair,
    elliptic_curves::operation::{
        create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair,
    },
    rsa::operation::create_rsa_key_pair,
    KeyPair,
};
use cosmian_kms_interfaces::{AtomicOperation, SessionParams};
#[cfg(not(feature = "fips"))]
use tracing::warn;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

pub(crate) async fn create_key_pair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<CreateKeyPairResponse> {
    trace!("Create key pair: {}", serde_json::to_string(&request)?);

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
    let key_pair = generate_key_pair(request, &sk_uid, &pk_uid)?;

    trace!("create_key_pair: sk_uid: {sk_uid}, pk_uid: {pk_uid}");

    let private_key_attributes = key_pair.private_key().attributes()?.clone();
    let public_key_attributes = key_pair.public_key().attributes()?.clone();

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            key_pair.private_key().to_owned(),
            private_key_attributes,
            key_pair.private_key().attributes()?.get_tags(),
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            key_pair.public_key().to_owned(),
            public_key_attributes,
            key_pair.public_key().attributes()?.get_tags(),
        )),
    ];
    let ids = kms.database.atomic(owner, &operations, params).await?;

    let sk_uid = ids
        .first()
        .ok_or_else(|| KmsError::ServerError("Private key id not available".to_owned()))?;
    let pk_uid = ids
        .get(1)
        .ok_or_else(|| KmsError::ServerError("Public key id not available".to_owned()))?;
    debug!("Created key pair: sk: {sk_uid}, pk: {pk_uid}");
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
pub(crate) fn generate_key_pair(
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

            match curve {
                #[cfg(not(feature = "fips"))]
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
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVE25519 => create_x25519_key_pair(
                    private_key_uid,
                    public_key_uid,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                #[cfg(not(feature = "fips"))]
                RecommendedCurve::CURVE448 => create_x448_key_pair(
                    private_key_uid,
                    public_key_uid,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                RecommendedCurve::CURVEED25519 => {
                    #[cfg(feature = "fips")]
                    // Ed25519 not allowed for ECDH nor ECDSA.
                    // see NIST.SP.800-186 - Section 3.1.2 table 2.
                    {
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 25519 should not be requested to perform \
                             Elliptic Curves operations in FIPS mode"
                                .to_owned()
                        ))
                    }
                    #[cfg(not(feature = "fips"))]
                    {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
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
                    #[cfg(feature = "fips")]
                    {
                        // Ed448 not allowed for ECDH nor ECDSA.
                        // see NIST.SP.800-186 - Section 3.1.2 table 2.
                        kms_bail!(KmsError::NotSupported(
                            "An Edwards Keypair on curve 448 should not be requested to perform \
                             Elliptic Curves operations in FIPS mode"
                                .to_owned()
                        ))
                    }
                    #[cfg(not(feature = "fips"))]
                    {
                        if cryptographic_algorithm == CryptographicAlgorithm::ECDSA
                            || cryptographic_algorithm == CryptographicAlgorithm::EC
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
        CryptographicAlgorithm::CoverCrypt => create_master_keypair(
            &Covercrypt::default(),
            private_key_uid.to_owned(),
            public_key_uid,
            common_attributes,
            request.private_key_attributes,
            request.public_key_attributes,
            sensitive,
        ),
        other => {
            kms_bail!(KmsError::NotSupported(format!(
                "The creation of a keypair for algorithm: {other:?} is not supported"
            )))
        }
    }?;
    Ok(key_pair)
}

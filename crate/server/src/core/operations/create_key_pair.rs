#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::kem::kem_keygen;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::{
    hybrid_kem::create_hybrid_kem_key_pair, ml_dsa::create_ml_dsa_key_pair,
    ml_kem::create_ml_kem_key_pair, slh_dsa::create_slh_dsa_key_pair,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::reexport::cosmian_cover_crypt::api::Covercrypt;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::elliptic_curves::operation::{
    create_secp_key_pair, create_x448_key_pair, create_x25519_key_pair
};
use cosmian_kms_server_database::reexport::{cosmian_kms_crypto::crypto::{
    elliptic_curves::operation::{
        EcKeySpec, create_approved_ecc_key_pair, create_ed25519_key_pair, create_ed448_key_pair
    }, rsa::operation::create_rsa_key_pair, KeyPair, KeyPairIdentity
}};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::{ cosmian_kms_crypto::crypto::{
    cover_crypt::master_keys::create_master_keypair
}};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::KmsRng;
use cosmian_kms_server_database::reexport::cosmian_kms_interfaces::{AtomicOperation};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::kmip_attributes::Attributes,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    extra::tagging::SYSTEM_TAG_PUBLIC_KEY,
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse},
    kmip_types::{CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
};
#[cfg(feature = "non-fips")]
use cosmian_logger::warn;
use cosmian_logger::{debug, info, trace};
use uuid::Uuid;
use crate::middlewares::UserId;
use crate::{
    core::{KMS, uid_utils::ObjectHandle, wrapping::wrap_and_cache},
    error::KmsError,
    kms_bail,
    result::KResult,
};
use super::key_ops::ObjectLifecycleExt;

pub(crate) async fn create_key_pair(
    kms: &KMS,
    request: CreateKeyPair,
    owner: &UserId,
) -> KResult<CreateKeyPairResponse> {
    debug!("CreateKeyPair request");

    KMS::reject_protection_storage_masks(
        request.common_protection_storage_masks.is_some()
            || request.private_protection_storage_masks.is_some()
            || request.public_protection_storage_masks.is_some(),
    )?;
    kms.enforce_create_permission(owner).await?;

    // generate uids and create the key pair and tags
    let sk_uid = request
        .private_key_attributes
        .as_ref() // Convert Option to Option reference
        .and_then(|attrs| attrs.unique_identifier.as_ref()) // Safely access unique_identifier
        .map_or_else(
            || Uuid::new_v4().to_string(),
            std::string::ToString::to_string,
        );
    let pk_uid = sk_uid.clone() + SYSTEM_TAG_PUBLIC_KEY;

    // Extract rotate_name before `request` is consumed by `generate_key_pair`.
    // Keyset validation (SQL keys only): if rotate_name is set, it must equal the private key's UID.
    // HSM key pairs have opaque PKCS#11-prefixed UIDs — the UID-match constraint does not apply.
    let sk_rotate_name = request
        .private_key_attributes
        .as_ref()
        .or(request.common_attributes.as_ref())
        .and_then(|attrs| attrs.rotate_name.clone());
    if let Some(ref rotate_name) = sk_rotate_name {
        if !ObjectHandle::from(&sk_uid).is_hsm() && rotate_name.as_str() != sk_uid {
            return Err(KmsError::InvalidRequest(format!(
                "CreateKeyPair: rotate_name ('{rotate_name}') must equal the private key's UID \
                 ('{sk_uid}') — set the private key ID to the keyset name at creation time"
            )));
        }
    }
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

    let KeyPair((mut private_key, mut public_key)) =
        generate_key_pair(kms.vendor_id(), request, &sk_uid, &pk_uid, &kms.rng)?;

    trace!("sk_uid: {sk_uid}, pk_uid: {pk_uid}");
    let private_key_attributes =
        private_key.setup_with_lifecycle(ObjectType::PrivateKey, requested_sk_activation_date)?;
    let mut private_key_attributes = private_key_attributes;
    // The server SHALL create the AlwaysSensitive attribute (KMIP 2.1 §4.3):
    // True iff the private key is created Sensitive.
    private_key_attributes.initialize_always_sensitive();
    private_key_attributes.initialize_never_extractable();
    if let Ok(object_attributes) = private_key.attributes_mut() {
        object_attributes.always_sensitive = private_key_attributes.always_sensitive;
        object_attributes.never_extractable = private_key_attributes.never_extractable;
    }
    // Initialise keyset metadata for gen-0 on SQL key pairs only.
    if sk_rotate_name.is_some() && !ObjectHandle::from(&sk_uid).is_hsm() {
        private_key_attributes.rotate_generation = Some(0);
        private_key_attributes.rotate_latest = Some(true);
    }
    trace!("Private key lifecycle attributes initialized");
    let private_key_tags = private_key_attributes.get_tags(kms.vendor_id());
    let cryptographic_algorithm = private_key_attributes.cryptographic_algorithm;

    Box::pin(wrap_and_cache(
        kms,
        owner,
        &UniqueIdentifier::TextString(sk_uid.clone()),
        &mut private_key,
    ))
    .await?;
    // If the private key was wrapped, record the WrappingKeyLink in stored attributes
    // so KMIP GetAttributes returns it correctly (KMIP 2.1 §4.31 Link).
    private_key.copy_wrapping_key_link_to(&mut private_key_attributes);

    let mut public_key_attributes =
        public_key.setup_with_lifecycle(ObjectType::PublicKey, requested_pk_activation_date)?;
    // Public keys are never Sensitive; AlwaysSensitive SHALL always have a value
    // (KMIP 2.1 §4.3, Table 34: applies to all objects).
    public_key_attributes.initialize_always_sensitive();
    if let Ok(object_attributes) = public_key.attributes_mut() {
        object_attributes.always_sensitive = public_key_attributes.always_sensitive;
    }
    trace!("Public key lifecycle attributes initialized");
    let public_key_tags = public_key_attributes.get_tags(kms.vendor_id());
    Box::pin(wrap_and_cache(
        kms,
        owner,
        &UniqueIdentifier::TextString(pk_uid.clone()),
        &mut public_key,
    ))
    .await?;
    // If the public key was wrapped, record the WrappingKeyLink in stored attributes.
    public_key.copy_wrapping_key_link_to(&mut public_key_attributes);

    let operations = vec![
        AtomicOperation::Create((
            sk_uid.clone(),
            owner.to_owned(),
            private_key,
            private_key_attributes,
            private_key_tags,
        )),
        AtomicOperation::Create((
            pk_uid.clone(),
            owner.to_owned(),
            public_key,
            public_key_attributes,
            public_key_tags,
        )),
    ];
    kms.constraints.check_new_objects(&operations)?;
    let ids = kms.database.atomic(owner, &operations).await?;

    let sk_uid = ids
        .first()
        .ok_or_else(|| KmsError::ServerError("Private key id not available".to_owned()))?;
    let pk_uid = ids
        .get(1)
        .ok_or_else(|| KmsError::ServerError("Public key id not available".to_owned()))?;

    info!(
        uid = sk_uid,
        user = owner.as_str(),
        "Created Key Pair with cryptographic algorithm {:?}",
        cryptographic_algorithm
    );

    Ok(CreateKeyPairResponse {
        private_key_unique_identifier: UniqueIdentifier::TextString(sk_uid.to_owned()),
        public_key_unique_identifier: UniqueIdentifier::TextString(pk_uid.to_owned()),
    })
}

/// Resolve an attribute that must hold the same value on the private and the public key.
///
/// KMIP 2.1 §6.1.9: Private/Public Key Attributes take precedence over Common Attributes,
/// and Table 191 requires the same value on both keys; a mismatch is `Invalid_Attribute`.
fn resolve_shared_attribute<T: Clone + PartialEq>(
    name: &str,
    field: impl Fn(&Attributes) -> Option<&T>,
    common: &Attributes,
    private: Option<&Attributes>,
    public: Option<&Attributes>,
) -> KResult<Option<T>> {
    let common = field(common);
    let private = private.and_then(&field).or(common);
    let public = public.and_then(&field).or(common);
    match (private, public) {
        (Some(sk), Some(pk)) if sk != pk => Err(KmsError::Kmip21Error(
            ErrorReason::Invalid_Attribute,
            format!(
                "CreateKeyPair: {name} must have the same value for the private and public keys"
            ),
        )),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value.clone())),
        (None, None) => Ok(None),
    }
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
    vendor_id: &str,
    request: CreateKeyPair,
    private_key_uid: &str,
    public_key_uid: &str,
    #[cfg_attr(not(feature = "non-fips"), expect(unused_variables))] rng: &KmsRng,
) -> KResult<KeyPair> {
    trace!("Internal create key pair");

    let mut common_attributes = request.common_attributes.unwrap_or_default();
    let private_attributes = request.private_key_attributes.as_ref();
    let public_attributes = request.public_key_attributes.as_ref();

    // Private/Public Key Attributes take precedence over Common Attributes and these four
    // attributes must be identical on both keys (KMIP 2.1 §6.1.9, Table 191). Fold the
    // resolved values into the common attributes, which drive key generation below.
    let algorithm = resolve_shared_attribute(
        "Cryptographic Algorithm",
        |a| a.cryptographic_algorithm.as_ref(),
        &common_attributes,
        private_attributes,
        public_attributes,
    )?;
    let resolved_length = resolve_shared_attribute(
        "Cryptographic Length",
        |a| a.cryptographic_length.as_ref(),
        &common_attributes,
        private_attributes,
        public_attributes,
    )?;
    let resolved_curve_parameters = resolve_shared_attribute(
        "Cryptographic Domain Parameters",
        |a| a.cryptographic_domain_parameters.as_ref(),
        &common_attributes,
        private_attributes,
        public_attributes,
    )?;
    resolve_shared_attribute(
        "Cryptographic Parameters",
        |a| a.cryptographic_parameters.as_ref(),
        &common_attributes,
        private_attributes,
        public_attributes,
    )?;
    common_attributes.cryptographic_algorithm = algorithm;
    common_attributes.cryptographic_length = resolved_length;
    common_attributes.cryptographic_domain_parameters = resolved_curve_parameters;

    // Check that the cryptographic algorithm is specified.
    let Some(cryptographic_algorithm) = algorithm else {
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
                    KeyPairIdentity {
                        vendor_id,
                        private_key_uid,
                        public_key_uid,
                        common_attributes,
                        private_key_attributes: request.private_key_attributes,
                        public_key_attributes: request.public_key_attributes,
                    },
                    EcKeySpec {
                        curve,
                        cryptographic_algorithm,
                    },
                ),
                RecommendedCurve::P224
                | RecommendedCurve::P256
                | RecommendedCurve::P384
                | RecommendedCurve::P521 => create_approved_ecc_key_pair(
                    KeyPairIdentity {
                        vendor_id,
                        private_key_uid,
                        public_key_uid,
                        common_attributes,
                        private_key_attributes: request.private_key_attributes,
                        public_key_attributes: request.public_key_attributes,
                    },
                    EcKeySpec {
                        curve,
                        cryptographic_algorithm,
                    },
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::SECP224K1
                | RecommendedCurve::SECP256K1
                | RecommendedCurve::SECP192K1 => create_secp_key_pair(
                    KeyPairIdentity {
                        vendor_id,
                        private_key_uid,
                        public_key_uid,
                        common_attributes,
                        private_key_attributes: request.private_key_attributes,
                        public_key_attributes: request.public_key_attributes,
                    },
                    EcKeySpec {
                        curve,
                        cryptographic_algorithm,
                    },
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::CURVE25519 => create_x25519_key_pair(
                    vendor_id,
                    private_key_uid,
                    public_key_uid,
                    &cryptographic_algorithm,
                    common_attributes,
                    request.private_key_attributes,
                    request.public_key_attributes,
                ),
                #[cfg(feature = "non-fips")]
                RecommendedCurve::CURVE448 => create_x448_key_pair(
                    vendor_id,
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
                            vendor_id,
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
                            vendor_id,
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
            let requested_length = common_attributes
                .cryptographic_length
                .ok_or_else(|| KmsError::InvalidRequest("RSA key size: error".to_owned()))?;
            let key_size_in_bits = u32::try_from(requested_length)
                .ok()
                .filter(|bits| *bits > 0)
                .ok_or_else(|| {
                    KmsError::Kmip21Error(
                        ErrorReason::Invalid_Attribute_Value,
                        format!(
                            "CreateKeyPair: invalid RSA Cryptographic Length {requested_length}"
                        ),
                    )
                })?;
            debug!("RSA key pair generation: size in bits: {key_size_in_bits}");

            create_rsa_key_pair(
                vendor_id,
                private_key_uid,
                public_key_uid,
                common_attributes,
                request.private_key_attributes,
                request.public_key_attributes,
            )
        }
        CryptographicAlgorithm::Ed25519 => create_ed25519_key_pair(
            vendor_id,
            private_key_uid,
            public_key_uid,
            common_attributes,
            request.private_key_attributes,
            request.public_key_attributes,
        ),
        CryptographicAlgorithm::Ed448 => create_ed448_key_pair(
            vendor_id,
            private_key_uid,
            public_key_uid,
            common_attributes,
            request.private_key_attributes,
            request.public_key_attributes,
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::MLKEM_512
        | CryptographicAlgorithm::MLKEM_768
        | CryptographicAlgorithm::MLKEM_1024 => create_ml_kem_key_pair(
            cryptographic_algorithm,
            KeyPairIdentity {
                vendor_id,
                private_key_uid,
                public_key_uid,
                common_attributes,
                private_key_attributes: request.private_key_attributes,
                public_key_attributes: request.public_key_attributes,
            },
            Some(rng),
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::MLDSA_44
        | CryptographicAlgorithm::MLDSA_65
        | CryptographicAlgorithm::MLDSA_87 => create_ml_dsa_key_pair(
            cryptographic_algorithm,
            KeyPairIdentity {
                vendor_id,
                private_key_uid,
                public_key_uid,
                common_attributes,
                private_key_attributes: request.private_key_attributes,
                public_key_attributes: request.public_key_attributes,
            },
            Some(rng),
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::X25519MLKEM768 | CryptographicAlgorithm::X448MLKEM1024 => {
            create_hybrid_kem_key_pair(
                cryptographic_algorithm,
                KeyPairIdentity {
                    vendor_id,
                    private_key_uid,
                    public_key_uid,
                    common_attributes,
                    private_key_attributes: request.private_key_attributes,
                    public_key_attributes: request.public_key_attributes,
                },
                Some(rng),
            )
        }
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::SLHDSA_SHA2_128s
        | CryptographicAlgorithm::SLHDSA_SHA2_128f
        | CryptographicAlgorithm::SLHDSA_SHA2_192s
        | CryptographicAlgorithm::SLHDSA_SHA2_192f
        | CryptographicAlgorithm::SLHDSA_SHA2_256s
        | CryptographicAlgorithm::SLHDSA_SHA2_256f
        | CryptographicAlgorithm::SLHDSA_SHAKE_128s
        | CryptographicAlgorithm::SLHDSA_SHAKE_128f
        | CryptographicAlgorithm::SLHDSA_SHAKE_192s
        | CryptographicAlgorithm::SLHDSA_SHAKE_192f
        | CryptographicAlgorithm::SLHDSA_SHAKE_256s
        | CryptographicAlgorithm::SLHDSA_SHAKE_256f => create_slh_dsa_key_pair(
            cryptographic_algorithm,
            KeyPairIdentity {
                vendor_id,
                private_key_uid,
                public_key_uid,
                common_attributes,
                private_key_attributes: request.private_key_attributes,
                public_key_attributes: request.public_key_attributes,
            },
            Some(rng),
        ),
        #[cfg(feature = "non-fips")]
        CryptographicAlgorithm::ConfigurableKEM => kem_keygen(
            vendor_id,
            private_key_uid.to_owned(),
            request.private_key_attributes,
            public_key_uid.to_owned(),
            request.public_key_attributes,
            &common_attributes,
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
                KeyPairIdentity {
                    vendor_id,
                    private_key_uid,
                    public_key_uid,
                    common_attributes,
                    private_key_attributes: request.private_key_attributes,
                    public_key_attributes: request.public_key_attributes,
                },
                &Covercrypt::default(),
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

#[cfg(test)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_types::{CryptographicAlgorithm, CryptographicDomainParameters, RecommendedCurve},
        },
    };

    use super::resolve_shared_attribute;
    use crate::error::KmsError;

    fn curve(recommended_curve: RecommendedCurve) -> Attributes {
        Attributes {
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                qlength: None,
                recommended_curve: Some(recommended_curve),
            }),
            ..Attributes::default()
        }
    }

    #[test]
    fn per_key_attribute_is_resolved_and_mismatch_rejected() {
        fn field(a: &Attributes) -> Option<&CryptographicDomainParameters> {
            a.cryptographic_domain_parameters.as_ref()
        }
        let common = Attributes::default();

        // The curve is only given on the private key: it is the effective value.
        let resolved = resolve_shared_attribute(
            "domain",
            field,
            &common,
            Some(&curve(RecommendedCurve::P256)),
            None,
        )
        .ok()
        .flatten();
        assert_eq!(
            resolved.and_then(|p| p.recommended_curve),
            Some(RecommendedCurve::P256)
        );

        // Private and public key disagree: Invalid_Attribute.
        let err = resolve_shared_attribute(
            "domain",
            field,
            &common,
            Some(&curve(RecommendedCurve::P256)),
            Some(&curve(RecommendedCurve::P384)),
        )
        .err();
        assert!(matches!(
            err,
            Some(KmsError::Kmip21Error(ErrorReason::Invalid_Attribute, _))
        ));

        // A per-key value overrides the common one, and the other key inherits the common
        // value: they differ, so this is rejected too.
        let err = resolve_shared_attribute(
            "algorithm",
            |a: &Attributes| a.cryptographic_algorithm.as_ref(),
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                ..Attributes::default()
            },
            Some(&Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ECDSA),
                ..Attributes::default()
            }),
            None,
        )
        .err();
        assert!(matches!(
            err,
            Some(KmsError::Kmip21Error(ErrorReason::Invalid_Attribute, _))
        ));
    }
}

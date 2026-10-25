//! Lifecycle and usage rules of `ConfigurableKEM` hybrid keys (e.g. ML-KEM-768/P-256):
//! least-privilege usage masks, encapsulation round trip, refusal of non-KEM uses,
//! revocation and algorithm-policy enforcement on use.
use std::sync::Arc;

use cosmian_kms_client_utils::configurable_kem_utils::{
    KemAlgorithm, build_create_configurable_kem_keypair_request,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, RevocationReason, RevocationReasonCode},
        kmip_2_1::{
            extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_operations::{
                CreateKeyPair, EncryptResponse, Get, GetAttributes, Import, Locate, Operation,
                Revoke, Sign,
            },
            kmip_types::{
                CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
                RecommendedCurve, UniqueIdentifier,
            },
            requests::{
                create_pqc_key_pair_request, decrypt_request, encrypt_request,
                symmetric_key_create_request,
            },
        },
        ttlv::to_ttlv,
    },
    cosmian_kms_crypto::reexport::cosmian_crypto_core::bytes_ser_de::Serializable,
};
use cosmian_logger::log_init;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::{ClapConfig, ServerParams},
    core::{KMS, operations::algorithm_policy::enforce_kmip_algorithm_policy_for_operation},
    error::KmsError,
    result::KResult,
    tests::test_utils::https_clap_config,
};

async fn kms_from(conf: ClapConfig) -> KResult<Arc<KMS>> {
    Ok(Arc::new(
        KMS::instantiate(Arc::new(ServerParams::try_from(conf)?)).await?,
    ))
}

fn hybrid_request(tag: &str) -> KResult<CreateKeyPair> {
    build_create_configurable_kem_keypair_request(
        VENDOR_ID_COSMIAN,
        None,
        [tag],
        KemAlgorithm::MlKem768P256,
        false,
        None,
    )
    .map_err(|e| KmsError::InvalidRequest(e.to_string()))
}

/// Returns the (private, public) key identifiers
async fn create(kms: &KMS, owner: &str, request: CreateKeyPair) -> KResult<(String, String)> {
    let response = kms.create_key_pair(request, owner, None).await?;
    Ok((
        response.private_key_unique_identifier.to_string(),
        response.public_key_unique_identifier.to_string(),
    ))
}

async fn attributes(kms: &KMS, owner: &str, uid: &str) -> KResult<Attributes> {
    Ok(kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
                attribute_reference: None,
            },
            owner,
        )
        .await?
        .attributes)
}

async fn encrypt_raw(kms: &KMS, owner: &str, pk: &str) -> KResult<EncryptResponse> {
    kms.encrypt(encrypt_request(pk, None, vec![], None, None, None)?, owner)
        .await
}

fn unpack(data: &[u8]) -> KResult<(Vec<u8>, Vec<u8>)> {
    let (secret, enc) =
        <(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>::deserialize(data).map_err(|e| {
            KmsError::ServerError(format!("data is not a (secret, encapsulation): {e}"))
        })?;
    Ok((secret.to_vec(), enc.to_vec()))
}

/// Returns (shared secret, encapsulation). `ConfigurableKEM` packs both in `Data` as a
/// serialized tuple; the other KEMs return the secret in `Data` and the encapsulation in
/// `IVCounterNonce`.
async fn encapsulate(kms: &KMS, owner: &str, pk: &str) -> KResult<(Vec<u8>, Vec<u8>)> {
    let response = encrypt_raw(kms, owner, pk).await?;
    let data = response
        .data
        .ok_or_else(|| KmsError::ServerError("no data".to_owned()))?;
    match response.i_v_counter_nonce {
        Some(enc) => Ok((data, enc)),
        None => unpack(&data),
    }
}

/// The `ConfigurableKEM` `Encrypt` contract, which must not be aligned with ML-KEM's:
/// `IVCounterNonce` is empty and `Data` is the serialized `(shared secret, encapsulation)`
/// tuple. Only its encapsulation component can be decapsulated, to the packed secret.
async fn assert_configurable_kem_contract(
    kms: &KMS,
    owner: &str,
    sk: &str,
    pk: &str,
) -> KResult<()> {
    let response = encrypt_raw(kms, owner, pk).await?;
    assert_eq!(response.i_v_counter_nonce, None);
    assert_eq!(response.authenticated_encryption_tag, None);
    let data = response
        .data
        .ok_or_else(|| KmsError::ServerError("no data".to_owned()))?;
    let (secret, enc) = unpack(&data)?;
    assert!(!secret.is_empty() && !enc.is_empty());
    assert_eq!(decapsulate(kms, owner, sk, enc).await?, secret);
    assert!(
        decapsulate(kms, owner, sk, data).await.is_err(),
        "the packed tuple is not itself an encapsulation"
    );
    Ok(())
}

async fn decapsulate(kms: &KMS, owner: &str, sk: &str, enc: Vec<u8>) -> KResult<Vec<u8>> {
    let response = kms
        .decrypt(decrypt_request(sk, None, enc, None, None, None), owner)
        .await?;
    Ok(response
        .data
        .ok_or_else(|| KmsError::ServerError("no decapsulated secret".to_owned()))?
        .to_vec())
}

async fn assert_round_trip(kms: &KMS, owner: &str, sk: &str, pk: &str) -> KResult<()> {
    let (secret, enc) = encapsulate(kms, owner, pk).await?;
    assert!(!secret.is_empty());
    assert_eq!(decapsulate(kms, owner, sk, enc).await?, secret);
    Ok(())
}

#[tokio::test]
async fn test_configurable_kem_lifecycle() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = kms_from(https_clap_config()).await?;
    let owner = "configurable_kem_lifecycle";
    let tag = format!("hybrid-kem-{}", Uuid::new_v4());

    let (sk, pk) = create(&kms, owner, hybrid_request(&tag)?).await?;

    // least privilege: decapsulation and encapsulation only
    let sk_attributes = attributes(&kms, owner, &sk).await?;
    assert_eq!(
        sk_attributes.cryptographic_usage_mask,
        Some(CryptographicUsageMask::Decrypt)
    );
    assert_eq!(
        attributes(&kms, owner, &pk).await?.cryptographic_usage_mask,
        Some(CryptographicUsageMask::Encrypt)
    );

    assert_round_trip(&kms, owner, &sk, &pk).await?;
    assert_configurable_kem_contract(&kms, owner, &sk, &pk).await?;

    // plaintext is refused instead of being silently ignored
    let encrypt_with_data = kms
        .encrypt(
            encrypt_request(&pk, None, b"plaintext".to_vec(), None, None, None)?,
            owner,
        )
        .await;
    assert!(encrypt_with_data.is_err(), "KEM Encrypt accepted plaintext");

    // a KEM key cannot sign
    let sign = kms
        .sign(
            Sign {
                unique_identifier: Some(UniqueIdentifier::TextString(sk.clone())),
                data: Some(b"message".to_vec().into()),
                ..Sign::default()
            },
            owner,
        )
        .await;
    assert!(sign.is_err(), "a KEM private key signed data");

    // both halves are found by their tag
    let located = locate_by_tag(&kms, owner, &tag).await?;
    for uid in [&sk, &pk] {
        assert!(located.contains(uid), "Locate by tag missed {uid}");
    }

    // revocation: in 5.22.x neither half of a revoked pair can be used any more
    let (_, enc) = encapsulate(&kms, owner, &pk).await?;
    kms.revoke(
        Revoke {
            unique_identifier: Some(UniqueIdentifier::TextString(sk.clone())),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::KeyCompromise,
                revocation_message: None,
            },
            compromise_occurrence_date: None,
            cascade: true,
        },
        owner,
    )
    .await?;
    assert!(
        encapsulate(&kms, owner, &pk).await.is_err(),
        "a revoked KEM public key encapsulated"
    );
    assert!(
        decapsulate(&kms, owner, &sk, enc).await.is_err(),
        "a revoked KEM private key decapsulated"
    );
    Ok(())
}

async fn locate_by_tag(kms: &KMS, owner: &str, tag: &str) -> KResult<Vec<String>> {
    let mut search = Attributes::default();
    search.set_tags(VENDOR_ID_COSMIAN, [tag])?;
    Ok(kms
        .locate(
            Locate {
                attributes: search,
                ..Locate::default()
            },
            owner,
        )
        .await?
        .unique_identifier
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Every KEM key type returns the shared secret in `Data` and the encapsulation in
/// `IVCounterNonce`, and decapsulating it returns that same secret. Run with keys stored in
/// clear and wrapped by a software KEK, with a restart in between so that wrapped keys are
/// unwrapped from the database to be used.
#[tokio::test]
async fn test_kem_encrypt_decrypt_round_trip_all_algorithms() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let requests = || -> KResult<Vec<(&'static str, CreateKeyPair)>> {
        let mut requests = Vec::new();
        for (name, algorithm) in [
            ("ML-KEM-512/P-256", KemAlgorithm::MlKem512P256),
            ("ML-KEM-768/P-256", KemAlgorithm::MlKem768P256),
            ("ML-KEM-512/X25519", KemAlgorithm::MlKem512Curve25519),
            ("ML-KEM-768/X25519", KemAlgorithm::MlKem768Curve25519),
        ] {
            requests.push((
                name,
                build_create_configurable_kem_keypair_request(
                    VENDOR_ID_COSMIAN,
                    None,
                    [name],
                    algorithm,
                    false,
                    None,
                )
                .map_err(|e| KmsError::InvalidRequest(e.to_string()))?,
            ));
        }
        for (name, algorithm) in [
            ("ML-KEM-512", CryptographicAlgorithm::MLKEM_512),
            ("ML-KEM-768", CryptographicAlgorithm::MLKEM_768),
            ("ML-KEM-1024", CryptographicAlgorithm::MLKEM_1024),
            ("X25519MLKEM768", CryptographicAlgorithm::X25519MLKEM768),
            ("X448MLKEM1024", CryptographicAlgorithm::X448MLKEM1024),
        ] {
            requests.push((
                name,
                create_pqc_key_pair_request(VENDOR_ID_COSMIAN, [name], algorithm, false)?,
            ));
        }
        Ok(requests)
    };

    for with_kek in [false, true] {
        let owner = "kem_round_trip";
        let sqlite_path = https_clap_config().db.sqlite_path;
        let conf_with = |kek: Option<String>| {
            let mut conf = https_clap_config();
            conf.db.sqlite_path.clone_from(&sqlite_path);
            conf.key_encryption_key = kek;
            conf
        };
        let kms = kms_from(conf_with(None)).await?;
        let kek = if with_kek {
            Some(
                kms.create(
                    symmetric_key_create_request(
                        VENDOR_ID_COSMIAN,
                        None,
                        256,
                        CryptographicAlgorithm::AES,
                        EMPTY_TAGS,
                        false,
                        None,
                    )?,
                    owner,
                    None,
                )
                .await?
                .unique_identifier
                .to_string(),
            )
        } else {
            None
        };
        // keys created by a server that wraps them with the KEK, if any
        drop(kms);
        let kms = kms_from(conf_with(kek.clone())).await?;
        let mut pairs = Vec::new();
        for (name, request) in requests()? {
            let (sk, pk) = create(&kms, owner, request).await?;
            assert_round_trip(&kms, owner, &sk, &pk)
                .await
                .map_err(|e| KmsError::Default(format!("{name} (kek: {with_kek}): {e}")))?;
            // only the `ConfigurableKEM` names contain a `/`: they keep the packed layout
            if name.contains('/') {
                assert_configurable_kem_contract(&kms, owner, &sk, &pk).await?;
            } else {
                let response = encrypt_raw(&kms, owner, &pk).await?;
                assert!(response.i_v_counter_nonce.is_some(), "{name}: no IV");
            }
            pairs.push((name, sk, pk));
        }
        // restart: the keys are read back from the database, and unwrapped if wrapped
        drop(kms);
        let kms = kms_from(conf_with(kek)).await?;
        for (name, sk, pk) in &pairs {
            for uid in [sk, pk] {
                let stored =
                    kms.database.retrieve_object(uid).await?.ok_or_else(|| {
                        KmsError::ItemNotFound(format!("{name}: {uid} not stored"))
                    })?;
                assert_eq!(
                    stored.object().is_wrapped(),
                    with_kek,
                    "{name}: {uid} wrapped at rest"
                );
            }
            let (secret, enc) = encapsulate(&kms, owner, pk).await?;
            assert_eq!(
                decapsulate(&kms, owner, sk, enc.clone()).await?,
                secret,
                "{name} (kek: {with_kek}) after restart"
            );
            // a fresh encapsulation is not a replay of the previous one
            let (secret2, enc2) = encapsulate(&kms, owner, pk).await?;
            assert_ne!(enc, enc2, "{name}: deterministic encapsulation");
            assert_ne!(secret, secret2, "{name}: repeated shared secret");
        }
    }
    Ok(())
}

/// A per-key usage mask is honoured, not OR-ed with `Unrestricted`, and the per-key
/// attributes still inherit the common ones (tags).
#[tokio::test]
async fn test_configurable_kem_requested_mask_is_honoured() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let kms = kms_from(https_clap_config()).await?;
    let owner = "configurable_kem_mask";
    let tag = format!("hybrid-kem-mask-{}", Uuid::new_v4());

    let mut request = hybrid_request(&tag)?;
    if let Some(common) = request.common_attributes.as_mut() {
        common.cryptographic_usage_mask = Some(CryptographicUsageMask::Unrestricted);
    }
    request.private_key_attributes = Some(Attributes {
        cryptographic_usage_mask: Some(CryptographicUsageMask::Decrypt),
        ..Attributes::default()
    });
    let (sk, pk) = create(&kms, owner, request).await?;

    let sk_attributes = attributes(&kms, owner, &sk).await?;
    assert_eq!(
        sk_attributes.cryptographic_usage_mask,
        Some(CryptographicUsageMask::Decrypt)
    );
    assert!(locate_by_tag(&kms, owner, &tag).await?.contains(&sk));
    assert_round_trip(&kms, owner, &sk, &pk).await
}

/// Re-import the public key `pk` under a fresh identifier, with its component attributes
/// replaced by `curve` and `algorithm` (`None` strips them) in both the request and the object.
async fn import_relabelled(
    kms: &KMS,
    owner: &str,
    pk: &str,
    curve: Option<RecommendedCurve>,
    algorithm: Option<CryptographicAlgorithm>,
) -> KResult<String> {
    let relabel = |attributes: &mut Attributes| {
        attributes.cryptographic_domain_parameters = curve.map(|c| CryptographicDomainParameters {
            recommended_curve: Some(c),
            ..CryptographicDomainParameters::default()
        });
        attributes.cryptographic_parameters = algorithm.map(|a| CryptographicParameters {
            cryptographic_algorithm: Some(a),
            ..CryptographicParameters::default()
        });
    };
    let mut object = kms.get(Get::from(pk), owner).await?.object;
    relabel(object.attributes_mut()?);
    let mut attributes = Attributes {
        object_type: Some(ObjectType::PublicKey),
        ..Attributes::default()
    };
    relabel(&mut attributes);
    let uid = Uuid::new_v4().to_string();
    kms.import(
        Import {
            unique_identifier: UniqueIdentifier::TextString(uid.clone()),
            object_type: ObjectType::PublicKey,
            replace_existing: Some(false),
            key_wrap_type: None,
            attributes,
            object,
        },
        owner,
        None,
    )
    .await?;
    Ok(uid)
}

/// The algorithm policy checks both components of a hybrid key when it is used, so
/// tightening the policy after creation takes effect on existing keys. The components are
/// read from the serialized key, so stripped or relabelled KMIP attributes cannot bypass it.
#[tokio::test]
async fn test_configurable_kem_policy_on_use() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let conf = https_clap_config();
    let sqlite_path = conf.db.sqlite_path.clone();
    let owner = "configurable_kem_policy";
    // an ML-KEM-768/P-256 key pair, and two imports of its public key: one with the
    // components stripped, one relabelled as ML-KEM-512/P-384
    let (sk, pk, stripped, relabelled) = {
        let kms = kms_from(conf).await?;
        let (sk, pk) = create(&kms, owner, hybrid_request("hybrid-kem-policy")?).await?;
        let stripped = import_relabelled(&kms, owner, &pk, None, None).await?;
        let relabelled = import_relabelled(
            &kms,
            owner,
            &pk,
            Some(RecommendedCurve::P384),
            Some(CryptographicAlgorithm::MLKEM_512),
        )
        .await?;
        (sk, pk, stripped, relabelled)
    };

    // a server restarted on the same database with a tighter policy
    let with_policy = |algorithm: CryptographicAlgorithm, curve: RecommendedCurve| {
        let mut conf = https_clap_config();
        conf.db.sqlite_path.clone_from(&sqlite_path);
        conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
        conf.kmip_policy.allowlists.algorithms =
            Some(vec![CryptographicAlgorithm::ConfigurableKEM, algorithm]);
        conf.kmip_policy.allowlists.curves = Some(vec![curve]);
        conf
    };

    let allowed = kms_from(with_policy(
        CryptographicAlgorithm::MLKEM_768,
        RecommendedCurve::P256,
    ))
    .await?;
    // all three are the same key: usable when the policy allows its real components
    for uid in [&pk, &stripped, &relabelled] {
        assert_round_trip(&allowed, owner, &sk, uid).await?;
    }
    let (_, enc) = encapsulate(&allowed, owner, &pk).await?;
    drop(allowed);

    for (algorithm, curve, denied) in [
        (
            CryptographicAlgorithm::MLKEM_768,
            RecommendedCurve::P384,
            "P-256",
        ),
        (
            CryptographicAlgorithm::MLKEM_512,
            RecommendedCurve::P256,
            "ML-KEM-768",
        ),
        // the policy matches the relabelled attributes, not the key
        (
            CryptographicAlgorithm::MLKEM_512,
            RecommendedCurve::P384,
            "ML-KEM-768/P-256",
        ),
    ] {
        let kms = kms_from(with_policy(algorithm, curve)).await?;
        for uid in [&pk, &stripped, &relabelled] {
            assert!(
                encapsulate(&kms, owner, uid).await.is_err(),
                "{uid}: {denied} component used while only {algorithm}/{curve:?} is allowed"
            );
        }
        assert!(
            decapsulate(&kms, owner, &sk, enc.clone()).await.is_err(),
            "{denied} private key used while only {algorithm}/{curve:?} is allowed"
        );
    }
    Ok(())
}

/// Native hybrid KEM groups are in the `DEFAULT` policy scope.
#[test]
fn test_default_policy_allows_native_hybrid_kem() -> KResult<()> {
    let mut conf = ClapConfig::default();
    conf.kmip_policy.policy_id = Some("DEFAULT".to_owned());
    let params = ServerParams::try_from(conf)?;
    for algorithm in [
        CryptographicAlgorithm::X25519MLKEM768,
        CryptographicAlgorithm::X448MLKEM1024,
    ] {
        let request = create_pqc_key_pair_request(VENDOR_ID_COSMIAN, ["t"], algorithm, false)?;
        let ttlv = to_ttlv(&Operation::CreateKeyPair(Box::new(request)))?;
        enforce_kmip_algorithm_policy_for_operation(&params, "CreateKeyPair", &ttlv)?;
    }
    Ok(())
}

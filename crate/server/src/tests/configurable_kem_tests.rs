//! Lifecycle and usage rules of `ConfigurableKEM` hybrid keys (e.g. ML-KEM-768/P-256):
//! least-privilege usage masks, encapsulation round trip, refusal of non-KEM uses,
//! revocation and algorithm-policy enforcement on use.
use std::sync::Arc;

use cosmian_kms_client_utils::configurable_kem_utils::{
    KemAlgorithm, build_create_configurable_kem_keypair_request,
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, RevocationReason, RevocationReasonCode},
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_operations::{CreateKeyPair, GetAttributes, Locate, Operation, Revoke, Sign},
        kmip_types::{CryptographicAlgorithm, RecommendedCurve, UniqueIdentifier},
        requests::{create_pqc_key_pair_request, decrypt_request, encrypt_request},
    },
    ttlv::to_ttlv,
};
use cosmian_logger::log_init;
use uuid::Uuid;

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

/// Returns (shared secret, encapsulation)
async fn encapsulate(kms: &KMS, owner: &str, pk: &str) -> KResult<(Vec<u8>, Vec<u8>)> {
    let response = kms
        .encrypt(encrypt_request(pk, None, vec![], None, None, None)?, owner)
        .await?;
    Ok((
        response
            .data
            .ok_or_else(|| KmsError::ServerError("no shared secret".to_owned()))?,
        response
            .i_v_counter_nonce
            .ok_or_else(|| KmsError::ServerError("no encapsulation".to_owned()))?,
    ))
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

/// The algorithm policy checks both components of a hybrid key when it is used, so
/// tightening the policy after creation takes effect on existing keys.
#[tokio::test]
async fn test_configurable_kem_policy_on_use() -> KResult<()> {
    log_init(option_env!("RUST_LOG"));
    let conf = https_clap_config();
    let sqlite_path = conf.db.sqlite_path.clone();
    let owner = "configurable_kem_policy";
    let (sk, pk) = {
        let kms = kms_from(conf).await?;
        create(&kms, owner, hybrid_request("hybrid-kem-policy")?).await?
    };

    // a server restarted on the same database with a tighter policy
    let with_policy = |algorithms: Vec<CryptographicAlgorithm>, curve: RecommendedCurve| {
        let mut conf = https_clap_config();
        conf.db.sqlite_path.clone_from(&sqlite_path);
        conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());
        conf.kmip_policy.allowlists.algorithms = Some(algorithms);
        conf.kmip_policy.allowlists.curves = Some(vec![curve]);
        conf
    };
    let ml_kem_768 = vec![
        CryptographicAlgorithm::ConfigurableKEM,
        CryptographicAlgorithm::MLKEM_768,
    ];

    let allowed = kms_from(with_policy(ml_kem_768.clone(), RecommendedCurve::P256)).await?;
    assert_round_trip(&allowed, owner, &sk, &pk).await?;
    drop(allowed);

    let curve_denied = kms_from(with_policy(ml_kem_768, RecommendedCurve::P384)).await?;
    assert!(
        encapsulate(&curve_denied, owner, &pk).await.is_err(),
        "P-256 component used while only P-384 is allowed"
    );
    drop(curve_denied);

    let ml_kem_denied = kms_from(with_policy(
        vec![
            CryptographicAlgorithm::ConfigurableKEM,
            CryptographicAlgorithm::MLKEM_512,
        ],
        RecommendedCurve::P256,
    ))
    .await?;
    assert!(
        encapsulate(&ml_kem_denied, owner, &pk).await.is_err(),
        "ML-KEM-768 component used while only ML-KEM-512 is allowed"
    );
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

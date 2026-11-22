//! Keyset rotation against a real HSM (PKCS#11 token), run by `test_hsm_all`.
//!
//! The fake-HSM tests in `fake_hsm_rotation.rs` pin the server logic; this module proves the
//! same contract on the real token behind `HSM_MODEL`: `CKA_LABEL` round trips, generation of
//! the replacement key / key pair on the slot, retirement of old generations for protection
//! operations, processing with every generation, and, where the token stores
//! `CKA_START_DATE` / `CKA_END_DATE`, the auto-rotation scheduler.
use std::{collections::HashSet, fmt::Debug, sync::Arc};

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, ErrorReason, PaddingMethod},
    kmip_2_1::{
        extra::tagging::{SYSTEM_TAG_PUBLIC_KEY, VENDOR_ID_COSMIAN},
        kmip_attributes::Attribute,
        kmip_operations::{
            Decrypt, Encrypt, ReKey, ReKeyKeyPair, SetAttribute, Sign, SignatureVerify,
        },
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier, ValidityIndicator,
        },
        requests::{create_rsa_key_pair_request, symmetric_key_create_request},
    },
};
use cosmian_logger::info;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    EMPTY_TAGS, delete_key, hsm_clap_config, locate_keys,
    test_helpers::{assert_gcm_encrypt_refused, hsm_cannot_generate_gcm_iv, hsm_key_dates_support},
};
use crate::{
    core::{KMS, operations::run_auto_rotation},
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{get_tmp_sqlite_path, test_kms_with_config},
};

const ADMIN: &str = "rotation.admin@acme.com";
const OTHER: &str = "rotation.other@acme.com";
const PLAINTEXT: &[u8] = b"keyset rotation on a real HSM";
const MESSAGE: &[u8] = b"signed by one generation of an HSM keyset";
const THIRTY_DAYS_SECS: i64 = 30 * 24 * 3600;

/// Runs every keyset rotation scenario and removes the keys it created.
pub(super) async fn test_hsm_keyset_rotation() -> KResult<()> {
    let mut clap_config = hsm_clap_config(ADMIN, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = test_kms_with_config(clap_config).await?;

    let mut created = Vec::new();
    info!("HSM keyset rotation: AES keyset");
    aes_keyset(&kms, slot, &mut created).await?;
    info!("HSM keyset rotation: RSA key pair keyset");
    key_pair_keyset(&kms, slot, &mut created).await?;
    info!("HSM keyset rotation: rotation schedule");
    schedule(&kms, slot, &mut created).await?;

    for uid in created {
        delete_key(&uid, ADMIN, &kms).await?;
    }
    Ok(())
}

/// A short unique UID on the slot: the keyset label embeds it twice, and some tokens limit
/// the length of `CKA_LABEL`.
fn new_uid(slot: usize) -> String {
    let id = Uuid::new_v4().simple().to_string();
    as_hsm_uid!(slot, format!("rot{}", &id[..8]))
}

fn uid(id: &str) -> UniqueIdentifier {
    UniqueIdentifier::TextString(id.to_owned())
}

fn cbc() -> CryptographicParameters {
    CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(BlockCipherMode::CBC),
        padding_method: Some(PaddingMethod::PKCS5),
        ..CryptographicParameters::default()
    }
}

fn assert_reason<T: Debug>(result: &KResult<T>, reason: ErrorReason) {
    assert!(
        matches!(result, Err(KmsError::Kmip21Error(r, _)) if *r == reason),
        "expected {reason:?}, got {result:?}"
    );
}

fn assert_refused_with<T: Debug>(result: &KResult<T>, fragment: &str) {
    assert!(
        result
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains(fragment)),
        "expected an error containing {fragment:?}, got {result:?}"
    );
}

/// A wrong key either fails or, for an unauthenticated mode, returns garbage: never `PLAINTEXT`.
fn assert_not_decrypted(result: &KResult<Vec<u8>>) {
    if let Ok(data) = result {
        assert_ne!(
            data, PLAINTEXT,
            "a wrong generation must not recover the plaintext"
        );
    }
}

/// `iv || ciphertext || tag`, the layout the HSM decrypt oracle takes back as `data`.
async fn encrypt(
    kms: &KMS,
    uid_str: &str,
    parameters: Option<CryptographicParameters>,
) -> KResult<Vec<u8>> {
    let response = kms
        .encrypt(
            Encrypt {
                unique_identifier: Some(uid(uid_str)),
                cryptographic_parameters: parameters,
                data: Some(PLAINTEXT.to_vec().into()),
                ..Encrypt::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    let mut blob = Vec::new();
    if let Some(iv) = response.i_v_counter_nonce {
        blob.extend(&*iv);
    }
    blob.extend(&*response.data.unwrap_or_default());
    if let Some(tag) = response.authenticated_encryption_tag {
        blob.extend(&*tag);
    }
    Ok(blob)
}

async fn decrypt(
    kms: &KMS,
    uid_str: &str,
    blob: &[u8],
    parameters: Option<CryptographicParameters>,
) -> KResult<Vec<u8>> {
    let response = kms
        .decrypt(
            Decrypt {
                unique_identifier: Some(uid(uid_str)),
                cryptographic_parameters: parameters,
                data: Some(blob.to_vec()),
                ..Decrypt::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    Ok(response.data.map(|d| d.to_vec()).unwrap_or_default())
}

async fn sign(kms: &KMS, uid_str: &str) -> KResult<Vec<u8>> {
    let response = kms
        .sign(
            Sign {
                unique_identifier: Some(uid(uid_str)),
                data: Some(MESSAGE.to_vec().into()),
                ..Sign::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    Ok(response.signature_data.unwrap_or_default())
}

async fn verify(
    kms: &KMS,
    uid_str: &str,
    signature: &[u8],
    message: &[u8],
) -> KResult<ValidityIndicator> {
    kms.signature_verify(
        SignatureVerify {
            unique_identifier: Some(uid(uid_str)),
            data: Some(message.to_vec()),
            signature_data: Some(signature.to_vec()),
            ..SignatureVerify::default()
        },
        &UserId::from(ADMIN),
    )
    .await?
    .validity_indicator
    .ok_or_else(|| KmsError::ServerError("no validity indicator".to_owned()))
}

async fn rekey(kms: &KMS, uid_str: &str, user: &str) -> KResult<String> {
    Ok(kms
        .rekey(
            ReKey {
                unique_identifier: Some(uid(uid_str)),
                ..ReKey::default()
            },
            &UserId::from(user),
        )
        .await?
        .unique_identifier
        .to_string())
}

async fn rekey_key_pair(kms: &KMS, uid_str: &str) -> KResult<(String, String)> {
    let response = kms
        .rekey_keypair(
            ReKeyKeyPair {
                private_key_unique_identifier: Some(uid(uid_str)),
                ..ReKeyKeyPair::default()
            },
            &UserId::from(ADMIN),
        )
        .await?;
    Ok((
        response.private_key_unique_identifier.to_string(),
        response.public_key_unique_identifier.to_string(),
    ))
}

async fn set_attribute(kms: &KMS, uid_str: &str, attribute: Attribute) -> KResult<()> {
    kms.set_attribute(
        SetAttribute {
            unique_identifier: Some(uid(uid_str)),
            new_attribute: attribute,
        },
        &UserId::from(ADMIN),
    )
    .await
    .map(|_| ())
}

/// `(uid, generation)` of every member of the keyset, read from the token (`CKA_LABEL`).
async fn members(kms: &KMS, name: &str) -> KResult<Vec<(String, i32)>> {
    let mut members: Vec<(String, i32)> = kms
        .database
        .find_by_rotate_name_uncached(name, None, &UserId::from(ADMIN))
        .await?
        .into_iter()
        .map(|(uid, attributes)| (uid, attributes.rotate_generation.unwrap_or(-1)))
        .collect();
    members.sort_by_key(|(_, generation)| *generation);
    Ok(members)
}

async fn rotate_interval(kms: &KMS, uid_str: &str) -> KResult<Option<i64>> {
    Ok(kms
        .database
        .retrieve_object_uncached(uid_str)
        .await?
        .and_then(|owm| owm.attributes().rotate_interval))
}

async fn create_aes(kms: &KMS, uid_str: &str) -> KResult<()> {
    // Non-extractable, as a production key: the KMS only ever sees a metadata stub.
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(uid(uid_str)),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        true,
        None,
    )?;
    let response = kms.create(request, &UserId::from(ADMIN)).await?;
    assert_eq!(response.unique_identifier, uid(uid_str));
    Ok(())
}

async fn aes_keyset(kms: &KMS, slot: usize, created: &mut Vec<String>) -> KResult<()> {
    let base = new_uid(slot);
    create_aes(kms, &base).await?;
    created.push(base.clone());

    // Enrollment writes the generation-0 label on the token.
    set_attribute(kms, &base, Attribute::RotateName(base.clone())).await?;
    assert_eq!(members(kms, &base).await?, vec![(base.clone(), 0)]);
    let wrong_name = set_attribute(kms, &base, Attribute::RotateName("other".to_owned())).await;
    assert_refused_with(&wrong_name, "must be the key's base UID");

    let generation_0 = encrypt(kms, &base, Some(cbc())).await?;
    // CBC cannot tell a wrong key: a bare keyset name refuses it, an addressed generation does not.
    assert_reason(
        &decrypt(kms, &base, &generation_0, Some(cbc())).await,
        ErrorReason::Feature_Not_Supported,
    );
    assert_eq!(
        decrypt(kms, &format!("{base}@0"), &generation_0, Some(cbc())).await?,
        PLAINTEXT
    );

    // Manual re-key: the replacement is generated on the slot and the old head is retired.
    let generation_1_uid = rekey(kms, &base, ADMIN).await?;
    assert_eq!(generation_1_uid, format!("{base}@1"));
    created.push(generation_1_uid.clone());
    assert_eq!(
        members(kms, &base).await?,
        vec![(base.clone(), 0), (generation_1_uid.clone(), 1)]
    );

    // Protection operations use the head only.
    for head in [base.clone(), format!("{base}@1"), format!("{base}@latest")] {
        encrypt(kms, &head, Some(cbc())).await?;
    }
    for retired in [format!("{base}@0"), format!("{base}@first")] {
        assert_reason(
            &encrypt(kms, &retired, Some(cbc())).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    // Processing works with every generation, addressed explicitly.
    let generation_1 = encrypt(kms, &base, Some(cbc())).await?;
    assert_eq!(
        decrypt(kms, &format!("{base}@0"), &generation_0, Some(cbc())).await?,
        PLAINTEXT
    );
    assert_eq!(
        decrypt(kms, &format!("{base}@1"), &generation_1, Some(cbc())).await?,
        PLAINTEXT
    );
    assert_not_decrypted(&decrypt(kms, &format!("{base}@1"), &generation_0, Some(cbc())).await);
    assert_not_decrypted(&decrypt(kms, &format!("{base}@0"), &generation_1, Some(cbc())).await);

    // Re-key of a retired or missing generation, or by a caller without grant.
    for retired in [format!("{base}@0"), format!("{base}@first")] {
        assert_refused_with(
            &rekey(kms, &retired, ADMIN).await,
            "is not the latest in its keyset",
        );
    }
    assert_reason(
        &rekey(kms, &format!("{base}@99"), ADMIN).await,
        ErrorReason::Item_Not_Found,
    );
    assert_reason(&rekey(kms, &base, OTHER).await, ErrorReason::Item_Not_Found);
    let wrong_type = rekey_key_pair(kms, &base).await;
    assert_reason(&wrong_type, ErrorReason::Invalid_Object_Type);
    assert_eq!(
        members(kms, &base).await?.len(),
        2,
        "refusals must not rotate"
    );

    let generation_2_uid = rekey(kms, &format!("{base}@latest"), ADMIN).await?;
    assert_eq!(generation_2_uid, format!("{base}@2"));
    created.push(generation_2_uid);
    assert_reason(
        &encrypt(kms, &format!("{base}@1"), Some(cbc())).await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    assert_eq!(
        decrypt(kms, &format!("{base}@1"), &generation_1, Some(cbc())).await?,
        PLAINTEXT
    );

    // AES-GCM detects a wrong key: a bare keyset name walks every generation.
    if hsm_cannot_generate_gcm_iv() {
        assert_gcm_encrypt_refused(encrypt(kms, &base, None).await);
    } else {
        let gcm = encrypt(kms, &base, None).await?;
        assert_eq!(decrypt(kms, &base, &gcm, None).await?, PLAINTEXT);
        let generation_3_uid = rekey(kms, &base, ADMIN).await?;
        assert_eq!(generation_3_uid, format!("{base}@3"));
        created.push(generation_3_uid);
        assert_eq!(
            decrypt(kms, &base, &gcm, None).await?,
            PLAINTEXT,
            "the bare name walks to the generation that encrypted"
        );
    }
    Ok(())
}

async fn key_pair_keyset(kms: &KMS, slot: usize, created: &mut Vec<String>) -> KResult<()> {
    let private = new_uid(slot);
    let public = format!("{private}{SYSTEM_TAG_PUBLIC_KEY}");
    let request = create_rsa_key_pair_request(
        VENDOR_ID_COSMIAN,
        Some(uid(&private)),
        EMPTY_TAGS,
        2048,
        true,
        None,
    )?;
    let response = kms.create_key_pair(request, &UserId::from(ADMIN)).await?;
    assert_eq!(response.public_key_unique_identifier, uid(&public));
    created.extend([private.clone(), public.clone()]);

    let signature_0 = sign(kms, &private).await?;
    // A pair that never joined a keyset is enrolled by its first re-key.
    let (new_private, new_public) = rekey_key_pair(kms, &private).await?;
    assert_eq!(new_private, format!("{private}@1"));
    assert_eq!(new_public, format!("{private}@1{SYSTEM_TAG_PUBLIC_KEY}"));
    created.extend([new_private.clone(), new_public.clone()]);
    assert_eq!(
        members(kms, &private).await?,
        vec![(private.clone(), 0), (new_private.clone(), 1)]
    );
    assert_eq!(
        members(kms, &public).await?,
        vec![(public.clone(), 0), (new_public.clone(), 1)]
    );

    // Sign with the head only; verify with every generation of the public keyset.
    let signature_1 = sign(kms, &private).await?;
    for retired in [format!("{private}@0"), format!("{private}@first")] {
        assert_reason(
            &sign(kms, &retired).await,
            ErrorReason::Wrong_Key_Lifecycle_State,
        );
    }
    for signature in [&signature_0, &signature_1] {
        assert_eq!(
            verify(kms, &public, signature, MESSAGE).await?,
            ValidityIndicator::Valid
        );
    }
    assert_eq!(
        verify(kms, &format!("{public}@latest"), &signature_0, MESSAGE).await?,
        ValidityIndicator::Invalid,
        "an addressed generation does not walk the keyset"
    );
    assert_eq!(
        verify(kms, &format!("{public}@0"), &signature_0, MESSAGE).await?,
        ValidityIndicator::Valid
    );
    assert_eq!(
        verify(kms, &public, &signature_1, b"another message").await?,
        ValidityIndicator::Invalid
    );

    // Re-key refusals leave the pair untouched.
    assert_refused_with(
        &rekey_key_pair(kms, &format!("{private}@0")).await,
        "is not the latest in its keyset",
    );
    assert_reason(
        &rekey(kms, &private, ADMIN).await,
        ErrorReason::Invalid_Object_Type,
    );
    assert_reason(
        &rekey_key_pair(kms, &public).await,
        ErrorReason::Invalid_Object_Type,
    );
    assert_eq!(
        members(kms, &private).await?.len(),
        2,
        "refusals must not rotate"
    );
    Ok(())
}

async fn schedule(kms: &Arc<KMS>, slot: usize, created: &mut Vec<String>) -> KResult<()> {
    let key = new_uid(slot);
    create_aes(kms, &key).await?;
    created.push(key.clone());

    // RotateAutomatic cannot be stored on a token, whatever it supports.
    let automatic = set_attribute(kms, &key, Attribute::RotateAutomatic(true)).await;
    assert!(
        matches!(automatic, Err(KmsError::NotSupported(_))),
        "{automatic:?}"
    );

    let armed = set_attribute(kms, &key, Attribute::RotateInterval(THIRTY_DAYS_SECS)).await;
    let dates_supported = match (hsm_key_dates_support(), armed.as_ref().err()) {
        (Some(true) | None, None) => true,
        (Some(false) | None, Some(error))
            if error
                .to_string()
                .contains("does not support CKA_START_DATE") =>
        {
            false
        }
        (expected, _) => panic!("unexpected scheduling outcome (expected {expected:?}): {armed:?}"),
    };
    if !dates_supported {
        info!("HSM keyset rotation: this token stores no key dates, scheduling is refused");
        assert_refused_with(&armed, "rotation scheduling is unavailable");
        assert!(
            members(kms, &key).await?.is_empty(),
            "a refused schedule must not enroll the key"
        );
        return Ok(());
    }

    // Arming enrolls the key and stores the interval on the token.
    assert_eq!(members(kms, &key).await?, vec![(key.clone(), 0)]);
    assert_eq!(rotate_interval(kms, &key).await?, Some(THIRTY_DAYS_SECS));

    // The end date elapses: the scheduler rotates the keyset head once and re-arms it.
    let today = OffsetDateTime::now_utc().date();
    kms.database
        .set_key_rotation_dates(&key, Some(today - Duration::days(30)), Some(today))
        .await?;
    run_auto_rotation(kms).await;
    let new_key = format!("{key}@1");
    created.push(new_key.clone());
    assert_eq!(
        members(kms, &key).await?,
        vec![(key.clone(), 0), (new_key.clone(), 1)]
    );
    assert_eq!(
        rotate_interval(kms, &new_key).await?,
        Some(THIRTY_DAYS_SECS)
    );
    assert_reason(
        &encrypt(kms, &format!("{key}@0"), Some(cbc())).await,
        ErrorReason::Wrong_Key_Lifecycle_State,
    );
    encrypt(kms, &key, Some(cbc())).await?;

    // The retired generation keeps its past end date and is never rotated again.
    run_auto_rotation(kms).await;
    assert_eq!(members(kms, &key).await?.len(), 2);

    // Validity dates written by another application never opt a key into rotation.
    let foreign = new_uid(slot);
    create_aes(kms, &foreign).await?;
    created.push(foreign.clone());
    kms.database
        .set_key_rotation_dates(&foreign, Some(today - Duration::days(30)), Some(today))
        .await?;
    run_auto_rotation(kms).await;
    assert_eq!(members(kms, &foreign).await?, Vec::<(String, i32)>::new());
    let located: HashSet<String> = locate_keys(ADMIN, kms, None)
        .await?
        .iter()
        .filter_map(|uid| uid.as_str().map(str::to_owned))
        .collect();
    assert!(
        !located.contains(&format!("{foreign}@1")),
        "a key without a keyset label must not be rotated"
    );

    // Disarm: the dates are cleared, the key stays in its keyset.
    set_attribute(kms, &new_key, Attribute::RotateInterval(0)).await?;
    assert_eq!(rotate_interval(kms, &new_key).await?, None);
    assert_eq!(members(kms, &key).await?.len(), 2);
    Ok(())
}

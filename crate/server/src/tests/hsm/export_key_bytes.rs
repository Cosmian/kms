use std::sync::Arc;

use cosmian_kms_interfaces::as_hsm_uid;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_operations::Operation,
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};
use openssl::symm::{Cipher, decrypt_aead};
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    error::KmsError,
    result::KResult,
    tests::{
        hsm::{
            EMPTY_TAGS, delete_key, export_object, hsm_clap_config, send_message,
            symmetric_dek::symmetric_encrypt,
        },
        test_utils::get_tmp_sqlite_path,
    },
};

/// Create an AES-256 key on the HSM with the given `sensitive` flag.
pub(super) async fn create_hsm_aes_key(
    kms: &Arc<KMS>,
    owner: &str,
    uid: &str,
    sensitive: bool,
) -> KResult<()> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        Some(UniqueIdentifier::TextString(uid.to_owned())),
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        sensitive,
        None,
    )?;
    let response = send_message(kms.clone(), owner, vec![Operation::Create(request)]).await?;
    let Operation::CreateResponse(_) = &response[0] else {
        return Err(KmsError::ServerError("invalid create response".to_owned()));
    };
    Ok(())
}

/// An HSM AES key created with `sensitive = false` (so `CKA_SENSITIVE=false`,
/// `CKA_EXTRACTABLE=true`) can be exported in clear, and the exported bytes are the very
/// key held by the HSM: data encrypted inside the HSM decrypts locally with them.
/// A sensitive key on the same HSM must refuse the export.
pub(super) async fn test_hsm_export_key_bytes() -> KResult<()> {
    let owner = Uuid::new_v4().to_string();
    let mut clap_config = hsm_clap_config(&owner, None)?;
    clap_config.db.sqlite_path = get_tmp_sqlite_path();
    let slot = clap_config.hsm.hsm_slot[0];
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    // --- extractable, non-sensitive key: bytes are exported and are the HSM key
    let extractable_uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_hsm_aes_key(&kms, &owner, &extractable_uid, false).await?;

    let exported = export_object(&kms, &owner, &extractable_uid).await?;
    assert!(!exported.is_wrapped());
    let key_bytes = exported.key_block()?.key_bytes()?;
    assert_eq!(key_bytes.len(), 32);
    assert!(
        key_bytes.iter().any(|b| *b != 0),
        "exported key is all zeros"
    );

    let data = b"export the HSM key bytes";
    let ciphertext = symmetric_encrypt(&extractable_uid, &owner, &kms, data).await?;
    let (nonce, rest) = ciphertext.split_at(12);
    let (encrypted, tag) = rest.split_at(rest.len() - 16);
    let plaintext = decrypt_aead(
        Cipher::aes_256_gcm(),
        &key_bytes,
        Some(nonce),
        &[],
        encrypted,
        tag,
    )?;
    assert_eq!(plaintext, data);

    // --- sensitive key: the export is refused
    let sensitive_uid = as_hsm_uid!(slot, Uuid::new_v4());
    create_hsm_aes_key(&kms, &owner, &sensitive_uid, true).await?;
    let err = export_object(&kms, &owner, &sensitive_uid)
        .await
        .expect_err("a sensitive HSM key must not be exportable");
    assert!(
        matches!(err, KmsError::Kmip21Error(ErrorReason::Sensitive, _)),
        "unexpected error: {err}"
    );

    delete_key(&extractable_uid, &owner, &kms).await?;
    delete_key(&sensitive_uid, &owner, &kms).await?;
    Ok(())
}

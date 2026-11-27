//! Objects wrapped by the server key encryption key are bound to their database row.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::BlockCipherMode,
    kmip_2_1::{
        extra::tagging::{EMPTY_TAGS, VENDOR_ID_COSMIAN},
        kmip_data_structures::{KeyValue, KeyWrappingSpecification},
        kmip_objects::Object,
        kmip_operations::Import,
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, EncodingOption,
            EncryptionKeyInformation, UniqueIdentifier,
        },
        requests::symmetric_key_create_request,
    },
};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS,
        wrapping::{STORED_UID_ATTR, bind_stored_objects, unwrap_object, wrap_object},
    },
    middlewares::UserId,
    result::KResult,
    tests::test_utils::{
        assert_stored_wrapped_by_kek, https_clap_config, test_kms_with_kek, unwrapped_key_bytes,
    },
};

const OWNER: &str = "row-binding-owner";

async fn create_aes_key(kms: &KMS, owner: &UserId) -> KResult<String> {
    let request = symmetric_key_create_request(
        VENDOR_ID_COSMIAN,
        None,
        256,
        CryptographicAlgorithm::AES,
        EMPTY_TAGS,
        false,
        None,
    )?;
    Ok(kms
        .create(request, owner)
        .await?
        .unique_identifier
        .to_string())
}

/// The stored object of `uid`, as it is in the database.
async fn stored_object(kms: &KMS, uid: &str) -> KResult<Object> {
    Ok(kms
        .database
        .retrieve_object(uid)
        .await?
        .unwrap_or_else(|| panic!("{uid} must exist"))
        .object()
        .clone())
}

fn assert_not_bound(result: KResult<Zeroizing<Vec<u8>>>, uid: &str) {
    let error = result.expect_err("the object must be refused").to_string();
    assert!(
        error.contains(&format!(
            "stored object {uid}: key material is not bound to this row"
        )),
        "{error}"
    );
}

/// A ciphertext moved from one row to another is refused; the key keeps working in its row and
/// the binding never leaks into the unwrapped object.
#[tokio::test]
async fn test_swapped_kek_wrapped_rows_are_refused() -> KResult<()> {
    let (kms, kek_id) = test_kms_with_kek("kek-owner", https_clap_config).await?;
    let owner = UserId::from(OWNER);
    let uid_a = create_aes_key(&kms, &owner).await?;
    let uid_b = create_aes_key(&kms, &owner).await?;
    assert_stored_wrapped_by_kek(&kms, &uid_a, &kek_id).await;
    let bytes_a = unwrapped_key_bytes(&kms, &uid_a, &owner).await?;
    let bytes_b = unwrapped_key_bytes(&kms, &uid_b, &owner).await?;
    assert_ne!(bytes_a, bytes_b);

    // an unwrapped key carries no trace of the binding
    let stored_a = stored_object(&kms, &uid_a).await?;
    let unwrapped_a = kms.get_unwrapped(&uid_a, &stored_a, &owner).await?;
    let Some(KeyValue::Structure { attributes, .. }) = unwrapped_a.key_block()?.key_value.as_ref()
    else {
        panic!("the unwrapped key value must be a structure");
    };
    assert!(attributes.as_ref().is_none_or(|attrs| {
        attrs
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, STORED_UID_ATTR)
            .is_none()
    }));

    // a database writer puts B's ciphertext in A's row
    let owm_a = kms.database.retrieve_object(&uid_a).await?.expect("A");
    kms.database
        .update_object(
            &uid_a,
            &stored_object(&kms, &uid_b).await?,
            owm_a.attributes(),
            None,
        )
        .await?;
    assert_not_bound(unwrapped_key_bytes(&kms, &uid_a, &owner).await, &uid_a);
    assert_eq!(unwrapped_key_bytes(&kms, &uid_b, &owner).await?, bytes_b);
    Ok(())
}

/// Wrap `uid`'s key the way versions without row binding did: KEK, no encoding.
async fn store_unbound(kms: &KMS, uid: &str, kek_id: &str, owner: &UserId) -> KResult<()> {
    let owm = kms.database.retrieve_object(uid).await?.expect("object");
    let mut object = kms.get_unwrapped(uid, owm.object(), owner).await?;
    wrap_object(
        &mut object,
        &KeyWrappingSpecification {
            encryption_key_information: Some(EncryptionKeyInformation {
                unique_identifier: UniqueIdentifier::TextString(kek_id.to_owned()),
                cryptographic_parameters: Some(CryptographicParameters {
                    block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
                    ..CryptographicParameters::default()
                }),
            }),
            encoding_option: Some(EncodingOption::NoEncoding),
            ..Default::default()
        },
        kms,
        owner,
    )
    .await?;
    kms.database
        .update_object(uid, &object, owm.attributes(), None)
        .await?;
    Ok(())
}

/// Unbound rows are refused until the startup backfill binds them; a row bound to another row
/// is never re-bound.
#[tokio::test]
async fn test_bind_stored_objects_backfills_unbound_rows() -> KResult<()> {
    let (kms, kek_id) = test_kms_with_kek("kek-owner", https_clap_config).await?;
    let owner = UserId::from(OWNER);
    let uid_a = create_aes_key(&kms, &owner).await?;
    let uid_b = create_aes_key(&kms, &owner).await?;
    let bytes_a = unwrapped_key_bytes(&kms, &uid_a, &owner).await?;

    store_unbound(&kms, &uid_a, &kek_id, &owner).await?;
    assert_not_bound(unwrapped_key_bytes(&kms, &uid_a, &owner).await, &uid_a);

    // B's bound ciphertext in a third row
    let uid_c = create_aes_key(&kms, &owner).await?;
    let owm_c = kms.database.retrieve_object(&uid_c).await?.expect("C");
    kms.database
        .update_object(
            &uid_c,
            &stored_object(&kms, &uid_b).await?,
            owm_c.attributes(),
            None,
        )
        .await?;

    bind_stored_objects(&kms).await?;
    assert_stored_wrapped_by_kek(&kms, &uid_a, &kek_id).await;
    assert_eq!(unwrapped_key_bytes(&kms, &uid_a, &owner).await?, bytes_a);
    assert_not_bound(unwrapped_key_bytes(&kms, &uid_c, &owner).await, &uid_c);
    // running it again changes nothing
    bind_stored_objects(&kms).await?;
    assert_eq!(unwrapped_key_bytes(&kms, &uid_a, &owner).await?, bytes_a);
    Ok(())
}

/// Importing a KEK-wrapped object under a new UID binds it to the new row.
#[tokio::test]
async fn test_import_kek_wrapped_object_binds_new_row() -> KResult<()> {
    let (kms, kek_id) = test_kms_with_kek("kek-owner", https_clap_config).await?;
    // the KEK owner may decrypt with the KEK, hence import KEK-wrapped objects
    let owner = UserId::from("kek-owner");
    let uid = create_aes_key(&kms, &owner).await?;
    let bytes = unwrapped_key_bytes(&kms, &uid, &owner).await?;
    let owm = kms.database.retrieve_object(&uid).await?.expect("object");

    // The previous release unwraps a bound object without checking the binding: the key bytes
    // are intact, and the key value keeps the binding as an attribute (docs: tables.md).
    let mut previous_release_view = owm.object().clone();
    unwrap_object(&mut previous_release_view, &kms, &owner).await?;
    assert_eq!(previous_release_view.key_block()?.key_bytes()?, bytes);
    let Some(KeyValue::Structure {
        attributes: Some(attributes),
        ..
    }) = &previous_release_view.key_block()?.key_value
    else {
        panic!("the bound key value must carry attributes");
    };
    assert!(
        attributes
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, STORED_UID_ATTR)
            .is_some()
    );

    let imported_uid = kms
        .import(
            Import {
                unique_identifier: UniqueIdentifier::TextString("imported-kek-wrapped".to_owned()),
                object_type: owm.object().object_type(),
                attributes: owm.attributes().clone(),
                replace_existing: None,
                key_wrap_type: None,
                object: owm.object().clone(),
            },
            &owner,
        )
        .await?
        .unique_identifier
        .to_string();
    assert_stored_wrapped_by_kek(&kms, &imported_uid, &kek_id).await;
    assert_eq!(
        unwrapped_key_bytes(&kms, &imported_uid, &owner).await?,
        bytes
    );
    Ok(())
}

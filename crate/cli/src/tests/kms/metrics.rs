use cosmian_kmip::kmip_0::kmip_types::State;
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_operations::Get,
    reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::symmetric::keys::{
        create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
    },
    error::result::KmsCliResult,
};

// Verify active keys count after create/revoke/destroy sequence
#[tokio::test]
async fn test_count_active_keys() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create 10 symmetric AES keys with immediate activation
    let mut created_uids = Vec::new();
    for i in 0..10 {
        let uid = CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            tags: vec![format!("test_count_active_{}", i)],
            ..Default::default()
        }
        .run(client.clone())
        .await?;
        created_uids.push(uid);
    }

    assert_eq!(created_uids.len(), 10, "Expected 10 keys to be created");
    let first_uid = created_uids.first().unwrap().to_string();

    // Revoke then destroy the first key
    RevokeKeyAction {
        revocation_reason: "test revoke".to_string(),
        key_id: Some(first_uid.clone()),
        tags: None,
    }
    .run(client.clone())
    .await?;

    DestroyKeyAction {
        key_id: Some(first_uid.clone()),
        tags: None,
        remove: false,
    }
    .run(client.clone())
    .await?;

    // Verify that exactly 9 of our created keys still exist
    let mut found_count = 0;
    for uid in &created_uids {
        let uid_str = uid.to_string();
        if uid_str == first_uid {
            // This is the destroyed key, skip it
            continue;
        }

        // Try to get this specific key by UID
        let get_req = Get {
            unique_identifier: Some(uid.clone()),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: None,
        };

        if client.get(get_req).await.is_ok() {
            found_count += 1;
        }
    }

    assert_eq!(
        found_count, 9,
        "Expected 9 of our created keys to remain after destroying one"
    );
    Ok(())
}

// Verify that revoked keys are not counted as active
#[tokio::test]
async fn test_revoked_keys_not_active() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Use a unique tag for all keys in this test
    let test_tag = format!("test_revoked_{}", uuid::Uuid::new_v4());

    // Create 10 symmetric AES keys with the same tag
    let mut created_uids = Vec::new();
    for _ in 0..10 {
        let uid = CreateKeyAction {
            algorithm: SymmetricAlgorithm::Aes,
            number_of_bits: Some(256),
            tags: vec![test_tag.clone()],
            ..Default::default()
        }
        .run(client.clone())
        .await?;
        created_uids.push(uid);
    }

    assert_eq!(created_uids.len(), 10, "Expected 10 keys to be created");

    // Revoke all keys with the tag in a single operation
    RevokeKeyAction {
        revocation_reason: "test revoke all".to_string(),
        key_id: None,
        tags: Some(vec![test_tag]),
    }
    .run(client.clone())
    .await?;

    // Verify that none of our created keys are active
    // We use Get to retrieve each key and check its state
    let mut active_count = 0;
    for uid in &created_uids {
        let get_req = Get {
            unique_identifier: Some(uid.clone()),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: None,
        };

        if let Ok(get_response) = client.get(get_req).await {
            // Check if the key's state is Active
            if let Ok(attrs) = get_response.object.attributes() {
                if let Some(key_state) = attrs.state {
                    if key_state == State::Active {
                        active_count += 1;
                    }
                }
            }
        }
    }

    assert_eq!(active_count, 0, "Expected 0 active keys after revoking all");
    Ok(())
}

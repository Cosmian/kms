use std::ops::Deref;

use cosmian_findex_cli::{
    actions::{
        findex::FindexParameters,
        permissions::{GrantPermission, RevokePermission},
    },
    reexports::cosmian_findex_structs::{Permission, Uuids},
};
use cosmian_kms_cli::actions::symmetric::{
    DataEncryptionAlgorithm, keys::create_key::CreateKeyAction,
};
use cosmian_logger::log_init;
use tracing::trace;
use uuid::Uuid;

use super::{add::add_cmd, delete::delete_cmd, search::search_cmd};
use crate::{
    actions::{
        delete_datasets::DeleteDatasetAction, encrypt_and_index::EncryptAndIndexAction,
        search_and_decrypt::SearchAndDecryptAction,
    },
    error::result::CosmianResult,
    tests::{
        findex::permissions::{create_index_id_cmd, grant_permission_cmd, revoke_permission_cmd},
        kms::create_key::create_symmetric_key,
    },
};

#[allow(dead_code)]
fn add(
    cli_conf_path: &str,
    index_id: &Uuid,
    kek_id: Option<&str>,
    dek_id: Option<&str>,
) -> CosmianResult<Uuids> {
    let uuids = add_cmd(cli_conf_path, EncryptAndIndexAction {
        findex_parameters: FindexParameters {
            key: "11223344556677889900AABBCCDDEEFF".to_owned(),
            label: "My Findex label".to_owned(),
            index_id: index_id.to_owned(),
        },
        csv_path: "../../test_data/datasets/smallpop.csv".into(),
        key_encryption_key_id: kek_id.map(std::borrow::ToOwned::to_owned),
        data_encryption_key_id: dek_id.map(std::borrow::ToOwned::to_owned),
        data_encryption_algorithm: DataEncryptionAlgorithm::AesGcm,
        nonce: None,
        authentication_data: None,
    })?;
    trace!("add: uuids: {uuids}");
    assert_eq!(uuids.len(), 10);
    Ok(uuids)
}

fn delete(cli_conf_path: &str, index_id: &Uuid, uuids: &Uuids) -> CosmianResult<()> {
    delete_cmd(cli_conf_path, &DeleteDatasetAction {
        index_id: index_id.to_owned(),
        uuid: uuids.deref().clone(),
    })?;
    Ok(())
}

fn search(
    cli_conf_path: &str,
    index_id: &Uuid,
    kek_id: Option<&str>,
    dek_id: Option<&str>,
) -> CosmianResult<String> {
    search_cmd(cli_conf_path, SearchAndDecryptAction {
        findex_parameters: FindexParameters {
            key: "11223344556677889900AABBCCDDEEFF".to_owned(),
            label: "My Findex label".to_owned(),
            index_id: index_id.to_owned(),
        },
        key_encryption_key_id: kek_id.map(std::borrow::ToOwned::to_owned),
        data_encryption_key_id: dek_id.map(std::borrow::ToOwned::to_owned),
        data_encryption_algorithm: DataEncryptionAlgorithm::AesGcm,
        keyword: vec!["Southborough".to_owned(), "Northbridge".to_owned()],
        authentication_data: None,
    })
}

#[allow(
    clippy::panic_in_result_fn,
    clippy::print_stdout,
    clippy::cognitive_complexity
)]
fn add_search_delete(
    cli_conf_path: &str,
    index_id: &Uuid,
    kek_id: Option<&str>,
    dek_id: Option<&str>,
) -> CosmianResult<()> {
    trace!("add_search_delete: entering");
    let uuids = add(cli_conf_path, index_id, kek_id, dek_id)?;
    trace!("add_search_delete: add: uuids: {uuids}");

    // make sure searching returns the expected results
    let search_results = search(cli_conf_path, index_id, kek_id, dek_id)?;
    trace!("add_search_delete: search_results: {search_results}");
    assert!(search_results.contains("States9686")); // for Southborough
    assert!(search_results.contains("States14061")); // for Northbridge

    delete(cli_conf_path, index_id, &uuids)?;

    // make sure no results are returned after deletion
    let rerun_search_results = search(cli_conf_path, index_id, kek_id, dek_id)?;
    trace!(
        "add_search_delete: re-search_results (len={}): {rerun_search_results}",
        rerun_search_results.len()
    );
    assert!(!rerun_search_results.contains("States9686")); // for Southborough
    assert!(!rerun_search_results.contains("States14061")); // for Northbridge

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_encrypt_and_add_no_auth() -> CosmianResult<()> {
    log_init(None);

    let cli_conf_path = "../../test_data/configs/cosmian.toml";

    let kek_or_dek_id = create_symmetric_key(cli_conf_path, CreateKeyAction::default())?;

    add_search_delete(cli_conf_path, &Uuid::new_v4(), Some(&kek_or_dek_id), None)?;
    add_search_delete(cli_conf_path, &Uuid::new_v4(), None, Some(&kek_or_dek_id))?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_encrypt_and_add_cert_auth() -> CosmianResult<()> {
    log_init(None);

    let owner_client_conf_path = "../../test_data/configs/cosmian_cert_auth_owner.toml";

    let kek_id = create_symmetric_key(owner_client_conf_path, CreateKeyAction::default())?;

    let index_id = create_index_id_cmd(owner_client_conf_path)?;
    trace!("index_id: {index_id}");

    add_search_delete(owner_client_conf_path, &index_id, Some(&kek_id), None)?;
    Ok(())
}

#[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
#[tokio::test]
pub(crate) async fn test_encrypt_and_add_grant_and_revoke_permission() -> CosmianResult<()> {
    log_init(None);

    let owner_client_conf_path = "../../test_data/configs/cosmian_cert_auth_owner.toml";
    let user_client_conf_path = "../../test_data/configs/cosmian_cert_auth_user.toml";

    let kek_id = create_symmetric_key(owner_client_conf_path, CreateKeyAction::default())?;

    let index_id = create_index_id_cmd(owner_client_conf_path)?;
    trace!("index_id: {index_id}");

    add(owner_client_conf_path, &index_id, Some(&kek_id), None)?;

    // Grant read permission to the client
    grant_permission_cmd(owner_client_conf_path, &GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Read,
    })?;

    // User can read...
    let search_results = search(user_client_conf_path, &index_id, Some(&kek_id), None)?;
    assert!(search_results.contains("States9686")); // for Southborough
    assert!(search_results.contains("States14061")); // for Northbridge

    // ... but not write
    assert!(add(user_client_conf_path, &index_id, Some(&kek_id), None).is_err());

    // Grant write permission
    grant_permission_cmd(owner_client_conf_path, &GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Write,
    })?;

    // User can read...
    let search_results = search(user_client_conf_path, &index_id, Some(&kek_id), None)?;
    assert!(search_results.contains("States9686")); // for Southborough
    assert!(search_results.contains("States14061")); // for Northbridge

    // ... and write
    add(user_client_conf_path, &index_id, Some(&kek_id), None)?;

    // Try to escalade privileges from `read` to `admin`
    grant_permission_cmd(user_client_conf_path, &GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Admin,
    })
    .unwrap_err();

    revoke_permission_cmd(owner_client_conf_path, &RevokePermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
    })?;

    search(user_client_conf_path, &index_id, Some(&kek_id), None).unwrap_err();

    Ok(())
}

#[allow(clippy::panic_in_result_fn)]
#[tokio::test]
pub(crate) async fn test_encrypt_and_add_no_permission() -> CosmianResult<()> {
    log_init(None);
    let owner_client_conf_path = "../../test_data/configs/cosmian_cert_auth_owner.toml";
    let user_client_conf_path = "../../test_data/configs/cosmian_cert_auth_user.toml";

    let kek_id = create_symmetric_key(owner_client_conf_path, CreateKeyAction::default())?;

    assert!(
        add_search_delete(user_client_conf_path, &Uuid::new_v4(), Some(&kek_id), None).is_err()
    );
    Ok(())
}

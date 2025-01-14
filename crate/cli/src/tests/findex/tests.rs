use std::ops::Deref;

use cosmian_config_utils::ConfigUtils;
use cosmian_findex_cli::{
    actions::{
        datasets::DeleteEntries,
        findex::FindexParameters,
        permissions::{CreateIndex, GrantPermission, RevokePermission},
    },
    reexports::{
        cosmian_findex_client::FindexRestClient,
        cosmian_findex_structs::{Permission, Uuids},
    },
};
use cosmian_kms_cli::{
    actions::symmetric::{keys::create_key::CreateKeyAction, DataEncryptionAlgorithm},
    reexport::cosmian_kms_client::{kmip_2_1::kmip_types::UniqueIdentifier, KmsClient},
};
use cosmian_logger::log_init;
use lazy_static::lazy_static;
use tracing::trace;
use uuid::Uuid;

use crate::{
    actions::{
        encrypt_and_index::EncryptAndIndexAction, search_and_decrypt::SearchAndDecryptAction,
    },
    config::ClientConf,
    error::result::CosmianResult,
};

struct TestClients {
    pub kms: KmsClient,
    pub findex: FindexRestClient,
}

struct AdminAndUsers {
    pub no_auth: TestClients,
    pub admin: TestClients,
    pub users: TestClients,
}

lazy_static! {
    static ref CLIENTS: AdminAndUsers = {
        let no_auth_clients = instantiate_clients("../../test_data/configs/cosmian.toml").unwrap();
        let owner_clients =
            instantiate_clients("../../test_data/configs/cosmian_cert_auth_owner.toml").unwrap();
        let user_clients =
            instantiate_clients("../../test_data/configs/cosmian_cert_auth_user.toml").unwrap();
        AdminAndUsers {
            no_auth: no_auth_clients,
            admin: owner_clients,
            users: user_clients,
        }
    };
}

async fn index(
    findex: &FindexRestClient,
    kms: &KmsClient,
    index_id: &Uuid,
    kek_id: Option<&UniqueIdentifier>,
    dek_id: Option<&UniqueIdentifier>,
) -> CosmianResult<Uuids> {
    let uuids = EncryptAndIndexAction {
        findex_parameters: FindexParameters {
            key: "11223344556677889900AABBCCDDEEFF".to_owned(),
            label: "My Findex label".to_owned(),
            index_id: index_id.to_owned(),
        },
        csv_path: "../../test_data/datasets/smallpop.csv".into(),
        key_encryption_key_id: kek_id.map(std::string::ToString::to_string),
        data_encryption_key_id: dek_id.map(std::string::ToString::to_string),
        data_encryption_algorithm: DataEncryptionAlgorithm::AesGcm,
        nonce: None,
        authentication_data: None,
    }
    .run(findex, kms)
    .await?;
    trace!("index: uuids: {uuids}");
    assert_eq!(uuids.len(), 10);
    Ok(uuids)
}

async fn delete(
    findex: &FindexRestClient,
    index_id: &Uuid,
    uuids: &Uuids,
) -> CosmianResult<String> {
    Ok(DeleteEntries {
        index_id: index_id.to_owned(),
        uuids: uuids.deref().clone(),
    }
    .run(findex)
    .await?)
}

async fn search(
    findex: &FindexRestClient,
    kms: &KmsClient,
    index_id: &Uuid,
    kek_id: Option<&UniqueIdentifier>,
    dek_id: Option<&UniqueIdentifier>,
) -> CosmianResult<Vec<String>> {
    SearchAndDecryptAction {
        findex_parameters: FindexParameters {
            key: "11223344556677889900AABBCCDDEEFF".to_owned(),
            label: "My Findex label".to_owned(),
            index_id: index_id.to_owned(),
        },
        key_encryption_key_id: kek_id.map(std::string::ToString::to_string),
        data_encryption_key_id: dek_id.map(std::string::ToString::to_string),
        data_encryption_algorithm: DataEncryptionAlgorithm::AesGcm,
        keyword: vec!["Southborough".to_owned(), "Northbridge".to_owned()],
        authentication_data: None,
    }
    .run(findex, kms)
    .await
}

fn contains_substring(results: &[String], substring: &str) -> bool {
    results.iter().any(|result| result.contains(substring))
}

#[allow(
    clippy::panic_in_result_fn,
    clippy::print_stdout,
    clippy::cognitive_complexity
)]
async fn index_search_delete(
    findex: &FindexRestClient,
    kms: &KmsClient,
    index_id: &Uuid,
    kek_id: Option<&UniqueIdentifier>,
    dek_id: Option<&UniqueIdentifier>,
) -> CosmianResult<()> {
    trace!("index_search_delete: entering");
    let uuids = index(findex, kms, index_id, kek_id, dek_id).await?;
    trace!("index_search_delete: index: uuids: {uuids}");

    // make sure searching returns the expected results
    let search_results = search(findex, kms, index_id, kek_id, dek_id).await?;
    trace!("index_search_delete: search_results: {search_results:?}");
    assert!(contains_substring(&search_results, "States9686")); // for Southborough
    assert!(contains_substring(&search_results, "States14061")); // for Northbridge

    delete(findex, index_id, &uuids).await?;

    // make sure no results are returned after deletion
    let rerun_search_results = search(findex, kms, index_id, kek_id, dek_id).await?;
    trace!(
        "index_search_delete: re-search_results (len={}): {rerun_search_results:?}",
        rerun_search_results.len()
    );
    assert!(!contains_substring(&rerun_search_results, "States9686")); // for Southborough
    assert!(!contains_substring(&rerun_search_results, "States14061")); // for Northbridge

    Ok(())
}

fn instantiate_clients(conf_path: &str) -> CosmianResult<TestClients> {
    let client_config = ClientConf::from_toml(conf_path)?;
    let kms = KmsClient::new(client_config.kms_config)?;
    let findex = FindexRestClient::new(client_config.findex_config.unwrap())?;
    Ok(TestClients { kms, findex })
}

#[tokio::test]
pub(crate) async fn test_encrypt_and_index_no_auth() -> CosmianResult<()> {
    log_init(None);

    let kek_or_dek_id = CreateKeyAction::default().run(&CLIENTS.no_auth.kms).await?;

    index_search_delete(
        &CLIENTS.no_auth.findex,
        &CLIENTS.no_auth.kms,
        &Uuid::new_v4(),
        Some(&kek_or_dek_id),
        None,
    )
    .await?;
    index_search_delete(
        &CLIENTS.no_auth.findex,
        &CLIENTS.no_auth.kms,
        &Uuid::new_v4(),
        None,
        Some(&kek_or_dek_id),
    )
    .await?;
    Ok(())
}

#[tokio::test]
pub(crate) async fn test_encrypt_and_index_cert_auth() -> CosmianResult<()> {
    log_init(None);

    let kek_id = CreateKeyAction::default().run(&CLIENTS.admin.kms).await?;

    let index_id = CreateIndex.run(&CLIENTS.admin.findex).await?;
    trace!("index_id: {index_id}");

    index_search_delete(
        &CLIENTS.admin.findex,
        &CLIENTS.admin.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await?;
    Ok(())
}

#[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
#[tokio::test]
pub(crate) async fn test_encrypt_and_index_grant_and_revoke_permission() -> CosmianResult<()> {
    log_init(None);

    let kek_id = CreateKeyAction::default().run(&CLIENTS.admin.kms).await?;

    let index_id = CreateIndex.run(&CLIENTS.admin.findex).await?;
    trace!("index_id: {index_id}");

    index(
        &CLIENTS.admin.findex,
        &CLIENTS.admin.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await?;

    // Grant read permission to the client
    GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Read,
    }
    .run(&CLIENTS.admin.findex)
    .await?;

    // User can read...
    let search_results = search(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await?;
    assert!(contains_substring(&search_results, "States9686")); // for Southborough
    assert!(contains_substring(&search_results, "States14061")); // for Northbridge

    // ... but not write
    assert!(index(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &index_id,
        Some(&kek_id),
        None
    )
    .await
    .is_err());

    // Grant write permission
    GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Write,
    }
    .run(&CLIENTS.admin.findex)
    .await?;

    // User can read...
    let search_results = search(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await?;
    assert!(contains_substring(&search_results, "States9686")); // for Southborough
    assert!(contains_substring(&search_results, "States14061")); // for Northbridge

    // ... and write
    index(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await?;

    // Try to escalade privileges from `read` to `admin`
    GrantPermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
        permission: Permission::Admin,
    }
    .run(&CLIENTS.users.findex)
    .await
    .unwrap_err();

    RevokePermission {
        user: "user.client@acme.com".to_owned(),
        index_id,
    }
    .run(&CLIENTS.admin.findex)
    .await?;

    search(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &index_id,
        Some(&kek_id),
        None,
    )
    .await
    .unwrap_err();

    Ok(())
}

#[allow(clippy::panic_in_result_fn)]
#[tokio::test]
pub(crate) async fn test_encrypt_and_index_no_permission() -> CosmianResult<()> {
    log_init(None);

    let kek_id = CreateKeyAction::default().run(&CLIENTS.admin.kms).await?;

    assert!(index_search_delete(
        &CLIENTS.users.findex,
        &CLIENTS.users.kms,
        &Uuid::new_v4(),
        Some(&kek_id),
        None
    )
    .await
    .is_err());
    Ok(())
}

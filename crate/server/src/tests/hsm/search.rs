use std::{ops::Add, sync::Arc};

use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier::TextString;
use cosmian_kms_interfaces::as_hsm_uid;
use uuid::Uuid;

use crate::{
    config::ServerParams,
    core::KMS,
    result::KResult,
    tests::{
        hsm::{
            create_key_pair, create_sym_key, delete_all_keys, delete_key, hsm_clap_config,
            locate_keys,
        },
        test_utils::get_tmp_sqlite_path,
    },
};

pub(super) async fn test_object_search() -> KResult<()> {
    let rsa_uuid = Uuid::new_v4();
    let aes_uuid = Uuid::new_v4();
    let owner = Uuid::new_v4().to_string();

    let sqlite_path = get_tmp_sqlite_path();

    let mut clap_config = hsm_clap_config(&owner, None)?;
    clap_config.db.sqlite_path = sqlite_path.clone();
    let rsa_uid = as_hsm_uid!(clap_config.hsm_slot[0], rsa_uuid);
    let aes_uid = as_hsm_uid!(clap_config.hsm_slot[0], aes_uuid);
    let kms = Arc::new(KMS::instantiate(Arc::new(ServerParams::try_from(clap_config)?)).await?);

    delete_all_keys(&owner, &kms).await?;
    create_sym_key(&aes_uid, &owner, &kms).await?;
    let mut found = locate_keys(&owner, &kms).await?;
    assert_eq!(found.len(), 1);
    assert!(found.contains(&TextString(aes_uid.clone())));

    create_key_pair(&rsa_uid, &owner, &kms).await?;
    found = locate_keys(&owner, &kms).await?;
    assert_eq!(found.len(), 3);
    assert!(found.contains(&TextString(rsa_uid.clone())));
    assert!(found.contains(&TextString(rsa_uid.clone().add("_pk"))));

    delete_key(&rsa_uid, &owner, &kms).await?;
    found = locate_keys(&owner, &kms).await?;
    assert_eq!(found.len(), 2);

    delete_key(&rsa_uid.clone().add("_pk"), &owner, &kms).await?;
    found = locate_keys(&owner, &kms).await?;
    assert_eq!(found.len(), 1);

    delete_key(&aes_uid, &owner, &kms).await?;
    found = locate_keys(&owner, &kms).await?;
    assert_eq!(found.len(), 0);

    Ok(())
}

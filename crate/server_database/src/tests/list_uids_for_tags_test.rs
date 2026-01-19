use std::collections::HashSet;

use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, kmip_types::CryptographicAlgorithm,
    requests::create_symmetric_key_kmip_object,
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
use uuid::Uuid;

use crate::error::DbResult;

pub(super) async fn list_uids_for_tags_test<DB: ObjectsStore + PermissionsStore>(
    db: &DB,
) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = Uuid::new_v4().to_string();

    let tag1 = Uuid::new_v4().to_string();
    let tag2 = Uuid::new_v4().to_string();

    // Create a first symmetric key with tag "tag1"
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )?;

    let uid1 = Uuid::new_v4().to_string();

    db.create(
        Some(uid1.clone()),
        owner.as_str(),
        &symmetric_key,
        symmetric_key.attributes()?,
        &HashSet::from([tag1.clone()]),
    )
    .await?;

    // Create a first symmetric key with tag "tag1" and tag "tag2"
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )?;

    let uid2 = Uuid::new_v4().to_string();

    db.create(
        Some(uid2.clone()),
        owner.as_str(),
        &symmetric_key,
        symmetric_key.attributes()?,
        &HashSet::from([tag1.clone(), tag2.clone()]),
    )
    .await?;

    // List yids for tag "tag1"
    let uids = db
        .list_uids_for_tags(&HashSet::from([tag1.clone()]))
        .await?;
    assert_eq!(uids.len(), 2);
    assert!(uids.contains(&uid1));

    // List uids for tag2
    let uids = db
        .list_uids_for_tags(&HashSet::from([tag2.clone()]))
        .await?;
    assert_eq!(uids.len(), 1);
    assert!(uids.contains(&uid2));

    // List uids for tag1 and tag2
    let uids = db
        .list_uids_for_tags(&HashSet::from([tag1.clone(), tag2.clone()]))
        .await?;
    assert_eq!(uids.len(), 1);
    assert!(uids.contains(&uid2));

    Ok(())
}

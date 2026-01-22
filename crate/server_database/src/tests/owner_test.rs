use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        KmipOperation, kmip_attributes::Attributes, kmip_types::CryptographicAlgorithm,
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore};
use uuid::Uuid;

use crate::{db_error, error::DbResult};

pub(super) async fn owner<DB: ObjectsStore + PermissionsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";
    let user_id_1 = "user_id_1@example.org";
    let user_id_2 = "user_id_2@example.org";
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Attributes::default()
        },
    )?;
    let uid = Uuid::new_v4().to_string();

    db.create(
        Some(uid.clone()),
        owner,
        &symmetric_key,
        symmetric_key.attributes()?,
        &HashSet::new(),
    )
    .await?;

    assert!(db.is_object_owned_by(&uid, owner).await?);
    assert!(!db.is_object_owned_by(&uid, "INVALID OWNER").await?);

    // Retrieve the object and check the owner
    let obj = db
        .retrieve(&uid)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(State::PreActive, obj.state());
    assert_eq!(&symmetric_key, obj.object());
    assert_eq!(owner, obj.owner());

    // Grant `Get` operation to `userid 1`
    db.grant_operations(&uid, user_id_1, HashSet::from([KmipOperation::Get]))
        .await?;

    // User `userid` should only have the `Get` operation
    let operations = db
        .list_user_operations_on_object(&uid, user_id_1, false)
        .await?;
    assert_eq!(operations.len(), 1);
    assert!(operations.contains(&KmipOperation::Get));
    assert!(!operations.contains(&KmipOperation::Create));

    // Add authorized `userid2` to `read_access` table
    db.grant_operations(&uid, user_id_2, HashSet::from([KmipOperation::Get]))
        .await?;

    // Try to add same access again - OK
    db.grant_operations(&uid, user_id_2, HashSet::from([KmipOperation::Get]))
        .await?;

    // User `userid` should only have the `Get` operation
    let operations = db
        .list_user_operations_on_object(&uid, user_id_2, false)
        .await?;
    assert_eq!(operations.len(), 1);
    assert!(operations.contains(&KmipOperation::Get));
    assert!(!operations.contains(&KmipOperation::Create));

    // We should still be able to find the object by its owner
    let objects = db.find(None, None, owner, true).await?;
    assert_eq!(objects.len(), 1);
    let (o_uid, o_state, _) = &objects[0];
    assert_eq!(o_uid, &uid);
    assert_eq!(o_state, &State::PreActive);

    // We should not be able to find the object by specifying  that user_id_2 is the owner
    let objects = db.find(None, None, user_id_2, true).await?;
    assert!(objects.is_empty());

    let objects = db.list_user_operations_granted(user_id_2).await?;
    assert_eq!(
        objects[&uid],
        (
            String::from(owner),
            State::PreActive,
            vec![KmipOperation::Get].into_iter().collect(),
        )
    );

    Ok(())
}

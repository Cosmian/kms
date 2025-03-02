use std::{collections::HashSet, sync::Arc};

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::kmip_2_1::{
    kmip_types::{CryptographicAlgorithm, StateEnumeration},
    requests::create_symmetric_key_kmip_object,
    KmipOperation,
};
use cosmian_kms_interfaces::{ObjectsStore, PermissionsStore, SessionParams};
use uuid::Uuid;

use crate::{db_error, error::DbResult};

pub(crate) async fn owner<DB: ObjectsStore + PermissionsStore>(
    db: &DB,
    db_params: Option<Arc<dyn SessionParams>>,
) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";
    let user_id_1 = "user_id_1@example.org";
    let user_id_2 = "user_id_2@example.org";
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES, false)?;
    let uid = Uuid::new_v4().to_string();

    db.create(
        Some(uid.clone()),
        owner,
        &symmetric_key,
        symmetric_key.attributes()?,
        &HashSet::new(),
        db_params.clone(),
    )
    .await?;

    assert!(
        db.is_object_owned_by(&uid, owner, db_params.clone())
            .await?
    );
    assert!(
        !db.is_object_owned_by(&uid, "INVALID OWNER", db_params.clone())
            .await?
    );

    // Retrieve the object and check the owner
    let obj = db
        .retrieve(&uid, db_params.clone())
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(StateEnumeration::Active, obj.state());
    assert_eq!(&symmetric_key, obj.object());
    assert_eq!(owner, obj.owner());

    // Grant `Get` operation to `userid 1`
    db.grant_operations(
        &uid,
        user_id_1,
        HashSet::from([KmipOperation::Get]),
        db_params.clone(),
    )
    .await?;

    // User `userid` should only have the `Get` operation
    let operations = db
        .list_user_operations_on_object(&uid, user_id_1, false, db_params.clone())
        .await?;
    assert_eq!(operations.len(), 1);
    assert!(operations.contains(&KmipOperation::Get));
    assert!(!operations.contains(&KmipOperation::Create));

    // Add authorized `userid2` to `read_access` table
    db.grant_operations(
        &uid,
        user_id_2,
        HashSet::from([KmipOperation::Get]),
        db_params.clone(),
    )
    .await?;

    // Try to add same access again - OK
    db.grant_operations(
        &uid,
        user_id_2,
        HashSet::from([KmipOperation::Get]),
        db_params.clone(),
    )
    .await?;

    // User `userid` should only have the `Get` operation
    let operations = db
        .list_user_operations_on_object(&uid, user_id_2, false, db_params.clone())
        .await?;
    assert_eq!(operations.len(), 1);
    assert!(operations.contains(&KmipOperation::Get));
    assert!(!operations.contains(&KmipOperation::Create));

    // We should still be able to find the object by its owner
    let objects = db.find(None, None, owner, true, db_params.clone()).await?;
    assert_eq!(objects.len(), 1);
    let (o_uid, o_state, _) = &objects[0];
    assert_eq!(o_uid, &uid);
    assert_eq!(o_state, &StateEnumeration::Active);

    // We should not be able to find the object by specifying  that user_id_2 is the owner
    let objects = db
        .find(None, None, user_id_2, true, db_params.clone())
        .await?;
    assert!(objects.is_empty());

    let objects = db
        .list_user_operations_granted(user_id_2, db_params)
        .await?;
    assert_eq!(
        objects[&uid],
        (
            String::from(owner),
            StateEnumeration::Active,
            vec![KmipOperation::Get].into_iter().collect(),
        )
    );

    Ok(())
}

#![allow(clippy::indexing_slicing)] // Test file uses safe indexing patterns

use std::{collections::HashSet, sync::Arc};

use cosmian_kmip::{
    KmipResultHelper,
    kmip_0::kmip_types::State,
    kmip_2_1::{
        KmipOperation, kmip_attributes::Attributes, kmip_types::CryptographicAlgorithm,
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng, RandomFixedSizeCBytes, Secret, SymmetricKey,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_logger::trace;
use redis::aio::ConnectionManager;

use crate::{
    error::DbResult,
    stores::redis::{
        init_findex_redis,
        objects_db::{ObjectsDB, RedisDbObject},
        permissions::{ObjectUid, PermissionDB, UserId},
    },
    tests::get_redis_url,
};

async fn clear_all(mgr: &mut ConnectionManager) -> DbResult<()> {
    redis::cmd("FLUSHDB").query_async::<()>(mgr).await?;
    Ok(())
}

pub(crate) async fn test_objects_db() -> DbResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    trace!("test_objects_db");

    let mut rng = CsRng::from_entropy();
    let client = redis::Client::open(get_redis_url())?;
    let mgr = ConnectionManager::new(client).await?;

    let db_key = SymmetricKey::new(&mut rng);
    let o_db = ObjectsDB::new(mgr.clone(), &db_key);

    // clean up
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut mgr.clone())
        .await?;

    // single upsert - get - delete
    let uid = "test_objects_db";

    let mut symmetric_key = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key);
    let object = create_symmetric_key_kmip_object(
        &symmetric_key,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    // check that the object is not there
    assert!(o_db.object_get(uid).await?.is_none());

    o_db.object_upsert(
        uid,
        &RedisDbObject::new(
            object.clone(),
            "owner".to_owned(),
            State::Active,
            Some(HashSet::new()),
            object.attributes()?.clone(),
        ),
    )
    .await?;
    let redis_db_object = o_db.object_get(uid).await?.context("object not found")?;
    assert_eq!(
        object.key_block()?.key_bytes()?,
        redis_db_object.object.key_block()?.key_bytes()?
    );
    assert_eq!(redis_db_object.owner, "owner");
    assert_eq!(redis_db_object.state, State::Active);

    o_db.object_delete(uid).await?;
    assert!(o_db.object_get(uid).await?.is_none());

    Ok(())
}

pub(crate) async fn test_permissions_db() -> DbResult<()> {
    // generate the findex key
    let mut rng = CsRng::from_entropy();
    let findex_master_key = Secret::random(&mut rng);

    let redis_url = get_redis_url();
    let client = redis::Client::open(redis_url.clone())?;
    let mut mgr = ConnectionManager::new(client).await?;

    // clear the DB
    clear_all(&mut mgr).await?;

    // create the findex
    let findex_arc = Arc::new(init_findex_redis(&findex_master_key, redis_url.as_str()).await?);
    let permissions_db = PermissionDB::new(findex_arc);

    let object1 = ObjectUid("O1".to_owned());
    let user1 = UserId("U1".to_owned());

    // let us add the permission Encrypt on object O1 for user U1
    permissions_db
        .add(&object1, &user1, KmipOperation::Encrypt)
        .await?;

    // verify that the permission is present
    let permissions = permissions_db.get(&object1, &user1, false).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&KmipOperation::Encrypt));

    // find the permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&user1));
    assert_eq!(permissions[&user1], HashSet::from([KmipOperation::Encrypt]));

    // add the permission Decrypt to user U1 for object O1
    permissions_db
        .add(&object1, &user1, KmipOperation::Decrypt)
        .await?;

    // assert the permission is present
    let permissions = permissions_db.get(&object1, &user1, false).await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains(&KmipOperation::Encrypt));
    assert!(permissions.contains(&KmipOperation::Decrypt));

    // find the permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt, KmipOperation::Decrypt])
    );

    // find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&user1));
    assert_eq!(
        permissions[&user1],
        HashSet::from([KmipOperation::Encrypt, KmipOperation::Decrypt])
    );

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt

    // let's add another user and object
    let object2 = ObjectUid("O2".to_owned());
    let user2 = UserId("U2".to_owned());

    // let us add the permission Encrypt on object O1 for user U2
    permissions_db
        .add(&object1, &user2, KmipOperation::Encrypt)
        .await?;
    // assert the permission is present
    let permissions = permissions_db.get(&object1, &user2, false).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&KmipOperation::Encrypt));

    // find the permissions for user U2
    let permissions = permissions_db.list_user_permissions(&user2).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt])
    );

    //find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key(&user1));
    assert_eq!(
        permissions[&user1],
        HashSet::from([KmipOperation::Encrypt, KmipOperation::Decrypt])
    );
    assert!(permissions.contains_key(&user2));
    assert_eq!(permissions[&user2], HashSet::from([KmipOperation::Encrypt]));

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt
    // O1 -> U2 -> Encrypt

    // let us add the permission Encrypt on object O2 for user U2
    permissions_db
        .add(&object2, &user2, KmipOperation::Encrypt)
        .await?;
    // assert the permission is present
    let permissions = permissions_db.get(&object2, &user2, false).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&KmipOperation::Encrypt));

    // find the permissions for user U2
    let permissions = permissions_db.list_user_permissions(&user2).await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt])
    );
    assert!(permissions.contains_key(&object2));
    assert_eq!(
        permissions[&object2],
        HashSet::from([KmipOperation::Encrypt])
    );

    // find the permission for the object O2
    let permissions = permissions_db.list_object_permissions(&object2).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&user2));
    assert_eq!(permissions[&user2], HashSet::from([KmipOperation::Encrypt]));

    // the situation now is that we have
    // O1 -> U1 -> Encrypt, Decrypt
    // O1 -> U2 -> Encrypt
    // O2 -> U2 -> Encrypt

    // let us remove the permission Decrypt on object O1 for user U1
    permissions_db
        .remove(&object1, &user1, KmipOperation::Decrypt)
        .await?;
    // assert the permission Encrypt is present and Decrypt is not
    let permissions = permissions_db.get(&object1, &user1, false).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains(&KmipOperation::Encrypt));

    // find the permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt])
    );

    // find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 2);
    assert!(permissions.contains_key(&user1));
    assert_eq!(permissions[&user1], HashSet::from([KmipOperation::Encrypt]));
    assert!(permissions.contains_key(&user2));
    assert_eq!(permissions[&user2], HashSet::from([KmipOperation::Encrypt]));

    // let us remove the permission Encrypt on object O1 for user U1
    permissions_db
        .remove(&object1, &user1, KmipOperation::Encrypt)
        .await?;
    // assert the permission is not present
    let permissions = permissions_db.get(&object1, &user1, false).await?;
    assert_eq!(permissions.len(), 0);

    // find the permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 0);

    // find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&user2));
    assert_eq!(permissions[&user2], HashSet::from([KmipOperation::Encrypt]));

    // let us remove the permission Encrypt on object O1 for user U2
    permissions_db
        .remove(&object1, &user2, KmipOperation::Encrypt)
        .await?;
    // assert the permission is not present
    let permissions = permissions_db.get(&object1, &user2, false).await?;
    assert_eq!(permissions.len(), 0);

    // find the permissions for user U2
    let permissions = permissions_db.list_user_permissions(&user2).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object2));
    assert_eq!(
        permissions[&object2],
        HashSet::from([KmipOperation::Encrypt])
    );

    // find the permission for the object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 0);

    Ok(())
}

pub(crate) async fn test_corner_case() -> DbResult<()> {
    // generate the findex key
    let mut rng = CsRng::from_entropy();
    let findex_master_key = Secret::random(&mut rng);

    let redis_url = get_redis_url();
    let client = redis::Client::open(redis_url.clone())?;
    let mut mgr = ConnectionManager::new(client).await?;

    // clear the DB
    clear_all(&mut mgr).await?;

    // create the findex
    let findex_arc = Arc::new(init_findex_redis(&findex_master_key, redis_url.as_str()).await?);
    let permissions_db = PermissionDB::new(findex_arc);

    let object1 = ObjectUid("O1".to_owned());
    let user1 = UserId("U1".to_owned());

    // test that it does not exist
    let permissions = permissions_db.get(&object1, &user1, false).await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 0);

    // add the permission Encrypt on object O1 for user U1
    permissions_db
        .add(&object1, &user1, KmipOperation::Encrypt)
        .await?;

    // test there is one permission for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&object1));
    assert_eq!(
        permissions[&object1],
        HashSet::from([KmipOperation::Encrypt])
    );

    // test there is one permission for object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 1);
    assert!(permissions.contains_key(&user1));
    assert_eq!(permissions[&user1], HashSet::from([KmipOperation::Encrypt]));

    // remove the permission again
    permissions_db
        .remove(&object1, &user1, KmipOperation::Encrypt)
        .await?;

    // test there are no permissions for user U1
    let permissions = permissions_db.list_user_permissions(&user1).await?;
    assert_eq!(permissions.len(), 0);

    // test there are no permissions for object O1
    let permissions = permissions_db.list_object_permissions(&object1).await?;
    assert_eq!(permissions.len(), 0);

    Ok(())
}

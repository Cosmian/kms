use std::{collections::HashSet, sync::Arc};

use cosmian_kmip::{
    KmipResultHelper,
    kmip_0::kmip_types::State,
    kmip_2_1::{
        KmipOperation,
        extra::tagging::VENDOR_ID_COSMIAN,
        kmip_attributes::Attributes,
        kmip_objects::{Object, OpaqueObject},
        kmip_types::{CryptographicAlgorithm, OpaqueDataType},
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng, RandomFixedSizeCBytes, Secret, SymmetricKey,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::{ObjectsStore as _, UserId};
use cosmian_logger::trace;
use redis::{AsyncCommands, aio::ConnectionManager};

use crate::{
    error::{DbError, DbResult},
    stores::{
        REDIS_WITH_FINDEX_MASTER_KEY_LENGTH, RedisWithFindex,
        redis::{
            init_findex_redis,
            objects_db::{ACTIVE_KEY_COUNT_KEY, LIVE_COUNT_KEY, ObjectsDB, RedisDbObject},
            permissions::{FindexUserId, ObjectUid, PermissionDB},
        },
    },
    tests::get_redis_url,
};

pub(crate) mod issue_940_repro {
    use cosmian_kms_interfaces::AtomicOperation;
    use uuid::Uuid;

    use super::*;

    /// Two clients sharing one Redis database (and master key), flushed first.
    async fn clients(database: u8) -> DbResult<(RedisWithFindex, RedisWithFindex)> {
        let url = format!("{}/{database}", get_redis_url());
        let mut rng = CsRng::from_entropy();
        let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
        let first = RedisWithFindex::instantiate(&url, master_key.clone(), true).await?;
        let second = RedisWithFindex::instantiate(&url, master_key, false).await?;
        Ok((first, second))
    }

    fn key(marker: u8) -> DbResult<Object> {
        Ok(create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[marker; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )?)
    }

    fn upsert(
        uid: &str,
        object: &Object,
        tags: Option<HashSet<String>>,
    ) -> DbResult<AtomicOperation> {
        Ok(AtomicOperation::Upsert((
            uid.to_owned(),
            object.clone(),
            object.attributes()?.clone(),
            tags,
            State::PreActive,
        )))
    }

    struct TagCase {
        uid: String,
        owner: UserId,
        expected_tags: HashSet<String>,
        replace: [AtomicOperation; 1],
        preserve: [AtomicOperation; 1],
    }

    async fn tag_case(writer: &RedisWithFindex) -> DbResult<TagCase> {
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let old_tags = HashSet::from([format!("old-{uid}")]);
        let expected_tags = HashSet::from([format!("new-{uid}")]);
        let first_key = key(2)?;
        writer
            .create(
                Some(uid.clone()),
                &owner,
                &first_key,
                first_key.attributes()?,
                &old_tags,
            )
            .await?;
        Ok(TagCase {
            replace: [upsert(&uid, &first_key, Some(expected_tags.clone()))?],
            preserve: [upsert(&uid, &key(3)?, None)?],
            uid,
            owner,
            expected_tags,
        })
    }

    async fn sequential_controls(
        first: &RedisWithFindex,
        second: &RedisWithFindex,
    ) -> DbResult<()> {
        for replace_first in [true, false] {
            let case = tag_case(first).await?;
            if replace_first {
                first.atomic(&case.owner, &case.replace).await?;
                second.atomic(&case.owner, &case.preserve).await?;
            } else {
                second.atomic(&case.owner, &case.preserve).await?;
                first.atomic(&case.owner, &case.replace).await?;
            }
            let actual = second.retrieve_tags(&case.uid).await?;
            assert_eq!(
                actual, case.expected_tags,
                "Sequential control failed: replace_first={replace_first}"
            );
            eprintln!(
                "T2 sequential control replace_first={replace_first}: PASS uid={} tags={actual:?}",
                case.uid
            );
        }
        Ok(())
    }

    pub(crate) async fn t1_removed_tag_must_not_select_existing_object() -> DbResult<()> {
        let (writer, reader) = clients(1).await?;
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let old_tags = HashSet::from([format!("old-{uid}")]);
        let new_tags = HashSet::from([format!("new-{uid}")]);
        let object = key(1)?;
        writer
            .create(
                Some(uid.clone()),
                &owner,
                &object,
                object.attributes()?,
                &old_tags,
            )
            .await?;
        let operations = [upsert(&uid, &object, Some(new_tags.clone()))?];
        writer.atomic(&owner, &operations).await?;
        assert!(reader.retrieve(&uid).await?.is_some(), "K must still exist");
        let stored_tags = reader.retrieve_tags(&uid).await?;
        assert_eq!(stored_tags, new_tags, "Upsert must replace stored tags");
        let old_lookup = reader.list_uids_for_tags(&old_tags).await?;
        let new_lookup = reader.list_uids_for_tags(&new_tags).await?;
        let mut attributes = Attributes::default();
        attributes.set_tags(VENDOR_ID_COSMIAN, old_tags.clone())?;
        let old_find = reader
            .find(Some(&attributes), None, &owner, true, VENDOR_ID_COSMIAN)
            .await?
            .into_iter()
            .map(|(found, ..)| found)
            .collect::<HashSet<_>>();
        attributes.set_tags(VENDOR_ID_COSMIAN, new_tags.clone())?;
        let new_find = reader
            .find(Some(&attributes), None, &owner, true, VENDOR_ID_COSMIAN)
            .await?
            .into_iter()
            .map(|(found, ..)| found)
            .collect::<HashSet<_>>();
        eprintln!(
            "T1 uid={uid} stored_tags={stored_tags:?} old_lookup={old_lookup:?} new_lookup={new_lookup:?} old_find={old_find:?} new_find={new_find:?}"
        );
        assert!(new_lookup.contains(&uid), "New tag must select K");
        assert!(new_find.contains(&uid), "Find must select K by new tag");
        assert!(
            !old_lookup.contains(&uid) && !old_find.contains(&uid),
            "Removed tag still selects existing K: list={old_lookup:?}, find={old_find:?}"
        );
        Ok(())
    }

    pub(crate) async fn t2_concurrent_upserts_must_preserve_tags() -> DbResult<()> {
        let (first, second) = clients(2).await?;
        sequential_controls(&first, &second).await?;
        let started = std::time::Instant::now();
        for round in 1..=10_000 {
            let case = tag_case(&first).await?;
            let (replace_result, preserve_result) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(
                        first.atomic(&case.owner, &case.replace),
                        second.atomic(&case.owner, &case.preserve)
                    )
                })
                .await
                .map_err(|error| crate::db_error!(format!("T2 infrastructure timeout: {error}")))?;
            replace_result?;
            preserve_result?;
            let stored_tags = second.retrieve_tags(&case.uid).await?;
            assert_eq!(
                stored_tags, case.expected_tags,
                "Concurrent Upserts lost tags at round {round}, uid={}",
                case.uid
            );
            if started.elapsed() >= std::time::Duration::from_secs(10) {
                return Ok(());
            }
        }
        Ok(())
    }

    pub(crate) async fn t3_failed_competing_batch_must_rollback_upsert() -> DbResult<()> {
        let (first, second) = clients(3).await?;
        let shared = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{shared}"));
        let marker_a = format!("marker-a-{shared}");
        let marker_b = format!("marker-b-{shared}");
        let batch = |marker: &str, object: &Object| -> DbResult<[AtomicOperation; 2]> {
            Ok([
                upsert(
                    marker,
                    object,
                    Some(HashSet::from([format!("tag-{marker}")])),
                )?,
                AtomicOperation::Create((
                    shared.clone(),
                    owner.clone(),
                    object.clone(),
                    object.attributes()?.clone(),
                    HashSet::new(),
                )),
            ])
        };
        let first_operations = batch(&marker_a, &key(4)?)?;
        let second_operations = batch(&marker_b, &key(5)?)?;
        let (first_result, second_result) = tokio::join!(
            first.atomic(&owner, &first_operations),
            second.atomic(&owner, &second_operations)
        );
        eprintln!(
            "T3 shared={shared} marker_a={marker_a} marker_b={marker_b} first_result={first_result:?} second_result={second_result:?}"
        );
        let (winner, loser, conflict) = match (first_result, second_result) {
            (Ok(_), Err(error)) => (&marker_a, &marker_b, error),
            (Err(error), Ok(_)) => (&marker_b, &marker_a, error),
            results => {
                return Err(crate::db_error!(format!(
                    "T3 expected exactly one successful batch: {results:?}"
                )));
            }
        };
        assert!(
            conflict
                .to_string()
                .contains(&format!("object {shared} already exists")),
            "Unexpected failure: {conflict}"
        );
        assert!(
            first.retrieve(&shared).await?.is_some(),
            "Winning shared object must exist"
        );
        assert!(
            first.retrieve(winner).await?.is_some(),
            "Winning marker must exist"
        );
        let loser_exists = first.retrieve(loser).await?.is_some();
        let loser_lookup = first
            .list_uids_for_tags(&HashSet::from([format!("tag-{loser}")]))
            .await?;
        eprintln!(
            "T3 winner={winner} loser={loser} loser_exists={loser_exists} loser_lookup={loser_lookup:?}"
        );
        assert!(
            !loser_exists && !loser_lookup.contains(loser),
            "Failed batch left partial effects: loser={loser}, exists={loser_exists}, indexed={loser_lookup:?}"
        );
        Ok(())
    }

    /// A batch may delete a uid and re-create it; a Create after a live
    /// operation on the same uid in one batch must still fail atomically.
    pub(crate) async fn t4_same_uid_delete_then_create_and_create_after_upsert() -> DbResult<()> {
        let (store, _) = clients(4).await?;
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let object = key(6)?;
        let create = || -> DbResult<AtomicOperation> {
            Ok(AtomicOperation::Create((
                uid.clone(),
                owner.clone(),
                object.clone(),
                object.attributes()?.clone(),
                HashSet::from([format!("tag-{uid}")]),
            )))
        };
        store.atomic(&owner, &[create()?]).await?;

        // Delete + Create of an existing uid in one batch succeeds.
        store
            .atomic(&owner, &[AtomicOperation::Delete(uid.clone()), create()?])
            .await?;
        assert!(store.retrieve(&uid).await?.is_some(), "re-created object");

        // Create after a live Upsert of the same uid in one batch fails and writes nothing.
        let fresh = Uuid::new_v4().to_string();
        let batch = [
            upsert(&fresh, &object, None)?,
            AtomicOperation::Create((
                fresh.clone(),
                owner.clone(),
                object.clone(),
                object.attributes()?.clone(),
                HashSet::new(),
            )),
        ];
        let error = store
            .atomic(&owner, &batch)
            .await
            .err()
            .context("T4 expected a Create conflict")?;
        assert!(
            error
                .to_string()
                .contains(&format!("object {fresh} already exists")),
            "Unexpected failure: {error}"
        );
        assert!(store.retrieve(&fresh).await?.is_none(), "no partial write");
        Ok(())
    }

    /// A delete based on a stale baseline must not erase a concurrent write.
    pub(crate) async fn t5_delete_is_guarded_by_baseline() -> DbResult<()> {
        use crate::stores::redis::objects_db::{AtomicScriptOutcome, ScriptOp};

        let (store, _) = clients(5).await?;
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let object = key(7)?;
        store
            .create(
                Some(uid.clone()),
                &owner,
                &object,
                object.attributes()?,
                &HashSet::new(),
            )
            .await?;
        let current = store.objects_db().object_get_raw(&uid).await?;
        let stale = [1_u8, 2, 3];

        let outcome = store
            .objects_db()
            .atomic_script(&[ScriptOp::Delete {
                uid: &uid,
                expected: Some(&stale),
            }])
            .await?;
        assert!(matches!(outcome, AtomicScriptOutcome::CasConflict));
        assert!(
            store.retrieve(&uid).await?.is_some(),
            "stale delete erased the object"
        );

        let outcome = store
            .objects_db()
            .atomic_script(&[ScriptOp::Delete {
                uid: &uid,
                expected: current.as_deref(),
            }])
            .await?;
        assert!(matches!(outcome, AtomicScriptOutcome::Committed));
        assert!(store.retrieve(&uid).await?.is_none());
        Ok(())
    }

    /// `Create` then `Delete` of the same uid in one batch: a net no-op for an
    /// absent uid, but the `Create` must still fail fast if the uid exists.
    pub(crate) async fn t6_create_then_delete_in_one_batch() -> DbResult<()> {
        let (store, _) = clients(4).await?;
        let uid = Uuid::new_v4().to_string();
        let owner = UserId::from(format!("owner-{uid}"));
        let object = key(6)?;
        let batch = || -> DbResult<[AtomicOperation; 2]> {
            Ok([
                AtomicOperation::Create((
                    uid.clone(),
                    owner.clone(),
                    object.clone(),
                    object.attributes()?.clone(),
                    HashSet::new(),
                )),
                AtomicOperation::Delete(uid.clone()),
            ])
        };
        store.atomic(&owner, &batch()?).await?;
        assert!(store.retrieve(&uid).await?.is_none(), "net no-op expected");

        store.atomic(&owner, &batch()?[..1]).await?;
        let error = store
            .atomic(&owner, &batch()?)
            .await
            .err()
            .context("T6 expected a Create conflict")?;
        assert!(
            error
                .to_string()
                .contains(&format!("object {uid} already exists")),
            "Unexpected failure: {error}"
        );
        assert!(
            store.retrieve(&uid).await?.is_some(),
            "existing object must survive the rejected batch"
        );
        Ok(())
    }

    /// Stand-alone `update_object` racing an `Upsert` batch must not lose tags,
    /// and the stand-alone mutators keep object, index and errors consistent.
    pub(crate) async fn t8_standalone_mutators_are_cas_guarded() -> DbResult<()> {
        let (first, second) = clients(5).await?;
        for _ in 0..50 {
            let case = tag_case(&first).await?;
            let object = key(2)?;
            let (update, upsert) = tokio::join!(
                first.update_object(
                    &case.uid,
                    &object,
                    object.attributes()?,
                    Some(&case.expected_tags)
                ),
                second.atomic(&case.owner, &case.preserve)
            );
            update?;
            upsert?;
            assert_eq!(
                second.retrieve_tags(&case.uid).await?,
                case.expected_tags,
                "stand-alone update_object lost tags, uid={}",
                case.uid
            );
        }

        let case = tag_case(&first).await?;
        let object = key(2)?;
        let create_error = first
            .create(
                Some(case.uid.clone()),
                &case.owner,
                &object,
                object.attributes()?,
                &HashSet::new(),
            )
            .await
            .err()
            .context("T8 expected a Create conflict")?;
        assert!(create_error.to_string().contains("already exists"));
        first.update_state(&case.uid, State::Active).await?;
        assert_eq!(
            first
                .retrieve(&case.uid)
                .await?
                .context("T8 missing")?
                .state(),
            State::Active
        );
        assert!(
            first
                .update_state("no-such-uid", State::Active)
                .await
                .is_err()
        );
        first.delete(&case.uid).await?;
        assert!(first.retrieve(&case.uid).await?.is_none());
        first.delete(&case.uid).await?;
        Ok(())
    }

    /// Run every #940 contract test; called from `test_db_redis_with_findex`.
    pub(crate) async fn test_issue_940() -> DbResult<()> {
        t1_removed_tag_must_not_select_existing_object().await?;
        Box::pin(t2_concurrent_upserts_must_preserve_tags()).await?;
        Box::pin(t3_failed_competing_batch_must_rollback_upsert()).await?;
        Box::pin(t4_same_uid_delete_then_create_and_create_after_upsert()).await?;
        t5_delete_is_guarded_by_baseline().await?;
        Box::pin(t6_create_then_delete_in_one_batch()).await?;
        Box::pin(t8_standalone_mutators_are_cas_guarded()).await?;
        crate::stores::redis::redis_with_findex::tests::test_db_redis_stale_findex_hit_is_filtered_out().await?;
        crate::stores::redis::redis_with_findex::tests::test_db_redis_stale_attribute_hit_is_filtered_out().await?;
        crate::stores::redis::redis_with_findex::tests::test_db_redis_interleaved_index_updates_keep_object_findable().await
    }
}

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
        VENDOR_ID_COSMIAN,
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
    let user1 = FindexUserId("U1".to_owned());

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

    // find the permission for the object O1
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
    let user2 = FindexUserId("U2".to_owned());

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

    // find the permission for the object O1
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
    let user1 = FindexUserId("U1".to_owned());

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

/// Verify that the live-object counter key (`kms::metrics::live_object_count`) is
/// kept accurate across `create` / `update_state` / `delete` operations and that the
/// bootstrap SCAN path correctly reconstructs the counter when the key is absent.
///
/// **Requires a running Redis instance.**
pub(crate) async fn test_live_count_counter() -> DbResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));

    let mut rng = CsRng::from_entropy();
    let redis_url = get_redis_url();
    // `clear_database: true` issues a FLUSHDB so each run starts clean.
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let db = RedisWithFindex::instantiate(&redis_url, master_key, true).await?;

    // ── Step 1: create 3 objects ─────────────────────────────────────────────
    // All newly created objects are PreActive (live).
    let mut key_bytes = vec![0; 32];
    rng.fill_bytes(&mut key_bytes);
    let key1 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    rng.fill_bytes(&mut key_bytes);
    let key2 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    rng.fill_bytes(&mut key_bytes);
    let key3 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid1 = db
        .create(
            None,
            &UserId::from("owner"),
            &key1,
            key1.attributes()?,
            &HashSet::new(),
        )
        .await?;
    let uid2 = db
        .create(
            None,
            &UserId::from("owner"),
            &key2,
            key2.attributes()?,
            &HashSet::new(),
        )
        .await?;
    let uid3 = db
        .create(
            None,
            &UserId::from("owner"),
            &key3,
            key3.attributes()?,
            &HashSet::new(),
        )
        .await?;

    let raw: Option<i64> = db.mgr.clone().get(LIVE_COUNT_KEY).await?;
    assert_eq!(raw, Some(3), "counter should be 3 after 3 creates");

    // ── Step 2: destroy uid1 (live → destroyed) ─ counter must drop to 2 ───
    db.update_state(&uid1, State::Destroyed).await?;
    let raw: Option<i64> = db.mgr.clone().get(LIVE_COUNT_KEY).await?;
    assert_eq!(raw, Some(2), "counter should be 2 after destroying uid1");

    // ── Step 3: delete live uid2 ─ counter must drop to 1 ───────────────────
    db.delete(&uid2).await?;
    let raw: Option<i64> = db.mgr.clone().get(LIVE_COUNT_KEY).await?;
    assert_eq!(raw, Some(1), "counter should be 1 after deleting live uid2");

    // ── Step 4: delete destroyed uid1 ─ counter must remain at 1 ────────────
    db.delete(&uid1).await?;
    let raw: Option<i64> = db.mgr.clone().get(LIVE_COUNT_KEY).await?;
    assert_eq!(
        raw,
        Some(1),
        "deleting an already-destroyed object must not change the counter"
    );

    // ── Step 5: fast-path count_all_non_destroyed ────────────────────────────
    // Counter key exists → one O(1) GET, no SCAN.
    let n = db.count_all_non_destroyed().await?;
    assert_eq!(n, 1, "count_all_non_destroyed (fast path) should return 1");

    // ── Step 6: bootstrap SCAN path ──────────────────────────────────────────
    // Delete the counter key to simulate a first-boot / FLUSHDB situation.
    redis::cmd("DEL")
        .arg(LIVE_COUNT_KEY)
        .query_async::<()>(&mut db.mgr.clone())
        .await?;

    // count_all_non_destroyed must fall back to SCAN, count the one live
    // object (uid3), write the counter key, and return 1.
    let n = db.count_all_non_destroyed().await?;
    assert_eq!(
        n, 1,
        "count_all_non_destroyed (bootstrap SCAN) should return 1"
    );

    // Bootstrap must have persisted the counter so the next call is fast.
    let raw: Option<i64> = db.mgr.clone().get(LIVE_COUNT_KEY).await?;
    assert_eq!(raw, Some(1), "bootstrap must persist the counter to Redis");

    // ── Teardown ─────────────────────────────────────────────────────────────
    db.delete(&uid3).await?;

    Ok(())
}

/// Verify that `ACTIVE_KEY_COUNT_KEY` is maintained correctly across the
/// full lifecycle of key and non-key objects.
///
/// Steps:
///   1. Create 2 `SymmetricKey` objects → counter = 2.
///   2. Create an `OpaqueObject` → counter must stay at 2 (not a key type).
///   3. `update_state` key1 → Deactivated → counter stays at 2 (still non-destroyed).
///   4. `update_state` key1 → Destroyed → counter drops to 1.
///   5. `delete` key2 (live) → counter drops to 0.
///   6. Bootstrap SCAN path: delete the counter key, call `count_non_destroyed_keys`,
///      expect it to return 0 and persist the counter.
pub(crate) async fn test_active_key_count_counter() -> DbResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));

    let mut rng = CsRng::from_entropy();
    let redis_url = get_redis_url();
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let db = RedisWithFindex::instantiate(&redis_url, master_key, true).await?;

    // ── Step 1: create 2 SymmetricKey objects ────────────────────────────────
    let mut key_bytes = vec![0_u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let key1 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;
    rng.fill_bytes(&mut key_bytes);
    let key2 = create_symmetric_key_kmip_object(
        VENDOR_ID_COSMIAN,
        &key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        },
    )?;

    let uid_key1 = db
        .create(
            None,
            &UserId::from("owner"),
            &key1,
            key1.attributes()?,
            &HashSet::new(),
        )
        .await?;
    let uid_key2 = db
        .create(
            None,
            &UserId::from("owner"),
            &key2,
            key2.attributes()?,
            &HashSet::new(),
        )
        .await?;

    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(raw, Some(2), "counter should be 2 after creating 2 keys");

    // ── Step 2: create an OpaqueObject → counter must NOT increment ──────────
    let opaque = Object::OpaqueObject(OpaqueObject {
        opaque_data_type: OpaqueDataType::Unknown,
        opaque_data_value: b"test-opaque".to_vec(),
    });
    let _uid_opaque = db
        .create(
            None,
            &UserId::from("owner"),
            &opaque,
            &Attributes::default(),
            &HashSet::new(),
        )
        .await?;
    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(
        raw,
        Some(2),
        "creating an OpaqueObject must not increment the key counter"
    );

    // ── Step 3: Deactivate key1 → counter stays at 2 (still non-destroyed) ───
    db.update_state(&uid_key1, State::Deactivated).await?;
    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(
        raw,
        Some(2),
        "Deactivated key is non-destroyed and must still be counted"
    );

    // ── Step 4: Destroy key1 → counter drops to 1 ───────────────────────────
    db.update_state(&uid_key1, State::Destroyed).await?;
    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(raw, Some(1), "counter should be 1 after destroying key1");

    // ── Step 5: delete key2 (live) → counter drops to 0 ─────────────────────
    db.delete(&uid_key2).await?;
    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(raw, Some(0), "counter should be 0 after deleting key2");

    // ── Step 6: bootstrap SCAN path ─────────────────────────────────────────
    // Delete the counter key to simulate a first-boot / FLUSHDB situation.
    redis::cmd("DEL")
        .arg(ACTIVE_KEY_COUNT_KEY)
        .query_async::<()>(&mut db.mgr.clone())
        .await?;

    // count_non_destroyed_keys must fall back to SCAN, count 0 non-destroyed
    // key objects, write the counter key, and return 0.
    let n = db.count_non_destroyed_keys().await?;
    assert_eq!(
        n, 0,
        "count_non_destroyed_keys (bootstrap SCAN) should return 0"
    );
    let raw: Option<i64> = db.mgr.clone().get(ACTIVE_KEY_COUNT_KEY).await?;
    assert_eq!(raw, Some(0), "bootstrap must persist the counter to Redis");

    Ok(())
}

/// Faithful Redis re-index test for the `wrapped_by::<uid>` Findex index.
///
/// Seeds a **legacy** wrapped object — stored directly via `object_upsert`, so it
/// carries no `wrapped_by::` keyword, exactly like an object written before that
/// index existed — clears the completion marker, then runs
/// `backfill_wrapped_by_index` and asserts the object becomes discoverable
/// through `find_wrapped_by` (used by key rotation).
pub(crate) async fn test_wrapped_by_backfill() -> DbResult<()> {
    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let mut rng = CsRng::from_entropy();
    let redis_url = get_redis_url();

    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);
    let db = RedisWithFindex::instantiate(&redis_url, master_key, true).await?;

    let owner = "legacy_owner";
    let wrapping_key_uid = "legacy_kek";
    let uid = "legacy_wrapped_object";

    // A wrapped symmetric key whose KeyWrappingData references `wrapping_key_uid`.
    let wrapped_obj: Object = serde_json::from_value(serde_json::json!({
        "SymmetricKey": {
            "KeyBlock": {
                "KeyFormatType": "TransparentSymmetricKey",
                "CryptographicAlgorithm": "AES",
                "CryptographicLength": 256,
                "KeyWrappingData": {
                    "WrappingMethod": "Encrypt",
                    "EncryptionKeyInformation": { "UniqueIdentifier": wrapping_key_uid },
                    "EncodingOption": "TTLVEncoding"
                }
            }
        }
    }))
    .map_err(|e| DbError::DatabaseError(format!("failed to build wrapped object: {e}")))?;
    let attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        state: Some(State::Active),
        ..Default::default()
    };
    let dbo = RedisDbObject::new(
        wrapped_obj,
        owner.to_owned(),
        State::Active,
        Some(HashSet::new()),
        attributes,
    );

    // Store the object WITHOUT Findex indexing → simulates a pre-index legacy object.
    db.objects_db().object_upsert(uid, &dbo).await?;

    // Clear the completion marker so the backfill actually runs.
    redis::cmd("DEL")
        .arg("wrapping_key_id_backfilled")
        .query_async::<()>(&mut db.mgr.clone())
        .await?;

    // Before backfill: the legacy object is invisible to find_wrapped_by (no keyword).
    let before = db
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    assert!(
        before.iter().all(|(found, _, _)| found.as_str() != uid),
        "legacy wrapped object must NOT be found before backfill"
    );

    // Run the one-time backfill.
    db.backfill_wrapped_by_index().await?;

    // After backfill: the object is discoverable by its wrapping key.
    let after = db
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    assert!(
        after.iter().any(|(found, _, _)| found.as_str() == uid),
        "wrapped object must be discoverable after backfill, got: {after:?}"
    );

    // Idempotency: re-running is a no-op (marker set) and keeps it discoverable.
    db.backfill_wrapped_by_index().await?;
    let again = db
        .find_wrapped_by(wrapping_key_uid, &UserId::from(owner))
        .await?;
    assert!(
        again.iter().any(|(found, _, _)| found.as_str() == uid),
        "wrapped object must remain discoverable after an idempotent re-run"
    );

    db.delete(uid).await?;
    Ok(())
}

/// Logical Redis database used by [`test_migration_state_markers`], kept apart from the
/// default database (0) shared by the other Redis tests.
const ISOLATED_REDIS_DB: u8 = 15;

/// Redis migration-state markers: a freshly initialised database records its version
/// and a `ready` state; re-opening it is accepted, while a database whose recorded
/// state is not `ready` (or that has no markers) is refused as legacy.
pub(crate) async fn test_migration_state_markers() -> DbResult<()> {
    use crate::stores::migrate::{DbState, Migrate as _};

    cosmian_logger::log_init(option_env!("RUST_LOG"));
    let mut rng = CsRng::from_entropy();
    // Use a dedicated logical Redis database: this test deliberately leaves the database in
    // refused (non-ready / legacy) states, which must never leak into the default database
    // shared with the other Redis tests and with later runs.
    let redis_url = format!("{}/{ISOLATED_REDIS_DB}", get_redis_url());
    let master_key = Secret::<REDIS_WITH_FINDEX_MASTER_KEY_LENGTH>::random(&mut rng);

    let db = RedisWithFindex::instantiate(&redis_url, master_key.clone(), true).await?;
    assert_eq!(
        db.get_current_db_version().await?.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(db.get_db_state().await?, Some(DbState::Ready));

    // Re-opening a ready database must succeed and keep the markers.
    let reopened = RedisWithFindex::instantiate(&redis_url, master_key.clone(), false).await?;
    assert_eq!(reopened.get_db_state().await?, Some(DbState::Ready));

    // A non-ready state makes the next start refuse the database.
    reopened.set_db_state(DbState::Upgrading).await?;
    assert_eq!(reopened.get_db_state().await?, Some(DbState::Upgrading));
    let refused = RedisWithFindex::instantiate(&redis_url, master_key.clone(), false).await;
    assert!(
        matches!(&refused, Err(DbError::DatabaseError(msg)) if msg.contains("Legacy")),
        "database in 'upgrading' state must be refused, got: {:?}",
        refused.map(|_| ())
    );

    // Version marker round-trip.
    reopened.set_current_db_version("0.0.1-test").await?;
    assert_eq!(
        reopened.get_current_db_version().await?.as_deref(),
        Some("0.0.1-test")
    );

    // A database without markers (non-empty, no version/state) is legacy and refused.
    redis::cmd("DEL")
        .arg("db_version")
        .arg("db_state")
        .query_async::<()>(&mut reopened.mgr.clone())
        .await?;
    redis::cmd("SET")
        .arg("some_legacy_key")
        .arg("v")
        .query_async::<()>(&mut reopened.mgr.clone())
        .await?;
    let legacy = RedisWithFindex::instantiate(&redis_url, master_key, false).await;
    assert!(
        matches!(&legacy, Err(DbError::DatabaseError(msg)) if msg.contains("Legacy")),
        "marker-less database must be refused, got: {:?}",
        legacy.map(|_| ())
    );

    // Leave nothing behind: this test intentionally corrupts the migration markers.
    redis::cmd("FLUSHDB")
        .query_async::<()>(&mut reopened.mgr.clone())
        .await?;
    Ok(())
}

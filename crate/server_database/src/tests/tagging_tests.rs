use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_objects::ObjectType,
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    },
};
use uuid::Uuid;

use crate::{
    db_error,
    stores::{ExtraStoreParams, ObjectsStore, PermissionsStore},
    DbResult,
};

pub(crate) async fn tags<DB: ObjectsStore + PermissionsStore>(
    db_and_params: &(DB, Option<ExtraStoreParams>),
    verify_attributes: bool,
) -> DbResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();
    let mut rng = CsRng::from_entropy();

    // create a symmetric key with tags
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    // create symmetric key
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES, false)?;

    // insert into DB

    let owner = "eyJhbGciOiJSUzI1Ni";
    let uid = Uuid::new_v4().to_string();
    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
            db_params,
        )
        .await?;
    assert_eq!(&uid, &uid_);

    //recover the object from DB and check that the vendor attributes contain the tags
    let owm = db
        .retrieve(&uid, db_params)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;

    let expected_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey
                | CryptographicUsageMask::KeyAgreement,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        ..Attributes::default()
    };
    assert_eq!(StateEnumeration::Active, owm.state());
    assert!(&symmetric_key == owm.object());

    let tags = db.retrieve_tags(owm.id(), db_params).await?;
    assert_eq!(tags.len(), 2);
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag1".to_owned()]), db_params)
        .await?;

    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap(), db_params)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert_eq!(owm.attributes(), &expected_attributes);
    }
    assert_eq!(owm.state(), StateEnumeration::Active);

    let tags = db.retrieve_tags(owm.id(), db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag2
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag2".to_owned()]), db_params)
        .await?;
    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap(), db_params)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert_eq!(owm.attributes(), &expected_attributes);
    }
    assert_eq!(owm.state(), StateEnumeration::Active);
    let tags = db.retrieve_tags(owm.id(), db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1 and tag2
    let res = db
        .list_uids_for_tags(
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap(), db_params)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert_eq!(owm.attributes(), &expected_attributes);
    }
    assert_eq!(owm.state(), StateEnumeration::Active);
    let tags = db.retrieve_tags(owm.id(), db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // should NOT find this object from tags as owner using tag1, tag2 and tag3
    let res = db
        .list_uids_for_tags(
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned(), "tag3".to_owned()]),
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 0);

    // should NOT find this object from tags as owner using tag3
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag3".to_owned()]), db_params)
        .await?;
    assert_eq!(res.len(), 0);

    Ok(())
}

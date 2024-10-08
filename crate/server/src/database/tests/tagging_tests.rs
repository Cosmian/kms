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
use cosmian_kms_client::access::ObjectOperationType;
use uuid::Uuid;

use crate::{
    core::extra_database_params::ExtraDatabaseParams,
    database::{object_with_metadata::ObjectWithMetadata, Database},
    result::KResult,
};

const USER_GET: &str = "user_get";
const USER_DECRYPT: &str = "user_decrypt";

pub(crate) async fn tags<DB: Database>(
    db_and_params: &(DB, Option<ExtraDatabaseParams>),
    verify_attributes: bool,
) -> KResult<()> {
    cosmian_logger::log_utils::log_init(None);
    let db = &db_and_params.0;
    let db_params = db_and_params.1.as_ref();
    let mut rng = CsRng::from_entropy();

    // create a symmetric key with tags
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    // create symmetric key
    let symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES)?;

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
    let res = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

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
    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(StateEnumeration::Active, owm.state);
    assert!(symmetric_key == owm.object);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert_eq!(tags.len(), 2);
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag1"])?,
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(owm.id, uid);
    assert_eq!(owm.owner, owner);
    if verify_attributes {
        assert_eq!(owm.attributes, expected_attributes);
    }
    assert_eq!(owm.state, StateEnumeration::Active);
    assert_eq!(owm.permissions, vec![]);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag2
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag2"])?,
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(owm.id, uid);
    assert_eq!(owm.owner, owner);
    if verify_attributes {
        assert_eq!(owm.attributes, expected_attributes);
    }
    assert_eq!(owm.state, StateEnumeration::Active);
    assert_eq!(owm.permissions, vec![]);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1 and tag2
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag1", "tag2"])?,
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(owm.id, uid);
    assert_eq!(owm.owner, owner);
    if verify_attributes {
        assert_eq!(owm.attributes, expected_attributes);
    }
    assert_eq!(owm.state, StateEnumeration::Active);
    assert_eq!(owm.permissions, vec![]);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // should NOT find this object from tags as owner using tag1, tag2 and tag3
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag1", "tag2", "tag3"])?,
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 0);

    // should NOT find this object from tags as owner using tag3
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag3"])?,
            owner,
            ObjectOperationType::Get,
            db_params,
        )
        .await?;
    assert_eq!(res.len(), 0);

    // grant the Get access right to USER_GET
    db.grant_access(
        &uid,
        USER_GET,
        HashSet::from([ObjectOperationType::Get]),
        db_params,
    )
    .await?;

    // grant the Decrypt access right to USER_DECRYPT
    db.grant_access(
        &uid,
        USER_DECRYPT,
        HashSet::from([ObjectOperationType::Decrypt]),
        db_params,
    )
    .await?;

    // find this object from tags as USER_GET using tag1
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag1"])?,
            USER_GET,
            ObjectOperationType::Get,
            db_params,
        )
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(owm.id, uid);
    assert_eq!(owm.owner, owner);
    if verify_attributes {
        assert_eq!(owm.attributes, expected_attributes);
    }
    assert_eq!(owm.state, StateEnumeration::Active);
    assert_eq!(owm.permissions, vec![ObjectOperationType::Get]);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as USER_DECRYPT using tag1
    let res = db
        .retrieve(
            &serde_json::to_string(&["tag1", "tag2"])?,
            USER_DECRYPT,
            ObjectOperationType::Decrypt,
            db_params,
        )
        .await?
        .into_values()
        .collect::<Vec<ObjectWithMetadata>>();

    assert_eq!(res.len(), 1);
    let owm = res[0].clone();
    assert_eq!(owm.id, uid);
    assert_eq!(owm.owner, owner);
    if verify_attributes {
        assert_eq!(owm.attributes, expected_attributes);
    }
    assert_eq!(owm.state, StateEnumeration::Active);
    assert_eq!(owm.permissions, vec![ObjectOperationType::Decrypt]);
    let tags = db.retrieve_tags(&owm.id, db_params).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    Ok(())
}

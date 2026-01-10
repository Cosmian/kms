use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
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

pub(super) async fn tags<DB: ObjectsStore + PermissionsStore>(
    db: &DB,
    verify_attributes: bool,
) -> DbResult<()> {
    cosmian_logger::log_init(None);
    let mut rng = CsRng::from_entropy();

    let owner = "eyJhbGciOiJSUzI1Ni";
    let uid = Uuid::new_v4().to_string();
    // create a symmetric key with tags
    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    // create a symmetric key
    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
            ..Attributes::default()
        },
    )?;

    // insert into DB

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::from(["tag1".to_owned(), "tag2".to_owned()]),
        )
        .await?;
    assert_eq!(&uid, &uid_);

    // recover the object from DB and check that the vendor attributes contain the tags
    let owm = db
        .retrieve(&uid)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;

    let mut expected_attributes = Attributes {
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
        unique_identifier: Some(UniqueIdentifier::TextString(owm.id().to_owned())),
        ..Attributes::default()
    };
    expected_attributes.set_tags(["_kk".to_owned()])?;
    assert_eq!(State::PreActive, owm.state());
    assert_eq!(&symmetric_key, owm.object());

    let tags = db.retrieve_tags(owm.id()).await?;
    assert_eq!(tags.len(), 2);
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag1".to_owned()]))
        .await?;

    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap())
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert!(owm.attributes() == &expected_attributes);
    }
    assert_eq!(owm.state(), State::PreActive);

    let tags = db.retrieve_tags(owm.id()).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag2
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag2".to_owned()]))
        .await?;
    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap())
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert!(owm.attributes() == &expected_attributes);
    }
    assert_eq!(owm.state(), State::PreActive);
    let tags = db.retrieve_tags(owm.id()).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // find this object from tags as owner using tag1 and tag2
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag1".to_owned(), "tag2".to_owned()]))
        .await?;
    assert_eq!(res.len(), 1);
    let owm = db
        .retrieve(res.iter().next().unwrap())
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(owm.id(), uid);
    assert_eq!(owm.owner(), owner);
    if verify_attributes {
        assert!(owm.attributes() == &expected_attributes);
    }
    assert_eq!(owm.state(), State::PreActive);
    let tags = db.retrieve_tags(owm.id()).await?;
    assert!(tags.contains("tag1"));
    assert!(tags.contains("tag2"));

    // should NOT find this object from tags as owner using tag1, tag2 and tag3
    let res = db
        .list_uids_for_tags(&HashSet::from([
            "tag1".to_owned(),
            "tag2".to_owned(),
            "tag3".to_owned(),
        ]))
        .await?;
    assert_eq!(res.len(), 0);

    // should NOT find this object from tags as owner using tag3
    let res = db
        .list_uids_for_tags(&HashSet::from(["tag3".to_owned()]))
        .await?;
    assert_eq!(res.len(), 0);

    Ok(())
}

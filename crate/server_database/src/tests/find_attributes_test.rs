use std::collections::HashSet;

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_types::{
            CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier, Name, NameType,
        },
        requests::create_symmetric_key_kmip_object,
    },
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kms_interfaces::ObjectsStore;
use uuid::Uuid;

use crate::{db_error, error::DbResult};

pub(super) async fn find_attributes<DB: ObjectsStore>(db: &DB) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);

    let link = Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    };

    let name = Name {
        name_type: NameType::UninterpretedTextString,
        name_value: "bar".to_owned(),
    };

    let symmetric_key = create_symmetric_key_kmip_object(
        &symmetric_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            object_type: Some(ObjectType::SymmetricKey),
            name: Some(vec![name.clone()]),
            link: Some(vec![link.clone()]),
            ..Attributes::default()
        },
    )?;

    let uid = Uuid::new_v4().to_string();

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::new(),
        )
        .await?;
    assert_eq!(&uid, &uid_);

    let obj = db
        .retrieve(&uid)
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(State::PreActive, obj.state());
    assert_eq!(&symmetric_key, obj.object());
    assert!(
        obj.object().attributes()?.link.as_ref().unwrap()[0].linked_object_identifier
            == LinkedObjectIdentifier::TextString("foo".to_owned())
    );
    assert_eq!(
        obj.object().attributes()?.name.as_ref().unwrap()[0].name_value,
        "bar".to_owned()
    );

    // Search for the object using its links
    let researched_attributes = Some(Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        link: Some(vec![link.clone()]),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(State::PreActive),
            owner,
            true,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Search for the object using its name
    let researched_attributes = Some(Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        name: Some(vec![name.clone()]),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(State::PreActive),
            owner,
            true,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Search for the object using its name and link
    let researched_attributes = Some(Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        name: Some(vec![name.clone()]),
        link: Some(vec![link.clone()]),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(State::PreActive),
            owner,
            true,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    // Define a link vector not present in any database objects
    let link = vec![Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("bar".to_owned()),
    }];

    let researched_attributes = Some(Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        link: Some(link.clone()),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(State::PreActive),
            owner,
            true,
        )
        .await?;
    assert_eq!(found.len(), 0);

    Ok(())
}

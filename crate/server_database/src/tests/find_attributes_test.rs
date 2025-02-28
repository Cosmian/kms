use std::{collections::HashSet, sync::Arc};

use cosmian_crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_kmip::kmip_2_1::{
    kmip_objects::ObjectType,
    kmip_types::{
        Attributes, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier,
        StateEnumeration,
    },
    requests::create_symmetric_key_kmip_object,
};
use cosmian_kms_interfaces::{ObjectsStore, SessionParams};
use uuid::Uuid;

use crate::{db_error, error::DbResult};

pub(crate) async fn find_attributes<DB: ObjectsStore>(
    db: &DB,
    db_params: Option<Arc<dyn SessionParams>>,
) -> DbResult<()> {
    cosmian_logger::log_init(None);

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    //

    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let mut symmetric_key =
        create_symmetric_key_kmip_object(&symmetric_key_bytes, CryptographicAlgorithm::AES, false)?;

    let uid = Uuid::new_v4().to_string();

    // Define the link vector
    let link = vec![Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_owned()),
    }];

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(link.clone());

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            symmetric_key.attributes()?,
            &HashSet::new(),
            db_params.clone(),
        )
        .await?;
    assert_eq!(&uid, &uid_);

    let obj = db
        .retrieve(&uid, db_params.clone())
        .await?
        .ok_or_else(|| db_error!("Object not found"))?;
    assert_eq!(StateEnumeration::Active, obj.state());
    assert!(&symmetric_key == obj.object());
    assert_eq!(
        obj.object().attributes()?.link.as_ref().unwrap()[0].linked_object_identifier,
        LinkedObjectIdentifier::TextString("foo".to_owned())
    );

    let researched_attributes = Some(Attributes {
        object_type: Some(ObjectType::SymmetricKey),
        link: Some(link.clone()),
        ..Attributes::default()
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params.clone(),
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
            Some(StateEnumeration::Active),
            owner,
            true,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 0);

    Ok(())
}

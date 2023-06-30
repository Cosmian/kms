use std::collections::HashSet;

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_kmip::kmip::{
    kmip_objects::ObjectType,
    kmip_types::{
        Attributes, CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier,
        StateEnumeration,
    },
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::symmetric::create_symmetric_key,
};
use uuid::Uuid;

use super::{get_sql_cipher, get_sqlite};
use crate::{database::Database, kms_bail, log_utils::log_init, result::KResult};

#[actix_rt::test]
pub async fn test_find_attributes() -> KResult<()> {
    find_attributes(get_sql_cipher().await?).await?;
    find_attributes(get_sqlite().await?).await?;
    Ok(())
}

async fn find_attributes<DB: Database>(
    db_and_params: (DB, Option<ExtraDatabaseParams>),
) -> KResult<()> {
    log_init("debug");
    let db = db_and_params.0;
    let db_params = db_and_params.1.as_ref();

    let mut rng = CsRng::from_entropy();
    let owner = "eyJhbGciOiJSUzI1Ni";

    //

    let mut symmetric_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut symmetric_key_bytes);
    let mut symmetric_key = create_symmetric_key(&symmetric_key_bytes, CryptographicAlgorithm::AES);

    let uid = Uuid::new_v4().to_string();

    // Define the link vector
    let link = vec![Link {
        link_type: LinkType::ParentLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString("foo".to_string()),
    }];

    let attributes = symmetric_key.attributes_mut()?;
    attributes.link = Some(link.clone());

    let uid_ = db
        .create(
            Some(uid.clone()),
            owner,
            &symmetric_key,
            &HashSet::new(),
            db_params,
        )
        .await?;
    assert_eq!(&uid, &uid_);

    let objs_ = db
        .retrieve(&uid, owner, ObjectOperationType::Get, db_params)
        .await?;
    assert_eq!(objs_.len(), 1);
    match objs_.len() {
        1 => {
            assert_eq!(StateEnumeration::Active, objs_[0].state);
            assert_eq!(&symmetric_key, &objs_[0].object);
            assert_eq!(
                objs_[0].object.attributes()?.link.as_ref().unwrap()[0].linked_object_identifier,
                LinkedObjectIdentifier::TextString("foo".to_string())
            );
        }
        _ => kms_bail!("There should be one object"),
    }

    let researched_attributes = Some(Attributes {
        link: Some(link.clone()),
        ..Attributes::new(ObjectType::SymmetricKey)
    });
    let found = db
        .find(
            researched_attributes.as_ref(),
            Some(StateEnumeration::Active),
            owner,
            db_params,
        )
        .await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0, uid);

    Ok(())
}

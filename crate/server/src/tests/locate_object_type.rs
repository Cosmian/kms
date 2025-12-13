use actix_http::Request;
use actix_web::dev::Service;
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes,
    kmip_objects::ObjectType,
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse, Locate},
    kmip_types::{CryptographicAlgorithm, Name, NameType, UniqueIdentifier},
};

use crate::result::KResult;
use crate::tests::test_utils::{post_2_1, test_app};

#[actix_rt::test]
async fn locate_filters_by_object_type_and_and_semantics() -> KResult<()> {
    // Start test app (KMIP 2.1 endpoint)
    let app = test_app(None, None).await;

    // Create an EC key pair
    let create = CreateKeyPair {
        common_attributes: None,
        private_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_length: Some(256),
            name: Some(vec![Name {
                name_type: NameType::UninterpretedTextString,
                name_value: "ec_key".to_string(),
            }]),
            ..Default::default()
        }),
        public_key_attributes: Some(Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_length: Some(256),
            ..Default::default()
        }),
        common_protection_storage_masks: None,
        private_protection_storage_masks: None,
        public_protection_storage_masks: None,
    };

    let create_resp: CreateKeyPairResponse = post_2_1(&app, create).await?;
    let priv_id = match create_resp.private_key_unique_identifier {
        UniqueIdentifier::TextString(id) => id,
        _ => unreachable!(),
    };
    let pub_id = match create_resp.public_key_unique_identifier {
        UniqueIdentifier::TextString(id) => id,
        _ => unreachable!(),
    };

    // Baseline counts for PrivateKey/PublicKey
    let baseline_priv: Vec<UniqueIdentifier> = post_2_1(&app, Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes { object_type: Some(ObjectType::PrivateKey), ..Default::default() },
    }).await?;
    let baseline_pub: Vec<UniqueIdentifier> = post_2_1(&app, Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes { object_type: Some(ObjectType::PublicKey), ..Default::default() },
    }).await?;

    // Locate by ObjectType = PrivateKey: expect +1 vs baseline
    let locate_private = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            ..Default::default()
        },
    };
    let private_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_private).await?;
    assert_eq!(private_hits.len(), baseline_priv.len() + 1);
    assert!(matches!(private_hits[0], UniqueIdentifier::TextString(ref id) if id == &priv_id));

    // Locate by ObjectType = PublicKey: expect +1 vs baseline
    let locate_public = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PublicKey),
            ..Default::default()
        },
    };
    let public_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_public).await?;
    assert_eq!(public_hits.len(), baseline_pub.len() + 1);
    assert!(matches!(public_hits[0], UniqueIdentifier::TextString(ref id) if id == &pub_id));

    // AND semantics: ObjectType + CryptographicAlgorithm must both match
    let locate_and_ok = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        },
    };
    let and_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_and_ok).await?;
    assert_eq!(and_hits.len(), 1);

    let locate_and_zero = Locate {
        maximum_items: None,
        offset_items: None,
        storage_status_mask: None,
        object_group_member: None,
        attributes: Attributes {
            object_type: Some(ObjectType::PrivateKey),
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA), // mismatch
            ..Default::default()
        },
    };
    let zero_hits: Vec<UniqueIdentifier> = post_2_1(&app, locate_and_zero).await?;
    assert_eq!(zero_hits.len(), 0);

    Ok(())
}

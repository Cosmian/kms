use std::convert::TryFrom;

use abe_gpsw::hybrid_crypto::policy::PolicyGroup;
use actix_web::web;
use cosmian_kms::{
    kmip_client,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{CreateKeyPair, CreateKeyPairResponse, Import},
    kmip_shared::abe::{
        add_policy_group_to_attributes, array_to_key_block,
        user_key::{abe_create_key_pair_request, UserDecryptionKeySetup},
    },
    kmip_types::{Attributes, KeyFormatType},
};
use paperclip::actix::{api_v2_operation, web::Json, Apiv2Schema};
use serde::{Deserialize, Serialize};

use crate::prelude::*;

fn _generate_master_key(
    req: &ABESetup,
    kms_client: &web::Data<Box<dyn kmip_client::Client>>,
) -> anyhow::Result<CreateKeyPairResponse> {
    let cr = CreateKeyPair::try_from(req)?;
    debug!(
        "POST /kmip/abe/generate_master_key. Request: {:?}",
        serde_json::to_string(&cr)?
    );
    kms_client.create_key_pair(&cr)
}

/// `POST /kmip/abe/generate_master_key`
#[api_v2_operation]
pub async fn generate_master_key(
    req: Json<ABESetup>,
    kms_client: web::Data<Box<dyn kmip_client::Client>>,
) -> ActixResult<Json<CreateKeyPairResponse>> {
    Ok(Json(
        _generate_master_key(&req.into_inner(), &kms_client).expect("failed generating master key"),
    ))
}

#[derive(Serialize, Deserialize, Debug, Apiv2Schema)]
pub struct ImportSetup {
    policy_group: String,
    pub object_type: ObjectType,
    pub replace_existing: bool,
    pub bytes: String,
}
fn _import_master_key(
    req: &ImportSetup,
    kms_client: &web::Data<Box<dyn kmip_client::Client>>,
) -> anyhow::Result<String> {
    let policy_group = hex::decode(&req.policy_group)?;
    let pg: PolicyGroup = serde_json::from_slice(&policy_group)?;
    let attributes = Attributes::default();
    let updated_attributes = add_policy_group_to_attributes(&attributes, &pg)?;
    let object_bytes = hex::decode(&req.bytes)?;
    let object = match req.object_type {
        ObjectType::PublicKey => Object::PublicKey {
            key_block: array_to_key_block(
                &object_bytes,
                KeyFormatType::AbeMasterPublicKey,
                Some(updated_attributes),
            ),
        },
        ObjectType::PrivateKey => Object::PrivateKey {
            key_block: array_to_key_block(
                &object_bytes,
                KeyFormatType::AbeMasterSecretKey,
                Some(updated_attributes),
            ),
        },
        _ => anyhow::bail!("Object type not supported"),
    };

    let ir = Import {
        unique_identifier: "".to_owned(),
        object_type: req.object_type,
        replace_existing: Some(req.replace_existing),
        key_wrap_type: None,
        attributes: Attributes::default(),
        object,
    };
    Ok(kms_client.import(&ir)?.unique_identifier)
}

/// `POST /kmip/abe/import_master_key`
#[api_v2_operation]
pub async fn import_master_key(
    req: Json<ImportSetup>,
    kms_client: web::Data<Box<dyn kmip_client::Client>>,
) -> ActixResult<Json<String>> {
    debug!("POST /kmip/abe/import_master_key. Request: {:?}", req);
    Ok(Json(
        _import_master_key(&req.into_inner(), &kms_client).expect("failed importing master key"),
    ))
}

fn _generate_user_key(
    req: &UserDecryptionKeySetup,
    kms_client: &web::Data<Box<dyn kmip_client::Client>>,
) -> anyhow::Result<CreateKeyPairResponse> {
    let cr = abe_create_key_pair_request(req)?;
    kms_client.create_key_pair(&cr)
}

/// `POST /kmip/abe/generate_user_key`
#[api_v2_operation]
pub async fn generate_user_key(
    req: Json<UserDecryptionKeySetup>,
    kms_client: web::Data<Box<dyn kmip_client::Client>>,
) -> ActixResult<Json<CreateKeyPairResponse>> {
    debug!("POST /kmip/abe/generate_user_key. Request: {:?}", req);
    Ok(Json(
        _generate_user_key(&req.into_inner(), &kms_client).expect("failed generating user key"),
    ))
}

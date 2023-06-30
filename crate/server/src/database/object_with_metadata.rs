use cosmian_kmip::kmip::{
    kmip_objects::Object, kmip_operations::ErrorReason, kmip_types::StateEnumeration,
};
use cosmian_kms_utils::access::ObjectOperationType;
use serde_json::Value;
use sqlx::{postgres::PgRow, sqlite::SqliteRow, Row};

use super::{state_from_string, DBObject};
use crate::{
    error::KmsError,
    result::{KResult, KResultHelper},
};

#[derive(Debug, Clone)]
pub struct ObjectWithMetadata {
    pub(crate) id: String,
    pub(crate) object: Object,
    pub(crate) owner: String,
    pub(crate) state: StateEnumeration,
    pub(crate) permissions: Vec<ObjectOperationType>,
}

impl ObjectWithMetadata {
    fn try_from(
        id: String,
        object_bytes: Vec<u8>,
        owner: String,
        state_string: String,
        raw_permissions: Vec<u8>,
    ) -> KResult<Self> {
        let db_object: DBObject = serde_json::from_slice(&object_bytes)
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);

        let state = state_from_string(&state_string)?;

        let perms: Vec<ObjectOperationType> = if raw_permissions.is_empty() {
            vec![]
        } else {
            serde_json::from_slice(&raw_permissions)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?
        };

        Ok(ObjectWithMetadata {
            id,
            object,
            owner,
            state,
            permissions: perms,
        })
    }
}

impl TryFrom<&PgRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &PgRow) -> Result<Self, Self::Error> {
        let id = row.get::<String, _>(0);
        let db_object: DBObject = serde_json::from_value(row.get::<Value, _>(1))
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let owner = row.get::<String, _>(2);
        let state = state_from_string(&row.get::<String, _>(3))?;
        let permissions: Vec<ObjectOperationType> = match row.try_get::<Value, _>(4) {
            Err(_) => vec![],
            Ok(v) => serde_json::from_value(v)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?,
        };
        Ok(ObjectWithMetadata {
            id,
            object,
            owner,
            state,
            permissions,
        })
    }
}

impl TryFrom<&SqliteRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &SqliteRow) -> Result<Self, Self::Error> {
        ObjectWithMetadata::try_from(
            row.get::<String, _>(0),
            row.get::<Vec<u8>, _>(1),
            row.get::<String, _>(2),
            row.get::<String, _>(3),
            row.get::<Vec<u8>, _>(4),
        )
    }
}

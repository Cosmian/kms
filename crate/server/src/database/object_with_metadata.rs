use cosmian_kmip::kmip::{
    kmip_objects::Object, kmip_operations::ErrorReason, kmip_types::StateEnumeration,
};
use cosmian_kms_client::access::ObjectOperationType;
use serde_json::Value;
use sqlx::{mysql::MySqlRow, postgres::PgRow, sqlite::SqliteRow, Row};

use super::{state_from_string, DBObject};
use crate::{error::KmsError, result::KResultHelper};

/// An object with its metadata such as permissions and state
// TODO: add attributes when https://github.com/Cosmian/kms/issues/88 is fixed
#[derive(Debug, Clone)]
pub struct ObjectWithMetadata {
    pub(crate) id: String,
    pub(crate) object: Object,
    pub(crate) owner: String,
    pub(crate) state: StateEnumeration,
    pub(crate) permissions: Vec<ObjectOperationType>,
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
        Ok(Self {
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
        let id = row.get::<String, _>(0);

        let db_object: DBObject = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
            .context("failed deserializing the object")
            .reason(ErrorReason::Internal_Server_Error)?;
        let object = Object::post_fix(db_object.object_type, db_object.object);
        let owner = row.get::<String, _>(2);
        let state = state_from_string(&row.get::<String, _>(3))?;
        let raw_permissions = row.get::<Vec<u8>, _>(4);
        let perms: Vec<ObjectOperationType> = if raw_permissions.is_empty() {
            vec![]
        } else {
            serde_json::from_slice(&raw_permissions)
                .context("failed deserializing the permissions")
                .reason(ErrorReason::Internal_Server_Error)?
        };

        Ok(Self {
            id,
            object,
            owner,
            state,
            permissions: perms,
        })
    }
}

impl TryFrom<&MySqlRow> for ObjectWithMetadata {
    type Error = KmsError;

    fn try_from(row: &MySqlRow) -> Result<Self, Self::Error> {
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
        Ok(Self {
            id,
            object,
            owner,
            state,
            permissions,
        })
    }
}

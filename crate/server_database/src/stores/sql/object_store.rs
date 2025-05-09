//! This module is deactivated
//! and needs to be revisited as part of https://github.com/Cosmian/kms/issues/379

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    SessionParams,
};
use sqlx::{Executor, IntoArguments, Row, Transaction};
use tracing::trace;
use uuid::Uuid;

use crate::{
    error::{DbResult, DbResultHelper},
    stores::{
        sql::{
            database::{get_query, SqlDatabase},
            main_store::SqlMainStore,
        },
        DBObject,
    },
    DbError,
};

#[async_trait(?Send)]
impl<DB> ObjectsStore for SqlMainStore<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String> {
        // If the uid is not provided, generate a new one
        let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());

        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        if let Err(e) = self
            .create_tx(owner, tags, object, attributes, &uid, &mut tx)
            .await
        {
            tx.rollback().await.context("transaction failed")?;
            return Err(InterfaceError::Db(format!(
                "creation of object failed: {e}"
            )));
        }

        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to commit the transaction: {e}")))?;
        trace!("Created in DB: {uid} / {owner}");
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        let row: Option<DB::Row> = sqlx::query(get_query(self.get_loader(), "select-object")?)
            .bind(uid.to_owned())
            .fetch_optional(self.get_pool())
            .await
            .context("retrieve")?;
        if let Some(row) = row {
            return Ok(Some(self.db_row_to_owm(&row)?))
        }
        Ok(None)
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        let rows: Vec<DB::Row> = sqlx::query(get_query(self.get_loader(), "select-tags")?)
            .bind(uid.to_owned())
            .fetch_all(self.get_pool())
            .await
            .context("retrieve")?;

        let tags = rows.iter().map(|r| r.get(0)).collect::<HashSet<String>>();

        Ok(tags)
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        if let Err(e) = self
            .update_object_tx(uid, object, attributes, tags, &mut tx)
            .await
        {
            tx.rollback().await.context("transaction failed")?;
            return Err(InterfaceError::Db(format!("update of object failed: {e}")));
        }

        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to commit the transaction: {e}")))?;
        Ok(())
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        sqlx::query(get_query(self.get_loader(), "update-object-with-state")?)
            .bind(state.to_string())
            .bind(uid)
            .execute(self.get_pool())
            .await
            .context("update_state")?;
        Ok(())
    }

    async fn delete(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        if let Err(e) = self.delete_tx(uid, &mut tx).await {
            tx.rollback().await.context("transaction failed")?;
            return Err(InterfaceError::Db(format!("delete of object failed: {e}")));
        }

        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to commit the transaction: {e}")))?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        let tx_future = async {
            let mut uids = Vec::with_capacity(operations.len());
            for operation in operations {
                match operation {
                    AtomicOperation::Create((uid, object, attributes, tags)) => {
                        self.create_tx(user, tags, object, attributes, uid, &mut tx)
                            .await
                            .context(&format!("creation of object {uid} failed"))?;
                        uids.push(uid.clone());
                    }
                    AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                        self.update_object_tx(uid, object, attributes, tags.as_ref(), &mut tx)
                            .await
                            .context(&format!("update of object {uid} failed"))?;
                        uids.push(uid.clone());
                    }
                    AtomicOperation::UpdateState((uid, state)) => {
                        self.update_state_tx(uid, *state, &mut tx)
                            .await
                            .context(&format!("update of the state of object {uid} failed"))?;
                        uids.push(uid.clone());
                    }
                    AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                        self.upsert_tx(
                            uid,
                            user,
                            object,
                            attributes,
                            tags.as_ref(),
                            *state,
                            &mut tx,
                        )
                        .await
                        .context(&format!("upsert of the object {uid} failed"))?;
                        uids.push(uid.clone());
                    }
                    AtomicOperation::Delete(uid) => {
                        self.delete_tx(uid, &mut tx)
                            .await
                            .context(&format!("delete of the object {uid} failed"))?;
                        uids.push(uid.clone());
                    }
                }
            }
            Ok::<Vec<String>, DbError>(uids)
        };

        match tx_future.await {
            Ok(v) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(v)
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("{e}")))
            }
        }
    }

    async fn is_object_owned_by(
        &self,
        uid: &str,
        owner: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool> {
        let row: Option<DB::Row> = sqlx::query(get_query(self.get_loader(), "has-row-objects")?)
            .bind(uid)
            .bind(owner)
            .fetch_optional(self.get_pool())
            .await
            .context("is_object_owned_by")?;
        Ok(row.is_some())
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        let tags_params = tags
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");

        let raw_sql = get_query(self.get_loader(), "select-uids-from-tags")?
            .replace("@TAGS", &tags_params)
            .replace("@LEN", &format!("${}", tags.len() + 1));

        let mut query = sqlx::query::<DB>(&raw_sql);
        for tag in tags {
            query = query.bind(tag);
        }
        // Bind the tags len
        query =
            query.bind(i16::try_from(tags.len()).map_err(|e| {
                InterfaceError::Db(format!("failed to convert tags len to i16: {e}"))
            })?);

        let rows = query
            .fetch_all(self.get_pool())
            .await
            .context("list uids for tags")?;
        let ids = rows.iter().map(|r| r.get(0)).collect::<HashSet<String>>();
        Ok(ids)
    }

    async fn find(
        &self,
        _researched_attributes: Option<&Attributes>,
        _state: Option<StateEnumeration>,
        _user: &str,
        _user_must_be_owner: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, StateEnumeration, Attributes)>> {
        todo!()
    }
}

impl<DB> SqlMainStore<DB>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    for<'z> DB::Arguments<'z>: IntoArguments<'z, DB>,
    for<'z> i16: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> String: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'z> &'z str: sqlx::Encode<'z, DB> + sqlx::Decode<'z, DB> + sqlx::Type<DB>,
    for<'w, 'z> sqlx::types::Json<&'w serde_json::Value>: sqlx::Encode<'z, DB>,
    sqlx::types::Json<serde_json::Value>: sqlx::Type<DB>,
    usize: sqlx::ColumnIndex<<DB as sqlx::Database>::Row>,
{
    async fn create_tx(
        &self,
        owner: &str,
        tags: &HashSet<String>,
        object: &Object,
        attributes: &Attributes,
        uid: &String,
        tx: &mut Transaction<'_, DB>,
    ) -> DbResult<()> {
        let object_json = serde_json::to_value(DBObject {
            object_type: object.object_type(),
            object: object.clone(),
        })
        .context("failed serializing the object to JSON")?;

        let attributes_json = serde_json::to_value(attributes)
            .context("failed serializing the attributes to JSON")?;

        sqlx::query(get_query(self.get_loader(), "insert-objects")?)
            .bind(uid.clone())
            .bind(object_json)
            .bind(attributes_json)
            .bind(StateEnumeration::Active.to_string())
            .bind(owner.to_owned())
            .execute(&mut **tx)
            .await?;

        // Insert the tags
        for tag in tags {
            sqlx::query(get_query(self.get_loader(), "insert-tags")?)
                .bind(uid.clone())
                .bind(tag.to_owned())
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }

    async fn update_object_tx(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        tx: &mut Transaction<'_, DB>,
    ) -> DbResult<()> {
        let object_json = serde_json::to_value(DBObject {
            object_type: object.object_type(),
            object: object.clone(),
        })
        .context("failed serializing the object to JSON")?;

        let attributes_json = serde_json::to_value(attributes)
            .context("failed serializing the attributes to JSON")?;

        sqlx::query(get_query(self.get_loader(), "update-object-with-object")?)
            .bind(object_json)
            .bind(attributes_json)
            .bind(uid.to_owned())
            .execute(&mut **tx)
            .await?;

        // Insert the new tags if any
        if let Some(tags) = tags {
            // delete the existing tags
            sqlx::query(get_query(self.get_loader(), "delete-tags")?)
                .bind(uid.to_owned())
                .execute(&mut **tx)
                .await?;
            for tag in tags {
                sqlx::query(get_query(self.get_loader(), "insert-tags")?)
                    .bind(uid.to_owned())
                    .bind(tag.to_owned())
                    .execute(&mut **tx)
                    .await?;
            }
        }
        Ok(())
    }

    async fn update_state_tx(
        &self,
        uid: &str,
        state: StateEnumeration,
        tx: &mut Transaction<'_, DB>,
    ) -> DbResult<()> {
        sqlx::query(get_query(self.get_loader(), "update-object-with-state")?)
            .bind(state.to_string())
            .bind(uid)
            .execute(&mut **tx)
            .await
            .context("update_state")?;
        Ok(())
    }

    async fn delete_tx(&self, uid: &str, tx: &mut Transaction<'_, DB>) -> DbResult<()> {
        // delete the object
        sqlx::query(get_query(self.get_loader(), "delete-object")?)
            .bind(uid)
            .execute(&mut **tx)
            .await?;

        // delete the tags
        sqlx::query(get_query(self.get_loader(), "delete-tags")?)
            .bind(uid)
            .execute(&mut **tx)
            .await?;

        Ok(())
    }

    async fn upsert_tx(
        &self,
        uid: &str,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        state: StateEnumeration,
        tx: &mut Transaction<'_, DB>,
    ) -> DbResult<()> {
        trace!(
            "Upserting in DB: {uid}\n   object: {object}\n   attributes: {attributes:?}\n    \
             tags: {tags:?}\n    state: {state:?}\n    owner: {owner}"
        );
        let object_json = serde_json::to_value(DBObject {
            object_type: object.object_type(),
            object: object.clone(),
        })
        .context("failed serializing the object to JSON")?;

        let attributes_json = serde_json::to_value(attributes)
            .context("failed serializing the attributes to JSON")?;

        sqlx::query(get_query(self.get_loader(), "upsert-object")?)
            .bind(uid)
            .bind(object_json)
            .bind(attributes_json)
            .bind(state.to_string())
            .bind(owner)
            .execute(&mut **tx)
            .await?;

        // Insert the new tags if present
        if let Some(tags) = tags {
            // delete the existing tags
            sqlx::query(get_query(self.get_loader(), "delete-tags")?)
                .bind(uid)
                .execute(&mut **tx)
                .await?;
            // insert the new ones
            for tag in tags {
                sqlx::query(get_query(self.get_loader(), "insert-tags")?)
                    .bind(uid)
                    .bind(tag)
                    .execute(&mut **tx)
                    .await?;
            }
        }

        trace!("Upserted in DB: {uid}");
        Ok(())
    }
}

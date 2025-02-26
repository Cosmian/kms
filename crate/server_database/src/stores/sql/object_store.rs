use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_kmip::kmip_2_1::kmip_types::{Attributes, StateEnumeration};
use cosmian_kms_interfaces::{AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore, SessionParams};
use crate::stores::sqlite::{atomic_, create_, delete_, find_, is_object_owned_by_, list_uids_for_tags_, retrieve_, retrieve_tags_, update_object_, update_state_};
use crate::stores::SqlitePool;

#[async_trait(?Send)]
impl<'s> ObjectsStore for <'s> {
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
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;
        let uid = match create_(uid, owner, object, attributes, tags, &mut tx).await {
            Ok(uid) => uid,
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                return Err(InterfaceError::Db(format!(
                    "creation of object failed: {e}"
                )));
            }
        };
        tx.commit()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to commit the transaction: {e}")))?;
        Ok(uid)
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        Ok(retrieve_(uid, &self.pool).await?)
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        Ok(retrieve_tags_(uid, &self.pool).await?)
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
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;
        match update_object_(uid, object, attributes, tags, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("update of object failed: {e}")))
            }
        }
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;
        match update_state_(uid, state, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!(
                    "update of the state of object {uid} failed: {e}"
                )))
            }
        }
    }

    async fn delete(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;
        match delete_(uid, &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(())
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("delete of object failed: {e}")))
            }
        }
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;
        match atomic_(user, operations, &mut tx).await {
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
        Ok(is_object_owned_by_(uid, owner, &self.pool).await?)
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        Ok(list_uids_for_tags_(tags, &self.pool).await?)
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, StateEnumeration, Attributes)>> {
        Ok(find_(
            researched_attributes,
            state,
            user,
            user_must_be_owner,
            &self.pool,
        )
            .await?)
    }
}

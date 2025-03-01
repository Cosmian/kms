use async_trait::async_trait;
use cosmian_kms_interfaces::{DbState, InterfaceResult, Migrate};
use sqlx::{Executor, IntoArguments};

use crate::stores::SqlMainStore;

#[async_trait(?Send)]
impl<DB> Migrate for SqlMainStore<DB>
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
    async fn migrate(&self) -> InterfaceResult<()> {
        todo!()
    }

    async fn get_db_state(&self) -> InterfaceResult<Option<DbState>> {
        todo!()
    }

    async fn set_db_state(&self, _state: DbState) -> InterfaceResult<()> {
        todo!()
    }

    async fn get_current_db_version(&self) -> InterfaceResult<Option<String>> {
        todo!()
    }

    async fn set_current_db_version(&self, _version: &str) -> InterfaceResult<()> {
        todo!()
    }

    async fn migrate_from_4_12_0_to_4_13_0(&self) -> InterfaceResult<()> {
        todo!()
    }
}

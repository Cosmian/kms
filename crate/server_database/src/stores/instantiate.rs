use cosmian_kms_interfaces::{InterfaceError, InterfaceResult, Migrate, ObjectsStore};
use rawsql::Loader;
use sqlx::{Executor, IntoArguments, Pool, Transaction};

use crate::{error::DbResultHelper, DbError};

trait SqlStore<'a, DB>: ObjectsStore + Migrate
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>,
    DB::Arguments<'a>: IntoArguments<'a, DB>,
{
    fn get_pool(&self) -> &'a Pool<DB>;

    fn get_loader(&self) -> &'a Loader;

    async fn instantiate(&self) -> InterfaceResult<()> {
        let is_new_instance = self.setup_database().await?;
        if is_new_instance {
            self.set_current_db_version(env!("CARGO_PKG_VERSION")).await
        } else {
            self.migrate().await
        }
    }

    async fn setup_database(&self) -> InterfaceResult<bool> {
        let is_new_instance = sqlx::query("SELECT * FROM objects LIMIT 1")
            .fetch_optional(self.get_pool())
            .await
            .is_err();

        let mut tx = self
            .get_pool()
            .begin()
            .await
            .map_err(|e| InterfaceError::Db(format!("failed to start a transaction: {e}")))?;

        match create_tables(self.get_loader(), &mut tx).await {
            Ok(()) => {
                tx.commit().await.map_err(|e| {
                    InterfaceError::Db(format!("failed to commit the transaction: {e}"))
                })?;
                Ok(is_new_instance)
            }
            Err(e) => {
                tx.rollback().await.context("transaction failed")?;
                Err(InterfaceError::Db(format!("{e}")))
            }
        }
    }
}

fn get_query<'a>(loader: &'a Loader, name: &str) -> InterfaceResult<&'a String> {
    loader
        .get(name)
        .ok_or_else(|| InterfaceError::Db(format!("{} SQL query can't be found", name)))
}

async fn create_tables<'a, 'e, DB>(
    loader: &'a Loader,
    executor: &mut Transaction<'e, DB>,
) -> InterfaceResult<()>
where
    DB: sqlx::Database,
    for<'z> &'z mut DB::Connection: Executor<'z, Database = DB>, // DB::Connection: Deref<Target = E>,
    DB::Arguments<'a>: IntoArguments<'a, DB>,
{
    sqlx::query(get_query(loader, "create-table-parameters")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-objects")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-read_access")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    sqlx::query(get_query(loader, "create-table-tags")?)
        .execute(&mut **executor)
        .await
        .map_err(DbError::from)?;

    // Old table context used between version 4.13.0 and 4.22.1
    let _ = sqlx::query("DROP TABLE context")
        .execute(&mut **executor)
        .await;

    Ok(())
}

// if clear_database {
//     clear_database_(executor).await?;
// }
//
// let sqlite_pool = Self { pool };
//
// if is_new {
//     sqlite_pool
//         .set_current_db_version(env!("CARGO_PKG_VERSION"))
//         .await?;
//     sqlite_pool.set_db_state(DbState::Ready).await?;
// } else {
//     // perform any necessary migration now
//     sqlite_pool.migrate().await?;
// }
//
// Ok(())

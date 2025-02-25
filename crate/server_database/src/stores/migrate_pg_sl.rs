#[macro_export]
macro_rules! impl_migrate {
    ($pool:ty, $query_macro:ident) => {
        #[async_trait(?Send)]
        impl cosmian_kms_interfaces::Migrate for $pool {
            async fn get_db_state(
                &self,
            ) -> InterfaceResult<Option<cosmian_kms_interfaces::DbState>> {
                match sqlx::query($query_macro!("select-parameter"))
                    .bind("db_state")
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(DbError::from)?
                {
                    None => {
                        trace!("No state found, old KMS version");
                        Ok(None)
                    }
                    Some(row) => {
                        let json = row.get::<String, _>(0);
                        Ok(Some(
                            serde_json::from_str(&json)
                                .context("failed deserializing the DB state")?,
                        ))
                    }
                }
            }

            async fn set_db_state(
                &self,
                state: cosmian_kms_interfaces::DbState,
            ) -> InterfaceResult<()> {
                sqlx::query($query_macro!("upsert-parameter"))
                    .bind("db_state")
                    .bind(serde_json::to_string(&state).context("failed serializing the DB state")?)
                    .execute(&self.pool)
                    .await
                    .map_err(DbError::from)?;
                Ok(())
            }

            async fn get_current_db_version(&self) -> InterfaceResult<Option<String>> {
                match sqlx::query($query_macro!("select-parameter"))
                    .bind("db_version")
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(DbError::from)?
                {
                    None => {
                        trace!("No state found, old KMS version");
                        Ok(None)
                    }
                    Some(row) => Ok(Some(row.get::<String, _>(0))),
                }
            }

            async fn set_current_db_version(&self, version: &str) -> InterfaceResult<()> {
                sqlx::query($query_macro!("upsert-parameter"))
                    .bind("db_version")
                    .bind(version)
                    .execute(&self.pool)
                    .await
                    .map_err(DbError::from)?;
                Ok(())
            }

            async fn migrate_from_4_12_0_to_4_13_0(&self) -> InterfaceResult<()> {
                trace!("Migrating from 4.12.0 to 4.13.0");

                // Add the column attributes to the objects table
                if sqlx::query("SELECT attributes from objects")
                    .execute(&self.pool)
                    .await
                    .is_ok()
                {
                    trace!("Column attributes already exists, nothing to do");
                    return Ok(());
                }

                trace!("Column attributes does not exist, adding it");
                sqlx::query($query_macro!("add-column-attributes"))
                    .execute(&self.pool)
                    .await
                    .map_err(DbError::from)?;

                // Select all objects and extract the KMIP attributes to be stored in the new column
                let rows = sqlx::query("SELECT * FROM objects")
                    .fetch_all(&self.pool)
                    .await
                    .map_err(DbError::from)?;

                let mut operations = Vec::with_capacity(rows.len());
                for row in rows {
                    let uid = row.get::<String, _>(0);
                    let db_object: DBObject = serde_json::from_slice(&row.get::<Vec<u8>, _>(1))
                        .context("migrate: failed deserializing the object")?;
                    let object = db_object.object;
                    trace!(
                        "migrate_from_4_12_0_to_4_13_0: object (type: {})={:?}",
                        object.object_type(),
                        uid
                    );
                    let attributes = match object.attributes() {
                        Ok(attrs) => attrs.clone(),
                        Err(_error) => {
                            // For example, a Certificate object has no KMIP-attribute
                            Attributes::default()
                        }
                    };
                    let tags = retrieve_tags_(&uid, &self.pool).await?;
                    operations.push(AtomicOperation::UpdateObject((
                        uid,
                        object,
                        attributes,
                        Some(tags),
                    )));
                }

                let mut tx = (&self.pool).begin().await.map_err(DbError::from)?;
                match atomic_(
                    "this user is not used to update objects",
                    &operations,
                    &mut tx,
                )
                .await
                {
                    Ok(_v) => {
                        tx.commit().await.map_err(DbError::from)?;
                        Ok(())
                    }
                    Err(e) => {
                        tx.rollback().await.context("transaction failed")?;
                        Err(InterfaceError::from(e))
                    }
                }
            }
        }
    };
}

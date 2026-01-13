use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Duration,
};

use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{KmipOperation, kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{
    AtomicOperation, InterfaceError, InterfaceResult, ObjectWithMetadata, ObjectsStore,
    PermissionsStore,
};
use cosmian_logger::{debug, trace};
#[cfg(feature = "non-fips")]
use mysql_async::ClientIdentity;
use mysql_async::{Pool, SslOpts, Transaction, prelude::*};
use rawsql::Loader;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::{
    db_bail, db_error,
    error::{DbError, DbResult, DbResultHelper},
    migrate_block_cipher_mode_if_needed,
    stores::{
        MYSQL_QUERIES,
        migrate::{DbState, Migrate},
        sql::{
            database::SqlDatabase,
            locate_query::{MySqlPlaceholder, query_from_attributes},
        },
    },
};

// Deadlock handling parameters for MySQL (ER_LOCK_DEADLOCK = 1213)
const MYSQL_DEADLOCK_MAX_RETRIES: u32 = 6;

fn is_mysql_deadlock(msg: &str) -> bool {
    // Match common forms from MySQL/MariaDB drivers and servers
    // Examples:
    // - "Deadlock found when trying to get lock; try restarting transaction"
    // - "ERROR 40001 (1213): Deadlock found when trying to get lock; ..."
    // - "ER_LOCK_DEADLOCK"
    msg.contains("Deadlock found when trying to get lock")
        || msg.contains("(1213)")
        || msg.contains("ER_LOCK_DEADLOCK")
}

fn mysql_deadlock_backoff_ms(attempt: u32) -> u64 {
    // Exponential-ish backoff capped by retry count: 50, 100, 200, 400, 800, 1600ms
    let cap = attempt.min(MYSQL_DEADLOCK_MAX_RETRIES);
    50_u64 * (1_u64 << cap)
}

#[macro_export]
macro_rules! get_mysql_query {
    ($name:literal) => {
        MYSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
    ($name:expr) => {
        MYSQL_QUERIES
            .get($name)
            .ok_or_else(|| db_error!("{} SQL query can't be found", $name))?
    };
}

/// Convert a `MySQL` row into an `ObjectWithMetadata`
/// This function is used to convert the result of a SQL query into an `ObjectWithMetadata`.
/// This is used in the `retrieve_` function.
/// # Arguments
/// * `row` - The `MySQL` row to convert
/// # Returns
/// * An `ObjectWithMetadata` object
/// # Errors
/// * If the deserialization of the object or the attributes fails
/// * If the state is not a valid `StateEnumeration`
/// * If the conversion fails
fn my_sql_row_to_owm(row: &mysql_async::Row) -> Result<ObjectWithMetadata, DbError> {
    let id: String = row.get(0).context("missing id")?;
    let object_json: String = row.get(1).context("missing object")?;
    let attrs_json: Value = row.get(2).context("missing attributes")?;
    let owner: String = row.get(3).context("missing owner")?;
    let state_str: String = row.get(4).context("missing state")?;
    let object: Object =
        serde_json::from_str(&object_json).context("failed deserializing the object")?;
    let object = migrate_block_cipher_mode_if_needed(object);
    let attributes: Attributes =
        serde_json::from_value(attrs_json).context("failed deserializing the Attributes")?;
    let state = State::try_from(state_str.as_str()).context("failed converting the state")?;
    Ok(ObjectWithMetadata::new(
        id, object, owner, state, attributes,
    ))
}

/// The `MySQL` connector is also compatible to connect a `MariaDB`
/// see: <https://mariadb.com/kb/en/mariadb-vs-mysql-compatibility>/
#[derive(Clone)]
pub(crate) struct MySqlPool {
    pool: Pool,
}

impl MySqlPool {
    pub(crate) async fn instantiate(
        connection_url: &str,
        clear_database: bool,
        max_connections: Option<u32>,
    ) -> DbResult<Self> {
        // Parse URL for TLS parameters first
        let url = Url::parse(connection_url)
            .map_err(|e| DbError::DatabaseError(format!("Invalid MySQL URL: {e}")))?;
        let query_params: HashMap<_, _> = url.query_pairs().collect();

        // Build a clean URL without SSL parameters that mysql_async doesn't recognize
        let mut clean_url = url.clone();
        clean_url.set_query(None);
        let mut clean_query = clean_url.query_pairs_mut();
        for (key, value) in &query_params {
            // Remove our custom SSL parameters
            if key != "ssl-mode"
                && key != "ssl_mode"
                && key != "ssl-ca"
                && key != "ssl_ca"
                && key != "ssl-client-identity"
                && key != "ssl_client_identity"
                && key != "ssl-client-identity-password"
                && key != "ssl_client_identity_password"
            {
                clean_query.append_pair(key, value);
            }
        }
        drop(clean_query);

        let mut opts = mysql_async::Opts::from_url(clean_url.as_ref()).map_err(DbError::from)?;

        // Check for TLS configuration via ssl-mode parameter
        if let Some(ssl_mode) = query_params
            .get("ssl-mode")
            .or_else(|| query_params.get("ssl_mode"))
        {
            let mode_upper = ssl_mode.to_uppercase();
            match mode_upper.as_str() {
                "DISABLED" => {
                    // Explicitly disable TLS
                    opts = mysql_async::OptsBuilder::from_opts(opts)
                        .ssl_opts(None)
                        .into();
                }
                "REQUIRED" | "PREFERRED" | "VERIFY_CA" | "VERIFY_IDENTITY" => {
                    // Build SslOpts for TLS
                    let mut ssl_opts = SslOpts::default();

                    // For REQUIRED/PREFERRED: skip all verification (encrypt but don't verify)
                    // For VERIFY_CA/VERIFY_IDENTITY: verify certificates
                    if mode_upper == "REQUIRED" || mode_upper == "PREFERRED" {
                        ssl_opts = ssl_opts
                            .with_danger_accept_invalid_certs(true)
                            .with_danger_skip_domain_validation(true);
                    } else {
                        // Load CA certificate for server verification (ssl-ca) for VERIFY modes
                        if let Some(ca_path) = query_params
                            .get("ssl-ca")
                            .or_else(|| query_params.get("ssl_ca"))
                        {
                            ssl_opts = ssl_opts
                                .with_root_certs(vec![PathBuf::from(ca_path.as_ref()).into()]);
                        }
                    }

                    // For mTLS client authentication:
                    // In non-fips builds with native-tls backend, support PKCS12 identity via ssl-client-identity
                    #[cfg(feature = "non-fips")]
                    {
                        if let Some(p12_path) = query_params
                            .get("ssl-client-identity")
                            .or_else(|| query_params.get("ssl_client_identity"))
                        {
                            let password = query_params
                                .get("ssl-client-identity-password")
                                .or_else(|| query_params.get("ssl_client_identity_password"))
                                .map(std::string::ToString::to_string);

                            let mut identity =
                                ClientIdentity::new(PathBuf::from(p12_path.as_ref()).into());
                            if let Some(pass) = password {
                                identity = identity.with_password(pass);
                            }
                            ssl_opts = ssl_opts.with_client_identity(Some(identity));
                        }
                    }
                    // In FIPS builds, reject PKCS12 client identity parameters explicitly
                    #[cfg(not(feature = "non-fips"))]
                    {
                        if query_params
                            .get("ssl-client-identity")
                            .or_else(|| query_params.get("ssl_client_identity"))
                            .is_some()
                            || query_params
                                .get("ssl-client-identity-password")
                                .or_else(|| query_params.get("ssl_client_identity_password"))
                                .is_some()
                        {
                            return Err(DbError::DatabaseError(
                                "PKCS12 client identity is prohibited in FIPS mode. Use non-FIPS mode or configure MySQL without client identity.".to_owned(),
                            ));
                        }
                    }

                    opts = mysql_async::OptsBuilder::from_opts(opts)
                        .ssl_opts(Some(ssl_opts))
                        .into();
                }
                _ => {
                    return Err(DbError::DatabaseError(format!(
                        "Unknown ssl-mode: {ssl_mode}"
                    )));
                }
            }
        }

        // Pool sizing defaults: conservative pool tuned to CPU.
        // Session settings (READ COMMITTED + shorter lock wait timeout) are applied in
        // `get_configured_conn()` when acquiring a connection for transactional work.
        // Rationale: MySQL/MariaDB can suffer from too many concurrent connections
        // (threads, buffer pool pressure). Using min(10, 2 × CPU cores) balances
        // parallelism with stability for typical services.
        let default_conns: usize = num_cpus::get().saturating_mul(2).min(10);
        let max_conns: usize = max_connections
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(default_conns);

        let mut opts_builder = mysql_async::OptsBuilder::from_opts(opts);
        let pool_constraints = mysql_async::PoolConstraints::new(0, max_conns)
            .ok_or_else(|| DbError::DatabaseError("Invalid pool constraints".to_owned()))?;
        opts_builder = opts_builder
            .pool_opts(mysql_async::PoolOpts::default().with_constraints(pool_constraints));

        let pool = Pool::new(opts_builder);

        // Bootstrap: create tables if they don't exist
        let mut conn = pool.get_conn().await.map_err(DbError::from)?;
        for name in [
            "create-table-parameters",
            "create-table-objects",
            "create-table-read_access",
            "create-table-tags",
        ] {
            let sql = MYSQL_QUERIES
                .get(name)
                .ok_or_else(|| DbError::DatabaseError(format!("Missing SQL query: {name}")))?;
            conn.query_drop(sql).await.map_err(DbError::from)?;
        }

        // Optional: clear database content for tests to ensure isolation
        if clear_database {
            for name in [
                "clean-table-objects",
                "clean-table-read_access",
                "clean-table-tags",
            ] {
                if let Some(sql) = MYSQL_QUERIES.get(name) {
                    conn.query_drop(sql).await.map_err(DbError::from)?;
                }
            }
        }

        let this = Self { pool };

        // On clear or first boot, update metadata (non-fips only)
        if clear_database {
            this.set_current_db_version(env!("CARGO_PKG_VERSION"))
                .await?;
            this.set_db_state(DbState::Ready).await?;
        }

        Ok(this)
    }

    // Helper to obtain a pooled connection and configure session settings consistently
    // - Isolation level: READ COMMITTED (reduces deadlocks vs REPEATABLE READ)
    // - Lock wait timeout: 10s (avoid long stalls under contention)
    async fn get_configured_conn(&self) -> DbResult<mysql_async::Conn> {
        let mut conn = self.pool.get_conn().await.map_err(DbError::from)?;
        conn.query_drop("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
            .await
            .map_err(DbError::from)?;
        conn.query_drop("SET SESSION innodb_lock_wait_timeout=10")
            .await
            .map_err(DbError::from)?;
        Ok(conn)
    }
}

// Note: TLS can be enabled by compiling mysql_async with a TLS backend feature
// and configuring SslOpts within OptsBuilder. This module does not hardwire TLS
// to keep the default build backend-agnostic.

impl SqlDatabase for MySqlPool {
    fn get_loader(&self) -> &Loader {
        &MYSQL_QUERIES
    }

    fn binder(&self, _param_number: usize) -> String {
        "?".to_owned()
    }
}

#[async_trait(?Send)]
impl ObjectsStore for MySqlPool {
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> InterfaceResult<String> {
        async fn transact(
            tx: &mut Transaction<'_>,
            uid: Option<String>,
            owner: &str,
            object: &Object,
            attributes: &Attributes,
            tags: &HashSet<String>,
        ) -> DbResult<String> {
            create_(uid, owner, object, attributes, tags, tx).await
        }
        let max_retries = MYSQL_DEADLOCK_MAX_RETRIES;
        for attempt in 0..max_retries {
            let mut conn = self.get_configured_conn().await?;
            let mut tx = conn
                .start_transaction(mysql_async::TxOpts::default())
                .await
                .map_err(DbError::from)?;
            match transact(&mut tx, uid.clone(), owner, object, attributes, tags).await {
                Ok(v) => match tx.commit().await {
                    Ok(()) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        let is_deadlock = is_mysql_deadlock(&msg);
                        if is_deadlock && attempt + 1 < max_retries {
                            let delay_ms = mysql_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if let Err(re) = tx.rollback().await.map_err(DbError::from) {
                        return Err(InterfaceError::from(re));
                    }
                    let is_deadlock = matches!(
                        &e,
                        crate::DbError::SqlError(msg) | crate::DbError::DatabaseError(msg)
                        if is_mysql_deadlock(msg)
                    );
                    if is_deadlock && attempt + 1 < max_retries {
                        let delay_ms = mysql_deadlock_backoff_ms(attempt);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        Ok(retrieve_(uid, &self.pool).await?)
    }

    async fn retrieve_tags(&self, uid: &str) -> InterfaceResult<HashSet<String>> {
        Ok(retrieve_tags_(uid, &self.pool).await?)
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        async fn transact(
            tx: &mut Transaction<'_>,
            uid: &str,
            object: &Object,
            attributes: &Attributes,
            tags: Option<&HashSet<String>>,
        ) -> DbResult<()> {
            update_object_(uid, object, attributes, tags, tx).await
        }
        let max_retries = MYSQL_DEADLOCK_MAX_RETRIES;
        for attempt in 0..max_retries {
            let mut conn = self.get_configured_conn().await?;
            let mut tx = conn
                .start_transaction(mysql_async::TxOpts::default())
                .await
                .map_err(DbError::from)?;
            match transact(&mut tx, uid, object, attributes, tags).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        let is_deadlock = is_mysql_deadlock(&msg);
                        if is_deadlock && attempt + 1 < max_retries {
                            let delay_ms = mysql_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if let Err(re) = tx.rollback().await.map_err(DbError::from) {
                        return Err(InterfaceError::from(re));
                    }
                    let is_deadlock = matches!(
                        &e,
                        crate::DbError::SqlError(msg) | crate::DbError::DatabaseError(msg)
                        if is_mysql_deadlock(msg)
                    );
                    if is_deadlock && attempt + 1 < max_retries {
                        let delay_ms = mysql_deadlock_backoff_ms(attempt);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }

    async fn update_state(&self, uid: &str, state: State) -> InterfaceResult<()> {
        async fn transact(tx: &mut Transaction<'_>, uid: &str, state: State) -> DbResult<()> {
            update_state_(uid, state, tx).await
        }
        let max_retries = MYSQL_DEADLOCK_MAX_RETRIES;
        for attempt in 0..max_retries {
            let mut conn = self.get_configured_conn().await?;
            let mut tx = conn
                .start_transaction(mysql_async::TxOpts::default())
                .await
                .map_err(DbError::from)?;
            match transact(&mut tx, uid, state).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        let is_deadlock = is_mysql_deadlock(&msg);
                        if is_deadlock && attempt + 1 < max_retries {
                            let delay_ms = mysql_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if let Err(re) = tx.rollback().await.map_err(DbError::from) {
                        return Err(InterfaceError::from(re));
                    }
                    let is_deadlock = matches!(
                        &e,
                        crate::DbError::SqlError(msg) | crate::DbError::DatabaseError(msg)
                        if is_mysql_deadlock(msg)
                    );
                    if is_deadlock && attempt + 1 < max_retries {
                        let delay_ms = mysql_deadlock_backoff_ms(attempt);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        async fn transact(tx: &mut Transaction<'_>, uid: &str) -> DbResult<()> {
            delete_(uid, tx).await
        }
        let max_retries = MYSQL_DEADLOCK_MAX_RETRIES;
        for attempt in 0..max_retries {
            let mut conn = self.get_configured_conn().await?;
            let mut tx = conn
                .start_transaction(mysql_async::TxOpts::default())
                .await
                .map_err(DbError::from)?;
            match transact(&mut tx, uid).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        let msg = e.to_string();
                        let is_deadlock = is_mysql_deadlock(&msg);
                        if is_deadlock && attempt + 1 < max_retries {
                            let delay_ms = mysql_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if let Err(re) = tx.rollback().await.map_err(DbError::from) {
                        return Err(InterfaceError::from(re));
                    }
                    let is_deadlock = matches!(
                        &e,
                        crate::DbError::SqlError(msg) | crate::DbError::DatabaseError(msg)
                        if is_mysql_deadlock(msg)
                    );
                    if is_deadlock && attempt + 1 < max_retries {
                        let delay_ms = mysql_deadlock_backoff_ms(attempt);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        async fn transact(
            tx: &mut Transaction<'_>,
            user: &str,
            operations: &[AtomicOperation],
        ) -> DbResult<Vec<String>> {
            atomic_(user, operations, tx).await
        }
        let max_retries = MYSQL_DEADLOCK_MAX_RETRIES;
        for attempt in 0..max_retries {
            let mut conn = self.get_configured_conn().await?;
            let mut tx = conn
                .start_transaction(mysql_async::TxOpts::default())
                .await
                .map_err(DbError::from)?;
            match transact(&mut tx, user, operations).await {
                Ok(v) => match tx.commit().await {
                    Ok(()) => return Ok(v),
                    Err(e) => {
                        let msg = e.to_string();
                        let is_deadlock = is_mysql_deadlock(&msg);
                        if is_deadlock && attempt + 1 < max_retries {
                            let delay_ms = mysql_deadlock_backoff_ms(attempt);
                            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                        return Err(InterfaceError::from(DbError::from(e)));
                    }
                },
                Err(e) => {
                    if let Err(re) = tx.rollback().await.map_err(DbError::from) {
                        return Err(InterfaceError::from(re));
                    }
                    let is_deadlock = matches!(
                        &e,
                        crate::DbError::SqlError(msg) | crate::DbError::DatabaseError(msg)
                        if is_mysql_deadlock(msg)
                    );
                    if is_deadlock && attempt + 1 < max_retries {
                        let delay_ms = mysql_deadlock_backoff_ms(attempt);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(InterfaceError::from(e));
                }
            }
        }
        Err(InterfaceError::from(DbError::DatabaseError(
            "too much contention: too many attempts".to_owned(),
        )))
    }

    async fn is_object_owned_by(&self, uid: &str, owner: &str) -> InterfaceResult<bool> {
        Ok(is_object_owned_by_(uid, owner, &self.pool).await?)
    }

    async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> InterfaceResult<HashSet<String>> {
        Ok(list_uids_for_tags_(tags, &self.pool).await?)
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
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

#[async_trait(?Send)]
impl Migrate for MySqlPool {
    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        let mut conn = self.get_configured_conn().await?;
        let sql = get_mysql_query!("select-parameter");
        let res: Option<String> = conn
            .exec_first(sql, ("db_state",))
            .await
            .map_err(DbError::from)?;
        match res {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        let mut conn = self.get_configured_conn().await?;
        let sql = get_mysql_query!("upsert-parameter");
        let state_json = serde_json::to_string(&state)?;
        conn.exec_drop(sql, ("db_state", state_json))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }

    async fn get_current_db_version(&self) -> DbResult<Option<String>> {
        let mut conn = self.get_configured_conn().await?;
        let sql = get_mysql_query!("select-parameter");
        let res: Option<String> = conn
            .exec_first(sql, ("db_version",))
            .await
            .map_err(DbError::from)?;
        Ok(res)
    }

    async fn set_current_db_version(&self, version: &str) -> DbResult<()> {
        let mut conn = self.get_configured_conn().await?;
        let sql = get_mysql_query!("upsert-parameter");
        conn.exec_drop(sql, ("db_version", version))
            .await
            .map_err(DbError::from)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PermissionsStore for MySqlPool {
    async fn list_user_operations_granted(
        &self,
        user: &str,
    ) -> InterfaceResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
        Ok(list_user_granted_access_rights_(user, &self.pool).await?)
    }

    async fn list_object_operations_granted(
        &self,
        uid: &str,
    ) -> InterfaceResult<HashMap<String, HashSet<KmipOperation>>> {
        Ok(list_accesses_(uid, &self.pool).await?)
    }

    async fn grant_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        Ok(insert_access_(uid, user, operations, &self.pool).await?)
    }

    async fn remove_operations(
        &self,
        uid: &str,
        user: &str,
        operations: HashSet<KmipOperation>,
    ) -> InterfaceResult<()> {
        Ok(remove_access_(uid, user, operations, &self.pool).await?)
    }

    async fn list_user_operations_on_object(
        &self,
        uid: &str,
        user: &str,
        no_inherited_access: bool,
    ) -> InterfaceResult<HashSet<KmipOperation>> {
        Ok(list_user_access_rights_on_object_(uid, user, no_inherited_access, &self.pool).await?)
    }
}

pub(super) async fn create_(
    uid: Option<String>,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: &HashSet<String>,
    tx: &mut Transaction<'_>,
) -> DbResult<String> {
    let object_json = serde_json::to_string_pretty(object).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the object to JSON: {e}").into())
    })?;
    let attributes_json = serde_json::to_value(attributes).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the attributes to JSON: {e}").into())
    })?;
    let uid = uid.unwrap_or_else(|| Uuid::new_v4().to_string());
    tx.exec_drop(
        get_mysql_query!("insert-objects"),
        (
            uid.clone(),
            object_json,
            attributes_json,
            attributes.state.unwrap_or(State::PreActive).to_string(),
            owner.to_owned(),
        ),
    )
    .await
    .map_err(DbError::from)?;
    for tag in tags {
        tx.exec_drop(get_mysql_query!("insert-tags"), (uid.clone(), tag.as_str()))
            .await
            .map_err(DbError::from)?;
    }
    trace!("Created in DB: {uid} / {owner}");
    Ok(uid)
}

pub(super) async fn retrieve_(uid: &str, pool: &Pool) -> DbResult<Option<ObjectWithMetadata>> {
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let row_opt: Option<mysql_async::Row> = conn
        .exec_first(get_mysql_query!("select-object"), (uid,))
        .await
        .map_err(DbError::from)?;
    row_opt.map(|r| my_sql_row_to_owm(&r)).transpose()
}

async fn retrieve_tags_(uid: &str, pool: &Pool) -> DbResult<HashSet<String>> {
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let rows: Vec<mysql_async::Row> = conn
        .exec(get_mysql_query!("select-tags"), (uid,))
        .await
        .map_err(DbError::from)?;
    let tags = rows
        .iter()
        .map(|r| r.get::<String, _>(0).unwrap_or_default())
        .collect::<HashSet<String>>();
    Ok(tags)
}

pub(super) async fn update_object_(
    uid: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    tx: &mut Transaction<'_>,
) -> DbResult<()> {
    let object_json = serde_json::to_string_pretty(object).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the object to JSON: {e}").into())
    })?;

    let attributes_json = serde_json::to_value(attributes).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the attributes to JSON: {e}").into())
    })?;

    tx.exec_drop(
        get_mysql_query!("update-object-with-object"),
        (object_json, attributes_json, uid),
    )
    .await
    .map_err(DbError::from)?;

    // Insert the new tags if any
    if let Some(tags) = tags {
        // delete the existing tags
        tx.exec_drop(get_mysql_query!("delete-tags"), (uid,))
            .await
            .map_err(DbError::from)?;

        for tag in tags {
            tx.exec_drop(get_mysql_query!("insert-tags"), (uid, tag.as_str()))
                .await
                .map_err(DbError::from)?;
        }
    }

    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(super) async fn update_state_(
    uid: &str,
    state: State,
    tx: &mut Transaction<'_>,
) -> DbResult<()> {
    tx.exec_drop(
        get_mysql_query!("update-object-with-state"),
        (state.to_string(), uid),
    )
    .await
    .map_err(DbError::from)?;
    trace!("Updated in DB: {uid}");
    Ok(())
}

pub(super) async fn delete_(uid: &str, tx: &mut Transaction<'_>) -> DbResult<()> {
    // delete the object
    tx.exec_drop(get_mysql_query!("delete-object"), (uid,))
        .await
        .map_err(DbError::from)?;

    // delete the tags
    tx.exec_drop(get_mysql_query!("delete-tags"), (uid,))
        .await
        .map_err(DbError::from)?;

    trace!("Deleted in DB: {uid}");
    Ok(())
}

pub(super) async fn upsert_(
    uid: &str,
    owner: &str,
    object: &Object,
    attributes: &Attributes,
    tags: Option<&HashSet<String>>,
    state: State,
    tx: &mut Transaction<'_>,
) -> DbResult<()> {
    let object_json = serde_json::to_string_pretty(object).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the object to JSON: {e}").into())
    })?;
    let attributes_json = serde_json::to_value(attributes).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the attributes to JSON: {e}").into())
    })?;
    tx.exec_drop(
        get_mysql_query!("upsert-object"),
        (uid, object_json, attributes_json, state.to_string(), owner),
    )
    .await
    .map_err(DbError::from)?;

    // Insert the new tags if present
    if let Some(tags) = tags {
        // delete the existing tags
        tx.exec_drop(get_mysql_query!("delete-tags"), (uid,))
            .await
            .map_err(DbError::from)?;
        // insert the new ones
        for tag in tags {
            tx.exec_drop(get_mysql_query!("insert-tags"), (uid, tag.as_str()))
                .await
                .map_err(DbError::from)?;
        }
    }

    trace!("Upserted in DB: {uid}");
    Ok(())
}

pub(super) async fn list_uids_for_tags_(
    tags: &HashSet<String>,
    pool: &Pool,
) -> DbResult<HashSet<String>> {
    let tags_params = tags.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let raw_sql = get_mysql_query!("select-uids-from-tags").replace("@TAGS", &tags_params);
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let mut params: Vec<mysql_async::Value> = Vec::with_capacity(tags.len() + 1);
    for tag in tags {
        params.push(mysql_async::Value::Bytes(tag.clone().into_bytes()));
    }
    params.push(mysql_async::Value::Int(i64::from(i16::try_from(
        tags.len(),
    )?)));
    let rows: Vec<mysql_async::Row> = conn.exec(raw_sql, params).await.map_err(DbError::from)?;
    let uids = rows
        .iter()
        .map(|r| r.get::<String, _>(0).unwrap_or_default())
        .collect::<HashSet<String>>();
    Ok(uids)
}

pub(super) async fn list_accesses_(
    uid: &str,
    pool: &Pool,
) -> DbResult<HashMap<String, HashSet<KmipOperation>>> {
    debug!("Uid = {}", uid);
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let rows: Vec<mysql_async::Row> = conn
        .exec(
            get_mysql_query!("select-rows-read_access-with-object-id"),
            (uid,),
        )
        .await
        .map_err(DbError::from)?;
    let mut ids: HashMap<String, HashSet<KmipOperation>> = HashMap::with_capacity(rows.len());
    for row in rows {
        let userid: String = row
            .get(0)
            .ok_or_else(|| DbError::ConversionError(String::from("missing userid").into()))?;
        let perms_val: Value = row
            .get(1)
            .ok_or_else(|| DbError::ConversionError(String::from("missing permissions").into()))?;
        let perms: HashSet<KmipOperation> = serde_json::from_value(perms_val).map_err(|e| {
            DbError::ConversionError(format!("failed deserializing operations: {e}").into())
        })?;
        ids.insert(userid, perms);
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(super) async fn list_user_granted_access_rights_(
    user: &str,
    pool: &Pool,
) -> DbResult<HashMap<String, (String, State, HashSet<KmipOperation>)>> {
    debug!("Owner = {}", user);
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let rows: Vec<mysql_async::Row> = conn
        .exec(get_mysql_query!("select-objects-access-obtained"), (user,))
        .await
        .map_err(DbError::from)?;
    let mut ids: HashMap<String, (String, State, HashSet<KmipOperation>)> =
        HashMap::with_capacity(rows.len());
    for row in rows {
        let uid: String = row
            .get(0)
            .ok_or_else(|| DbError::ConversionError(String::from("missing uid").into()))?;
        let owner: String = row
            .get(1)
            .ok_or_else(|| DbError::ConversionError(String::from("missing owner").into()))?;
        let state_str: String = row
            .get(2)
            .ok_or_else(|| DbError::ConversionError(String::from("missing state").into()))?;
        let state = State::try_from(state_str.as_str()).map_err(|e| {
            DbError::ConversionError(format!("failed converting the state: {e}").into())
        })?;
        let ops_val: Value = row
            .get(3)
            .ok_or_else(|| DbError::ConversionError(String::from("missing operations").into()))?;
        let ops: HashSet<KmipOperation> = serde_json::from_value(ops_val).map_err(|e| {
            DbError::ConversionError(format!("failed deserializing the operations: {e}").into())
        })?;
        ids.insert(uid, (owner, state, ops));
    }
    debug!("Listed {} rows", ids.len());
    Ok(ids)
}

pub(super) async fn list_user_access_rights_on_object_(
    uid: &str,
    userid: &str,
    no_inherited_access: bool,
    pool: &Pool,
) -> DbResult<HashSet<KmipOperation>> {
    let mut user_perms = perms(pool, uid, userid).await?;
    if no_inherited_access || userid == "*" {
        return Ok(user_perms);
    }
    user_perms.extend(perms(pool, uid, "*").await?);
    Ok(user_perms)
}

async fn perms(pool: &Pool, uid: &str, userid: &str) -> DbResult<HashSet<KmipOperation>> {
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let row_opt: Option<mysql_async::Row> = conn
        .exec_first(
            get_mysql_query!("select-user-accesses-for-object"),
            (uid, userid),
        )
        .await
        .map_err(DbError::from)?;
    if let Some(row) = row_opt {
        let perms_raw: Value = row
            .get(0)
            .ok_or_else(|| DbError::ConversionError(String::from("missing permissions").into()))?;
        serde_json::from_value(perms_raw).map_err(|e| {
            DbError::ConversionError(format!("failed deserializing the permissions: {e}").into())
        })
    } else {
        Ok(HashSet::new())
    }
}

pub(super) async fn insert_access_(
    uid: &str,
    userid: &str,
    operation_types: HashSet<KmipOperation>,
    pool: &Pool,
) -> DbResult<()> {
    let mut perms = list_user_access_rights_on_object_(uid, userid, false, pool).await?;
    if operation_types.is_subset(&perms) {
        return Ok(());
    }
    perms.extend(operation_types.iter().copied());
    let json = serde_json::to_value(&perms).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the permissions to JSON: {e}").into())
    })?;
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    conn.exec_drop(
        get_mysql_query!("upsert-row-read_access"),
        (uid, userid, json),
    )
    .await
    .map_err(DbError::from)?;
    trace!("Insert read access right in DB: {uid} / {userid}");
    Ok(())
}

pub(super) async fn remove_access_(
    uid: &str,
    userid: &str,
    operation_types: HashSet<KmipOperation>,
    pool: &Pool,
) -> DbResult<()> {
    let perms = list_user_access_rights_on_object_(uid, userid, true, pool)
        .await?
        .difference(&operation_types)
        .copied()
        .collect::<HashSet<_>>();
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    if perms.is_empty() {
        conn.exec_drop(get_mysql_query!("delete-rows-read_access"), (uid, userid))
            .await
            .map_err(DbError::from)?;
        return Ok(());
    }
    let json = serde_json::to_value(&perms).map_err(|e| {
        DbError::ConversionError(format!("failed serializing the permissions to JSON: {e}").into())
    })?;
    conn.exec_drop(
        get_mysql_query!("update-rows-read_access-with-permission"),
        (json, uid, userid),
    )
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub(super) async fn is_object_owned_by_(uid: &str, owner: &str, pool: &Pool) -> DbResult<bool> {
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let row_opt: Option<mysql_async::Row> = conn
        .exec_first(get_mysql_query!("has-row-objects"), (uid, owner))
        .await
        .map_err(DbError::from)?;
    Ok(row_opt.is_some())
}

pub(super) async fn find_(
    researched_attributes: Option<&Attributes>,
    state: Option<State>,
    user: &str,
    user_must_be_owner: bool,
    pool: &Pool,
) -> DbResult<Vec<(String, State, Attributes)>> {
    let sql = query_from_attributes::<MySqlPlaceholder>(
        researched_attributes,
        state,
        user,
        user_must_be_owner,
    );
    trace!("find_: {sql:?}");
    let mut conn = pool.get_conn().await.map_err(DbError::from)?;
    let params: Vec<mysql_async::Value> = if user_must_be_owner {
        vec![mysql_async::Value::Bytes(user.as_bytes().to_vec())]
    } else {
        vec![
            mysql_async::Value::Bytes(user.as_bytes().to_vec()),
            mysql_async::Value::Bytes(user.as_bytes().to_vec()),
            mysql_async::Value::Bytes(user.as_bytes().to_vec()),
        ]
    };
    let rows: Vec<mysql_async::Row> = conn.exec(sql, params).await.map_err(DbError::from)?;
    to_qualified_uids(&rows)
}

/// Convert a list of rows into a list of qualified uids
fn to_qualified_uids(rows: &[mysql_async::Row]) -> DbResult<Vec<(String, State, Attributes)>> {
    let mut uids = Vec::with_capacity(rows.len());
    for row in rows {
        let raw = row
            .get::<Value, _>(2)
            .ok_or_else(|| DbError::ConversionError(String::from("missing attributes").into()))?;
        let attrs: Attributes = serde_json::from_value(raw).map_err(|e| {
            DbError::ConversionError(format!("failed deserializing attributes: {e}").into())
        })?;
        let uid: String = row
            .get::<String, _>(0)
            .ok_or_else(|| DbError::ConversionError(String::from("missing uid").into()))?;
        let state_str: String = row
            .get::<String, _>(1)
            .ok_or_else(|| DbError::ConversionError(String::from("missing state").into()))?;
        let state = State::try_from(state_str.as_str()).map_err(|e| {
            DbError::ConversionError(format!("failed converting the state: {e}").into())
        })?;
        uids.push((uid, state, attrs));
    }
    Ok(uids)
}

pub(super) async fn atomic_(
    owner: &str,
    operations: &[AtomicOperation],
    tx: &mut Transaction<'_>,
) -> DbResult<Vec<String>> {
    let mut uids = Vec::with_capacity(operations.len());
    for operation in operations {
        match operation {
            AtomicOperation::Create((uid, object, attributes, tags)) => {
                if let Err(e) =
                    create_(Some(uid.clone()), owner, object, attributes, tags, tx).await
                {
                    db_bail!("creation of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::UpdateObject((uid, object, attributes, tags)) => {
                if let Err(e) = update_object_(uid, object, attributes, tags.as_ref(), tx).await {
                    db_bail!("update of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::UpdateState((uid, state)) => {
                if let Err(e) = update_state_(uid, *state, tx).await {
                    db_bail!("update of the state of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::Upsert((uid, object, attributes, tags, state)) => {
                if let Err(e) =
                    upsert_(uid, owner, object, attributes, tags.as_ref(), *state, tx).await
                {
                    db_bail!("upsert of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
            AtomicOperation::Delete(uid) => {
                if let Err(e) = delete_(uid, tx).await {
                    db_bail!("deletion of object {uid} failed: {e}");
                }
                uids.push(uid.clone());
            }
        }
    }
    Ok(uids)
}

// impl_sql_migrate!(MySqlPool, get_mysql_query);

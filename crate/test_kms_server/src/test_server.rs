use std::{
    env,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
    time::Duration,
    vec,
};

/// Global counter ensuring unique temp directories even when multiple tests
/// start within the same clock tick (macOS `SystemTime` resolution = 1 µs).
static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

use actix_server::ServerHandle;
use cosmian_kms_client::{
    GmailApiConf, KmsClient, KmsClientConfig, KmsClientError,
    cosmian_kmip::{KmipResultHelper, kmip_2_1::extra::tagging::VENDOR_ID_COSMIAN, time_normalize},
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::Create,
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
    kms_client_bail, kms_client_error,
    reexport::cosmian_http_client::HttpClientConfig,
};
use cosmian_kms_server::{
    config::{ClapConfig, ServerParams},
    start_kms_server::start_kms_server,
};
use cosmian_logger::{error, info, trace, warn};
use tokio::sync::OnceCell;

use crate::test_jwt::{AUTH0_TOKEN, AUTH0_TOKEN_USER};

/// To run most tests in parallel,
/// We use that to avoid trying to start N KMS servers (one per test)
/// with a default configuration.
/// Otherwise, we get: "Address already in use (os error 98)"
/// for N-1 tests.
pub(crate) static ONCE: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_JWT_AUTH: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_NON_REVOCABLE_KEY: OnceCell<TestsContext> =
    OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_HSM: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_KEK: OnceCell<TestsContext> = OnceCell::const_new();
pub(crate) static ONCE_SERVER_WITH_PRIVILEGED_USERS: OnceCell<TestsContext> = OnceCell::const_new();
/// Dedicated cell for the `test_privileged_users` test which needs both the owner
/// *and* a second privileged identity (`user.privileged@acme.com`) in the list.
/// A separate cell prevents the race with `privilege_bypass` tests that share
/// `ONCE_SERVER_WITH_PRIVILEGED_USERS` but only register the owner.
pub(crate) static ONCE_SERVER_WITH_MULTI_PRIVILEGED_USERS: OnceCell<TestsContext> =
    OnceCell::const_new();
#[cfg(feature = "non-fips")]
pub(crate) static ONCE_PQC_TLS: OnceCell<TestsContext> = OnceCell::const_new();

/// Ensure localhost bypasses any corporate proxy for tests.
/// When `HTTP_PROXY`/`HTTPS_PROXY` are set, add standard loopback hosts
/// to `NO_PROXY` so local test servers are reachable.
#[allow(unsafe_code)]
fn ensure_no_proxy_for_localhost() {
    let has_http_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();

    if !has_http_proxy {
        return;
    }

    // Existing NO_PROXY entries, normalized to a comma-separated list
    let existing = env::var("NO_PROXY")
        .ok()
        .or_else(|| env::var("no_proxy").ok())
        .unwrap_or_default();

    // Always include common loopback hosts
    let required = ["localhost", "127.0.0.1", "::1"];

    // Build a normalized set
    let mut parts: Vec<String> = existing
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    for &r in &required {
        if !parts.iter().any(|p| p.eq_ignore_ascii_case(r)) {
            parts.push(r.to_owned());
        }
    }

    let updated = parts.join(",");
    // Set both uppercase and lowercase to cover different libraries' expectations
    unsafe {
        env::set_var("NO_PROXY", &updated);
        env::set_var("no_proxy", &updated);
    }
    trace!("Ensured NO_PROXY for localhost: {}", updated);
}

/// As a last resort for reliability, clear proxy env vars for the test process
/// so localhost traffic is never sent through a corporate proxy.
#[allow(unsafe_code)]
fn disable_proxies_for_tests() {
    // Only clear if a proxy is set; keep environment untouched otherwise.
    let has_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();
    if !has_proxy {
        return;
    }
    // Remove all common proxy variables to avoid library-specific behaviors.
    unsafe {
        env::remove_var("HTTP_PROXY");
        env::remove_var("http_proxy");
        env::remove_var("HTTPS_PROXY");
        env::remove_var("https_proxy");
    }
    trace!("Disabled HTTP(S)_PROXY for test run to protect localhost");
}

// Small utilities to reduce repetition
#[inline]
fn root_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns the absolute path to a test server TOML configuration file.
///
/// `name` should be just the filename (e.g. `"auth_plain.toml"`).
/// This resolves correctly regardless of which crate is calling it.
#[must_use]
pub fn test_config_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_data/configs/server/test")
        .join(name)
}

/// Like [`test_config_path`] but resolves paths under the `hsm/` sub-directory.
#[must_use]
pub fn hsm_config_path(name: &str) -> PathBuf {
    test_config_path("hsm").join(name)
}

fn path_to_string(p: &Path) -> Result<String, KmsClientError> {
    p.to_str()
        .map(str::to_owned)
        .ok_or_else(|| KmsClientError::Default("Can't convert path to string".to_owned()))
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication
/// # Panics
/// - if the server fails to start
pub async fn start_test_kms_server_with_config(config: ClapConfig) -> &'static TestsContext {
    trace!("Starting test server with config : {:#?}", config);
    ONCE.get_or_try_init(|| async move {
        let server_params = ServerParams::try_from(config).context(
            "Failed to create ServerParams from ClapConfig in start_default_test_kms_server",
        )?;
        start_from_server_params(server_params).await
    })
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}

/// Override the database backend used by `start_default_test_kms_server` via the
/// `KMS_TEST_DB` environment variable.
///
/// | `KMS_TEST_DB` value              | Backend        | Required env var(s)                          |
/// |----------------------------------|----------------|----------------------------------------------|
/// | unset / `sqlite`                 | SQLite         | —                                            |
/// | `postgresql` / `postgres`        | PostgreSQL     | `KMS_POSTGRES_URL` (falls back to localhost) |
/// | `mysql` / `mariadb`              | MySQL/MariaDB  | `KMS_MYSQL_URL` (falls back to localhost)    |
/// | `redis-findex` / `redis` (non-FIPS only) | Redis-findex | `KMS_REDIS_URL` or `REDIS_HOST`      |
fn apply_test_db_override(config: &mut ClapConfig) {
    let Ok(db) = env::var("KMS_TEST_DB") else {
        return; // default: SQLite, no override needed
    };
    match db.to_lowercase().as_str() {
        "postgresql" | "postgres" => {
            let url = env::var("KMS_POSTGRES_URL")
                .unwrap_or_else(|_| "postgresql://kms:kms@127.0.0.1:5432/kms".to_owned());
            config.db.database_type = Some("postgresql".to_owned());
            config.db.database_url = Some(url);
        }
        "mysql" | "mariadb" => {
            let url = env::var("KMS_MYSQL_URL")
                .unwrap_or_else(|_| "mysql://kms:kms@127.0.0.1:3306/kms".to_owned());
            config.db.database_type = Some("mysql".to_owned());
            config.db.database_url = Some(url);
        }
        #[cfg(feature = "non-fips")]
        "redis-findex" | "redis" => {
            let url = env::var("KMS_REDIS_URL")
                .or_else(|_| env::var("REDIS_HOST").map(|h| format!("redis://{h}:6379")))
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
            config.db.database_type = Some("redis-findex".to_owned());
            config.db.database_url = Some(url);
            config.db.redis_master_password = Some(
                env::var("KMS_REDIS_MASTER_PASSWORD")
                    .unwrap_or_else(|_| "master_password".to_owned()),
            );
        }
        _ => {} // unrecognized or non-FIPS redis: fall back to SQLite
    }
}

/// Start a test KMS server in a thread with the default options:
/// No TLS, no certificate authentication.
///
/// Configuration is loaded from `test_data/configs/server/test/auth_plain.toml` by default.
/// Set `KMS_TEST_DB` to `postgresql`, `mysql`, or `redis-findex` (non-FIPS only) to run
/// the full test suite against a different database backend transparently.
///
/// # Panics
/// - if the server fails to start
pub async fn start_default_test_kms_server() -> &'static TestsContext {
    trace!("Starting default test server");
    ensure_no_proxy_for_localhost();
    disable_proxies_for_tests();
    Box::pin(ONCE.get_or_try_init(|| async move {
        let config_path = root_dir().join("../../test_data/configs/server/test/auth_plain.toml");
        let mut config = load_test_config_from_toml(&config_path)?;
        apply_test_db_override(&mut config);
        start_server_from_config(config, &config_path).await
    }))
    .await
    .unwrap_or_else(|e| {
        error!("failed to start default test server: {e}");
        std::process::abort();
    })
}

/// TLS + certificate authentication.
///
/// Configuration is loaded from `test_data/configs/server/test/cert_auth.toml`.
pub async fn start_default_test_kms_server_with_cert_auth() -> &'static TestsContext {
    crate::init_openssl_providers_for_tests();
    trace!("Starting test server with cert auth");
    ONCE_SERVER_WITH_AUTH
        .get_or_try_init(|| async move {
            start_test_server_from_toml(
                &root_dir().join("../../test_data/configs/server/test/cert_auth.toml"),
            )
            .await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with cert auth: {e}");
            std::process::abort();
        })
}

/// Plain-HTTP server with JWT authentication enabled (Auth0 `IdP`).
///
/// Configuration is loaded from `test_data/configs/server/test/auth_plain_jwt.toml`.
pub async fn start_default_test_kms_server_with_jwt_auth() -> &'static TestsContext {
    crate::init_openssl_providers_for_tests();
    trace!("Starting test server with JWT auth");
    ONCE_SERVER_WITH_JWT_AUTH
        .get_or_try_init(|| async move {
            start_test_server_from_toml(
                &root_dir().join("../../test_data/configs/server/test/auth_plain_jwt.toml"),
            )
            .await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with JWT auth: {e}");
            std::process::abort();
        })
}

/// Non-revocable key IDs.
///
/// Base configuration is loaded from `test_data/configs/server/test/non_revocable.toml`;
/// the `non_revocable_key_id` field is injected from the argument.
pub async fn start_default_test_kms_server_with_non_revocable_key_ids(
    non_revocable_key_id: Option<Vec<String>>,
) -> &'static TestsContext {
    trace!("Starting test server with non-revocable key ids");
    ONCE_SERVER_WITH_NON_REVOCABLE_KEY
        .get_or_try_init(|| async move {
            let config_path =
                root_dir().join("../../test_data/configs/server/test/non_revocable.toml");
            let mut config = load_test_config_from_toml(&config_path)?;
            config.non_revocable_key_id = non_revocable_key_id;
            start_server_from_config(config, &config_path).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with non-revocable key ids: {e}");
            std::process::abort();
        })
}

/// With Utimaco HSM
pub async fn start_default_test_kms_server_with_utimaco_hsm() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM");
    ONCE_SERVER_WITH_HSM
        .get_or_try_init(|| async move {
            start_test_server_from_toml(
                &root_dir().join("../../test_data/configs/server/test/hsm.toml"),
            )
            .await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with utimaco hsm: {e}");
            std::process::abort();
        })
}

// Create a KEK in the HSM before running server with `key_encryption_key` arg
async fn create_kek_in_db() -> Result<(PathBuf, String), KmsClientError> {
    // Use a unique path per CI job to avoid conflicts when multiple CI runners
    // share the same /tmp directory.
    let workspace_dir = std::env::temp_dir().join(format!(
        "kms_test_kek_{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let kek_id = "hsm::0::kek";

    let workspace_clone = workspace_dir.clone();
    let ctx = start_test_server_with_patch(
        &hsm_config_path("hsm_jwt.toml"),
        move |config| {
            config.db.sqlite_path = workspace_clone.join("sqlite-data");
            config.workspace.root_data_path = workspace_clone.join("workspace");
            config.workspace.tmp_path = workspace_clone.join("tmp");
        },
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;

    // Create the KEK in the HSM (idempotent: ignore "already exists").
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt
                    | CryptographicUsageMask::WrapKey
                    | CryptographicUsageMask::UnwrapKey,
            ),
            object_type: Some(ObjectType::SymmetricKey),
            unique_identifier: Some(UniqueIdentifier::TextString(kek_id.to_owned())),
            activation_date: Some(time_normalize()?),
            ..Default::default()
        },
        protection_storage_masks: None,
    };
    match ctx.get_owner_client().create(create_request).await {
        Ok(_) => trace!("KEK created in HSM"),
        Err(e) if e.to_string().to_lowercase().contains("already exist") => {
            trace!("KEK already exists in HSM, reusing");
        }
        Err(e) => return Err(e),
    }

    ctx.stop_server().await?;

    Ok((workspace_dir, kek_id.to_owned()))
}

/// With Utimaco HSM
///
/// # Panics
/// - if the `workspace_dir` does not exist
/// - if the `kek_id` is empty
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server_with_utimaco_and_kek() -> &'static TestsContext {
    trace!("Starting test server with Utimaco HSM and KEK");
    Box::pin(ONCE_SERVER_WITH_KEK.get_or_try_init(|| async move {
        let (workspace_dir, kek_id) = Box::pin(create_kek_in_db()).await?;
        trace!(
            "Key encryption key created: {kek_id} in workspace {}",
            workspace_dir.display()
        );
        assert!(
            workspace_dir.exists() && !kek_id.is_empty(),
            "workspace_dir must exist and kek_id must be non-empty"
        );

        let config_path = hsm_config_path("hsm_kek.toml");
        let mut config = load_test_config_from_toml(&config_path)?;
        config.db.sqlite_path = workspace_dir.join("sqlite-data");
        config.db.clear_database = false;
        config.workspace.root_data_path = workspace_dir.join("workspace");
        config.workspace.tmp_path = workspace_dir.join("tmp");
        config.key_encryption_key = Some(kek_id);
        start_server_from_config(config, &config_path).await
    }))
    .await
    .unwrap_or_else(|e| {
        error!("failed to start test server with utimaco hsm: {e}");
        std::process::abort();
    })
}

// ---------------------------------------------------------------------------
// SoftHSM2 + KEK
// ---------------------------------------------------------------------------

pub(crate) static ONCE_SERVER_WITH_SOFTHSM2_KEK: OnceCell<TestsContext> = OnceCell::const_new();

/// Read the `SoftHSM2` slot id from the `HSM_SLOT_ID` environment variable.
///
/// # Panics
/// Panics if the variable is missing or not a valid `usize`.
#[allow(clippy::expect_used, clippy::panic)]
fn get_softhsm2_slot_id() -> usize {
    let raw = env::var("HSM_SLOT_ID").expect(
        "HSM_SLOT_ID environment variable must be set (by test_hsm_softhsm2.sh) to run \
         SoftHSM2+KEK tests",
    );
    raw.parse::<usize>().unwrap_or_else(|_| {
        panic!("HSM_SLOT_ID '{raw}' is not a valid usize");
    })
}

/// Bootstrap a KEK inside `SoftHSM2`.
///
/// Mirrors [`create_kek_in_db`] but uses the `SoftHSM2`-specific TOML and reads
/// the slot from `HSM_SLOT_ID`.
async fn create_softhsm2_kek_in_db() -> Result<(PathBuf, String), KmsClientError> {
    let slot = get_softhsm2_slot_id();
    let workspace_dir = std::env::temp_dir().join(format!(
        "kms_test_softhsm2_kek_{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let kek_id = format!("hsm::{slot}::kek");

    let workspace_clone = workspace_dir.clone();
    let ctx = start_test_server_with_patch(
        &hsm_config_path("hsm_softhsm2_jwt.toml"),
        move |config| {
            config.hsm.hsm_slot = vec![slot];
            config.db.sqlite_path = workspace_clone.join("sqlite-data");
            config.workspace.root_data_path = workspace_clone.join("workspace");
            config.workspace.tmp_path = workspace_clone.join("tmp");
        },
        TestClientOptions {
            send_jwt: true,
            ..Default::default()
        },
    )
    .await?;

    // Create the KEK in the HSM (idempotent: ignore "already exists").
    let create_request = Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt
                    | CryptographicUsageMask::Decrypt
                    | CryptographicUsageMask::WrapKey
                    | CryptographicUsageMask::UnwrapKey,
            ),
            object_type: Some(ObjectType::SymmetricKey),
            unique_identifier: Some(UniqueIdentifier::TextString(kek_id.clone())),
            activation_date: Some(time_normalize()?),
            ..Default::default()
        },
        protection_storage_masks: None,
    };
    match ctx.get_owner_client().create(create_request).await {
        Ok(_) => trace!("KEK created in HSM"),
        Err(e) if e.to_string().to_lowercase().contains("already exist") => {
            trace!("KEK already exists in HSM, reusing");
        }
        Err(e) => return Err(e),
    }

    ctx.stop_server().await?;

    Ok((workspace_dir, kek_id))
}

/// With `SoftHSM2` HSM + KEK
///
/// # Panics
/// - if `HSM_SLOT_ID` is not set
/// - if the `workspace_dir` does not exist
/// - if the `kek_id` is empty
#[allow(clippy::unwrap_used)]
pub async fn start_default_test_kms_server_with_softhsm2_and_kek() -> &'static TestsContext {
    trace!("Starting test server with SoftHSM2 HSM and KEK");
    let slot = get_softhsm2_slot_id();
    Box::pin(
        ONCE_SERVER_WITH_SOFTHSM2_KEK.get_or_try_init(|| async move {
            let (workspace_dir, kek_id) = Box::pin(create_softhsm2_kek_in_db()).await?;
            trace!(
                "SoftHSM2 key encryption key created: {kek_id} in workspace {}",
                workspace_dir.display()
            );
            assert!(
                workspace_dir.exists() && !kek_id.is_empty(),
                "workspace_dir must exist and kek_id must be non-empty"
            );

            let config_path = hsm_config_path("hsm_softhsm2_kek.toml");
            let mut config = load_test_config_from_toml(&config_path)?;
            config.hsm.hsm_slot = vec![slot];
            config.db.sqlite_path = workspace_dir.join("sqlite-data");
            config.db.clear_database = false;
            config.workspace.root_data_path = workspace_dir.join("workspace");
            config.workspace.tmp_path = workspace_dir.join("tmp");
            config.key_encryption_key = Some(kek_id);
            start_server_from_config(config, &config_path).await
        }),
    )
    .await
    .unwrap_or_else(|e| {
        error!("failed to start test server with softhsm2 hsm: {e}");
        std::process::abort();
    })
}

/// Privileged users — two distinct identities in the list.
///
/// Base configuration is loaded from `test_data/configs/server/test/privileged_users.toml`;
/// the `privileged_users` field is hardcoded to `["owner.client@acme.com", "user.privileged@acme.com"]`.
///
/// Uses a dedicated [`ONCE_SERVER_WITH_MULTI_PRIVILEGED_USERS`] cell so that
/// tests requiring both the owner *and* `user.privileged@acme.com` never share
/// state with tests that only register the owner (e.g. `privilege_bypass`).
pub async fn start_default_test_kms_server_with_multi_privileged_users() -> &'static TestsContext {
    trace!("Starting test server with multi privileged users");
    ONCE_SERVER_WITH_MULTI_PRIVILEGED_USERS
        .get_or_try_init(|| async move {
            let config_path =
                root_dir().join("../../test_data/configs/server/test/privileged_users.toml");
            let mut config = load_test_config_from_toml(&config_path)?;
            config.privileged_users = Some(vec![
                "owner.client@acme.com".to_owned(),
                "user.privileged@acme.com".to_owned(),
            ]);
            start_server_from_config(config, &config_path).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with multi privileged users: {e}");
            std::process::abort();
        })
}

/// Privileged users.
///
/// Base configuration is loaded from `test_data/configs/server/test/privileged_users.toml`;
/// the `privileged_users` field is injected from the argument.
pub async fn start_default_test_kms_server_with_privileged_users(
    privileged_users: Vec<String>,
) -> &'static TestsContext {
    trace!("Starting test server with privileged users");
    ONCE_SERVER_WITH_PRIVILEGED_USERS
        .get_or_try_init(|| async move {
            let config_path =
                root_dir().join("../../test_data/configs/server/test/privileged_users.toml");
            let mut config = load_test_config_from_toml(&config_path)?;
            config.privileged_users = Some(privileged_users);
            start_server_from_config(config, &config_path).await
        })
        .await
        .unwrap_or_else(|e| {
            error!("failed to start test server with PQC TLS cert: {e}");
            std::process::abort();
        })
}

#[derive(Debug)]
pub struct TestsContext {
    pub server_port: u16,
    pub owner_client_config: KmsClientConfig,
    pub user_client_config: KmsClientConfig,
    pub server_handle: ServerHandle,
    pub thread_handle: JoinHandle<Result<(), KmsClientError>>,
}

impl TestsContext {
    #[must_use]
    pub fn get_owner_client(&self) -> KmsClient {
        KmsClient::new_with_config(self.owner_client_config.clone()).unwrap_or_else(|e| {
            error!("Can't create a KMS owner client: {e}");
            std::process::abort();
        })
    }

    #[must_use]
    pub fn get_user_client(&self) -> KmsClient {
        KmsClient::new_with_config(self.user_client_config.clone()).unwrap_or_else(|e| {
            error!("Can't create a KMS user client: {e}");
            std::process::abort();
        })
    }

    pub async fn stop_server(self) -> Result<(), KmsClientError> {
        self.server_handle.stop(false).await;
        self.thread_handle
            .join()
            .map_err(|_e| kms_client_error!("failed joining the stop thread"))?
    }
}

/// Start a test KMS server with the given config in a separate thread
fn start_test_kms_server(
    server_params: ServerParams,
) -> Result<(ServerHandle, JoinHandle<Result<(), KmsClientError>>), KmsClientError> {
    let (tx, rx) = mpsc::channel::<ServerHandle>();

    let thread_handle = thread::spawn(move || {
        // allow others `spawn` to happen within the KMS Server in the future
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                error!("Error building tokio runtime: {e:?}");
                KmsClientError::UnexpectedError(e.to_string())
            })?;

        runtime
            .block_on(start_kms_server(Arc::new(server_params), Some(tx)))
            .map_err(|e| {
                error!("Error starting the KMS server: {e:?}");
                KmsClientError::UnexpectedError(e.to_string())
            })
    });
    trace!("Waiting for test KMS server to start...");
    let server_handle = rx.recv_timeout(Duration::from_secs(25)).map_err(|e| {
        KmsClientError::UnexpectedError(format!("Error getting test KMS server handle: {e}"))
    })?;
    trace!("... got handle ...");
    Ok((server_handle, thread_handle))
}

/// Wait for the server to start by reading the version
async fn wait_for_server_to_start(
    kms_client_config: &KmsClientConfig,
) -> Result<(), KmsClientError> {
    // Depending on the running environment, the server could take a bit of time to start
    // We try to query it with a dummy request until we are sure it is started.
    let kms_client = KmsClient::new_with_config(kms_client_config.clone())?;
    let mut retry = true;
    let mut timeout = 2;
    let mut waiting = 1;
    while retry {
        info!("...checking if the server is up...");
        let result = kms_client.version().await;
        if let Err(KmsClientError::Unauthorized(e)) = result {
            // The server is up with authentication problems
            warn!("Server is up but with authentication problems! Unauthorized: {e}");
            break;
        }
        if result.is_err() {
            timeout -= 1;
            retry = timeout >= 0;
            if retry {
                info!("The server is not up yet, retrying in {waiting}s... ({result:?}) ",);
                tokio::time::sleep(Duration::from_secs(waiting)).await;
                waiting *= 2;
            } else {
                info!("The server is still not up, stop trying.");
                kms_client_bail!("Can't start the kms server to run tests: {result:?}");
            }
        } else {
            info!("UP!");
            retry = false;
        }
    }
    Ok(())
}

/// Common finalization once the server parameters are fully constructed
async fn start_from_server_params(
    server_params: ServerParams,
) -> Result<TestsContext, KmsClientError> {
    // Protect local test connections from corporate proxies
    ensure_no_proxy_for_localhost();
    disable_proxies_for_tests();

    let opts = TestClientOptions::default();
    let owner_client_config = generate_owner_conf_from_opts(&server_params, &opts)?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    let use_jwt_token = server_params.identity_provider_configurations.is_some();
    let user_client_config =
        generate_user_conf_from_opts(&owner_client_config, use_jwt_token, &opts)?;
    let server_port = server_params.http_port;

    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    wait_for_server_to_start(&owner_client_config)
        .await
        .map_err(|e| {
            error!("Error waiting for server to start: {e:?}");
            KmsClientError::UnexpectedError(e.to_string())
        })?;

    Ok(TestsContext {
        server_port,
        owner_client_config,
        user_client_config,
        server_handle,
        thread_handle,
    })
}

fn set_access_token(
    use_jwt_token: bool,
    use_api_token: bool,
    access_token: Option<String>,
    api_token: Option<String>,
) -> Option<String> {
    if use_jwt_token {
        trace!("Setting access token for JWT: {access_token:?}");
        access_token
    } else if use_api_token {
        trace!("Setting access token for API: {api_token:?}");
        api_token
    } else {
        None
    }
}

/// Load a TOML configuration file into [`ClapConfig`], allocating a free port
/// and setting unique temp paths for `SQLite` and workspace.
///
/// This is the shared logic used by both [`start_test_server_from_toml`] and
/// the singleton wrappers that need to patch the config before starting.
fn load_test_config_from_toml(config_path: &Path) -> Result<ClapConfig, KmsClientError> {
    let toml_content = std::fs::read_to_string(config_path).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot read test server config at {}: {e}",
            config_path.display()
        ))
    })?;
    let mut config: ClapConfig = toml::from_str(&toml_content).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Cannot parse test server config at {}: {e}",
            config_path.display()
        ))
    })?;

    // Allocate a guaranteed-unique port: bind to :0, read the port, then
    // release so the KMS server can bind it immediately after.
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
        KmsClientError::UnexpectedError(format!("Failed to allocate port for test server: {e}"))
    })?;
    let port = listener
        .local_addr()
        .map_err(|e| {
            KmsClientError::UnexpectedError(format!("Failed to read port from listener: {e}"))
        })?
        .port();
    drop(listener);
    config.http.port = port;

    // Also dynamically allocate the socket server port to avoid conflicts
    // when multiple test servers run in parallel.
    if config.socket_server.socket_server_start {
        let socket_listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
            KmsClientError::UnexpectedError(format!(
                "Failed to allocate socket server port for test server: {e}"
            ))
        })?;
        let socket_port = socket_listener
            .local_addr()
            .map_err(|e| {
                KmsClientError::UnexpectedError(format!(
                    "Failed to read socket server port from listener: {e}"
                ))
            })?
            .port();
        drop(socket_listener);
        config.socket_server.socket_server_port = socket_port;
    }

    // Use a unique temp directory for SQLite and workspace to avoid collisions.
    // Combine timestamp with an atomic counter so that tests starting within
    // the same clock tick (macOS resolution ≈ 1 µs) still get distinct paths.
    let tmp_dir = std::env::temp_dir().join(format!(
        "kms_test_toml_{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    config.db.sqlite_path = tmp_dir.join("sqlite-data");
    // Give each test its own isolated database space so that parallel tests
    // with fixed UIDs (KAT / regression vectors) never conflict with each other.
    // • SQLite: unique file path (set above) — always safe to clear.
    // • Other backends (PostgreSQL, MySQL, Redis): vector tests use singleton
    //   servers (one per backend) with `clear_database = true` at startup,
    //   avoiding parallel schema/table conflicts.
    let db_type = config.db.database_type.as_deref().unwrap_or("sqlite");
    if db_type == "sqlite" {
        config.db.clear_database = true;
    }
    config.workspace.root_data_path = tmp_dir.join("workspace");
    config.workspace.tmp_path = tmp_dir.join("tmp");

    // Resolve any relative TLS cert paths relative to the repo root so that
    // test servers launched from any crate (e.g. ckms) find the files correctly
    // regardless of the process working directory.
    let repo_root = root_dir().join("../../");
    let abs = |p: Option<PathBuf>| {
        p.map(|x| {
            if x.is_relative() {
                repo_root.join(x)
            } else {
                x
            }
        })
    };
    config.tls.tls_cert_file = abs(config.tls.tls_cert_file);
    config.tls.tls_key_file = abs(config.tls.tls_key_file);
    config.tls.tls_chain_file = abs(config.tls.tls_chain_file);
    config.tls.clients_ca_cert_file = abs(config.tls.clients_ca_cert_file);

    Ok(config)
}

/// Start a server from a pre-loaded (and optionally patched) [`ClapConfig`].
async fn start_server_from_config(
    config: ClapConfig,
    config_path: &Path,
) -> Result<TestsContext, KmsClientError> {
    ensure_no_proxy_for_localhost();
    disable_proxies_for_tests();

    let server_params = ServerParams::try_from(config).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Failed to create ServerParams from TOML config {}: {e}",
            config_path.display()
        ))
    })?;

    start_from_server_params(server_params).await
}

/// Start an isolated test KMS server from a TOML configuration file.
///
/// The TOML file is loaded into [`ClapConfig`], the HTTP port is overridden to a
/// free port for safe parallel test execution, and the `SQLite` path and workspace
/// directory are set to unique temp paths to avoid cross-test interference.
///
/// Each call starts a **new** server instance — there is no `OnceCell` caching.
/// The caller is responsible for stopping the server when done (via
/// [`TestsContext::stop_server()`]).
///
/// # Arguments
/// * `config_path` — Path to a TOML file that can be deserialized into `ClapConfig`
///   (e.g. `test_data/configs/server/test/auth_plain.toml`).
///
/// # Errors
/// Returns an error if the file cannot be read/parsed, or if the server fails to start.
pub async fn start_test_server_from_toml(
    config_path: &Path,
) -> Result<TestsContext, KmsClientError> {
    let config = load_test_config_from_toml(config_path)?;
    start_server_from_config(config, config_path).await
}

// ─── New TOML-driven API (replaces build_server_params_full) ─────────────────

/// Simplified client authentication options for test scenarios.
///
/// Controls what credentials the test client sends to the server.
/// Replaces the former `ClientAuthOptions` + `JwtPolicy` + `ClientCertPolicy` + `ApiTokenPolicy`.
#[derive(Clone, Debug)]
pub struct TestClientOptions {
    /// Extra HTTP client configuration (e.g. explicit cert paths, access tokens).
    pub http: HttpClientConfig,
    /// Whether the client should send a JWT token (when the server has an `IdP` configured).
    pub send_jwt: bool,
    /// Whether the client should present a TLS client certificate.
    pub send_client_cert: bool,
    /// Whether the client should send an API token (from `http.access_token`).
    pub send_api_token: bool,
}

impl Default for TestClientOptions {
    fn default() -> Self {
        Self {
            http: HttpClientConfig::default(),
            send_jwt: true,
            send_client_cert: true,
            send_api_token: true,
        }
    }
}

/// Start a test server from a TOML config file with default client options.
///
/// The server is started in a dedicated thread with dynamic port allocation.
/// Returns a [`TestsContext`] for interacting with the running server.
///
/// # Arguments
/// * `config_path` — Path to a TOML config file (relative to repo root or absolute).
pub async fn start_test_server(
    config_path: &Path,
    client_opts: TestClientOptions,
) -> Result<TestsContext, KmsClientError> {
    start_test_server_with_patch(config_path, |_| {}, client_opts).await
}

/// Start a test server from a TOML config file, applying a runtime patch to the config.
///
/// Use this when you need to inject runtime-determined values (e.g. `api_token_id`,
/// `privileged_users`, `key_encryption_key`) that cannot be known at TOML authoring time.
///
/// # Arguments
/// * `config_path` — Path to a TOML config file.
/// * `patch` — A closure that mutates the loaded [`ClapConfig`] before starting the server.
/// * `client_opts` — Controls what credentials the test client sends.
pub async fn start_test_server_with_patch(
    config_path: &Path,
    patch: impl FnOnce(&mut ClapConfig),
    client_opts: TestClientOptions,
) -> Result<TestsContext, KmsClientError> {
    ensure_no_proxy_for_localhost();
    disable_proxies_for_tests();

    let mut config = load_test_config_from_toml(config_path)?;
    patch(&mut config);

    let server_params = ServerParams::try_from(config).map_err(|e| {
        KmsClientError::UnexpectedError(format!(
            "Failed to create ServerParams from TOML config {}: {e}",
            config_path.display()
        ))
    })?;

    // Build client configurations
    let owner_client_config = generate_owner_conf_from_opts(&server_params, &client_opts)?;

    info!(" -- Test KMS server configuration: {:#?}", server_params);
    info!(
        " -- Test KMS owner client configuration: {:#?}",
        owner_client_config
    );

    let use_jwt_token = server_params.identity_provider_configurations.is_some();
    let user_client_config =
        generate_user_conf_from_opts(&owner_client_config, use_jwt_token, &client_opts)?;
    let server_port = server_params.http_port;

    let (server_handle, thread_handle) = start_test_kms_server(server_params)?;

    wait_for_server_to_start(&owner_client_config)
        .await
        .map_err(|e| {
            error!("Error waiting for server to start: {e:?}");
            KmsClientError::UnexpectedError(e.to_string())
        })?;

    Ok(TestsContext {
        server_port,
        owner_client_config,
        user_client_config,
        server_handle,
        thread_handle,
    })
}

/// Generate owner client config from the new [`TestClientOptions`].
fn generate_owner_conf_from_opts(
    server_params: &ServerParams,
    opts: &TestClientOptions,
) -> Result<KmsClientConfig, KmsClientError> {
    let root_path = root_dir();

    let gmail_api_conf: Option<GmailApiConf> = env::var("TEST_GMAIL_API_CONF")
        .ok()
        .and_then(|config| serde_json::from_str(&config).ok());

    let server_requests_client_cert = server_params
        .tls_params
        .as_ref()
        .and_then(|tls| tls.clients_ca_cert_pem.as_ref())
        .is_some();
    let use_client_cert = server_requests_client_cert && opts.send_client_cert;

    let use_jwt_token = opts.send_jwt
        && server_params.identity_provider_configurations.is_some()
        && opts.http.access_token.is_none();

    let use_api_token = opts.send_api_token && opts.http.access_token.is_some();

    let mut http_conf = opts.http.clone();
    http_conf.server_url = if server_params.tls_params.is_some() {
        format!("https://localhost:{}", server_params.http_port)
    } else {
        format!("http://localhost:{}", server_params.http_port)
    };
    http_conf.accept_invalid_certs = true;
    http_conf.access_token = set_access_token(
        use_jwt_token,
        use_api_token,
        Some(AUTH0_TOKEN.to_owned()),
        if use_api_token {
            opts.http.access_token.clone()
        } else {
            None
        },
    );

    if use_client_cert {
        #[cfg(feature = "non-fips")]
        {
            let has_pkcs12 = http_conf.tls_client_pkcs12_path.is_some();
            let has_pem = http_conf.tls_client_pem_cert_path.is_some()
                && http_conf.tls_client_pem_key_path.is_some();

            if !has_pkcs12 && !has_pem {
                let p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.p12",
                );
                http_conf.tls_client_pkcs12_path = Some(path_to_string(&p)?);
                http_conf.tls_client_pkcs12_password = Some("password".to_owned());
                http_conf.tls_client_pem_cert_path = None;
                http_conf.tls_client_pem_key_path = None;
            } else if has_pkcs12 {
                http_conf.tls_client_pem_cert_path = None;
                http_conf.tls_client_pem_key_path = None;
            } else {
                http_conf.tls_client_pkcs12_path = None;
                http_conf.tls_client_pkcs12_password = None;
            }
        }
        #[cfg(not(feature = "non-fips"))]
        {
            let has_pem = http_conf.tls_client_pem_cert_path.is_some()
                && http_conf.tls_client_pem_key_path.is_some();
            if !has_pem {
                let cert_p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.crt",
                );
                let key_p = root_path.join(
                    "../../test_data/certificates/client_server/owner/owner.client.acme.com.key",
                );
                http_conf.tls_client_pem_cert_path = Some(path_to_string(&cert_p)?);
                http_conf.tls_client_pem_key_path = Some(path_to_string(&key_p)?);
            }
            http_conf.tls_client_pkcs12_path = None;
            http_conf.tls_client_pkcs12_password = None;
        }
    } else {
        http_conf.tls_client_pkcs12_path = None;
        http_conf.tls_client_pkcs12_password = None;
        http_conf.tls_client_pem_cert_path = None;
        http_conf.tls_client_pem_key_path = None;
    }

    Ok(KmsClientConfig {
        http_config: http_conf,
        gmail_api_conf,
        print_json: None,
        vendor_id: VENDOR_ID_COSMIAN.to_owned(),
        pkcs11_use_pin_as_access_token: None,
    })
}

/// Generate user client config from the new [`TestClientOptions`].
fn generate_user_conf_from_opts(
    owner_client_conf: &KmsClientConfig,
    use_jwt_token: bool,
    opts: &TestClientOptions,
) -> Result<KmsClientConfig, KmsClientError> {
    let root_dir = root_dir();
    let mut conf = owner_client_conf.clone();
    let is_https = conf.http_config.server_url.starts_with("https://");

    if is_https {
        #[cfg(feature = "non-fips")]
        {
            let p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.p12");
            conf.http_config.tls_client_pkcs12_path = Some(path_to_string(&p)?);
            conf.http_config.tls_client_pkcs12_password = Some("password".to_owned());
            conf.http_config.tls_client_pem_cert_path = None;
            conf.http_config.tls_client_pem_key_path = None;
        }
        #[cfg(not(feature = "non-fips"))]
        {
            let cert_p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.crt");
            let key_p = root_dir
                .join("../../test_data/certificates/client_server/user/user.client.acme.com.key");
            conf.http_config.tls_client_pem_cert_path = Some(path_to_string(&cert_p)?);
            conf.http_config.tls_client_pem_key_path = Some(path_to_string(&key_p)?);
            conf.http_config.tls_client_pkcs12_path = None;
            conf.http_config.tls_client_pkcs12_password = None;
        }
    } else {
        conf.http_config.tls_client_pkcs12_path = None;
        conf.http_config.tls_client_pkcs12_password = None;
        conf.http_config.tls_client_pem_cert_path = None;
        conf.http_config.tls_client_pem_key_path = None;
    }

    let should_send_jwt = opts.send_jwt && use_jwt_token;
    let should_send_api = opts.send_api_token && conf.http_config.access_token.is_some();
    conf.http_config.access_token = set_access_token(
        should_send_jwt,
        should_send_api,
        Some(AUTH0_TOKEN_USER.to_owned()),
        None,
    );

    Ok(conf)
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[allow(clippy::unwrap_in_result)]
#[tokio::test]
async fn test_start_server() -> Result<(), KmsClientError> {
    let context = start_test_server(
        &test_config_path("auth_plain.toml"),
        TestClientOptions::default(),
    )
    .await?;
    context.stop_server().await
}

#[cfg(test)]
#[cfg(feature = "non-fips")]
#[allow(clippy::panic_in_result_fn)]
#[tokio::test]
async fn test_start_server_from_toml() -> Result<(), KmsClientError> {
    let config_path = Path::new("../../test_data/configs/server/test/auth_plain.toml");
    let context = start_test_server_from_toml(config_path).await?;
    assert!(context.server_port > 0, "Server should be assigned a port");
    // Verify the server is responding
    let client = context.get_owner_client();
    let version = client.version().await?;
    assert!(!version.is_empty(), "Server should return a version");
    context.stop_server().await
}

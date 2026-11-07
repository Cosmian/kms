use std::{str::FromStr, time::Duration};

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    extra::tagging::SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX, kmip_objects::Object,
};
use cosmian_logger::reexport::tracing;
use serde::{Deserialize, Serialize};

use crate::{
    core::extract_serial_hex_from_object,
    db_error,
    error::{DbError, DbResult},
};

/// Completion marker for the one-time scan deriving wrapping-key IDs from stored objects.
pub(crate) const WRAPPING_KEY_BACKFILL_PARAM: &str = "wrapping_key_id_backfilled";

/// Completion marker for the one-time certificate `_serial=<HEX>` tag backfill.
pub(crate) const CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM: &str = "certificate_serial_tag_backfilled";

/// Maximum time a starting instance waits for another instance's migration lock.
pub(crate) const MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_mins(31);
const MIGRATION_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(500);
const SUPPORTED_BASELINE: Version = Version(5, 20, 0);

/// Data transformations whose markers and version checkpoints are owned by the runner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationStep {
    /// Make pre-existing wrapped objects discoverable through `find_wrapped_by`.
    WrappingKeyIdBackfill,
    /// Add serial lookup tags to certificates created before that tag existed.
    CertificateSerialTagBackfill,
}

/// Strictly ascending release boundaries; adding a step also requires backend and scenario tests.
pub(crate) const MIGRATION_STEPS: [MigrationStep; 2] = [
    MigrationStep::WrappingKeyIdBackfill,
    MigrationStep::CertificateSerialTagBackfill,
];

impl MigrationStep {
    pub(crate) const fn version(self) -> &'static str {
        match self {
            Self::WrappingKeyIdBackfill => "5.25.0",
            Self::CertificateSerialTagBackfill => "5.29.0",
        }
    }

    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::WrappingKeyIdBackfill => WRAPPING_KEY_BACKFILL_PARAM,
            Self::CertificateSerialTagBackfill => CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Version(u32, u32, u32);

impl FromStr for Version {
    type Err = DbError;

    fn from_str(value: &str) -> DbResult<Self> {
        let invalid = || {
            db_error!("Invalid database migration version '{value}': expected MAJOR.MINOR.PATCH")
        };
        let core = value.split(['-', '+']).next().ok_or_else(invalid)?;
        let mut components = core.split('.');
        let mut component = || {
            components
                .next()
                .filter(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .ok_or_else(invalid)?
                .parse::<u32>()
                .map_err(|error| db_error!("Invalid database migration version '{value}': {error}"))
        };
        let version = Self(component()?, component()?, component()?);
        if components.next().is_some() {
            return Err(invalid());
        }
        Ok(version)
    }
}

fn newer_database_error(recorded: &str, target: &str) -> DbError {
    db_error!(
        "Database version {recorded} is newer than this KMS server version {target}: \
         refusing to start. Upgrade the KMS server to {recorded} or later."
    )
}

/// Poll without blocking the runtime; attempts may borrow a dedicated mutable backend connection.
pub(crate) async fn wait_for_migration_lock(
    lock_name: &str,
    max_wait: Duration,
    mut try_acquire: impl AsyncFnMut() -> DbResult<bool>,
) -> DbResult<()> {
    tokio::time::timeout(max_wait, async {
        loop {
            if try_acquire().await? {
                return Ok(());
            }
            tokio::time::sleep(MIGRATION_LOCK_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|error| {
        db_error!(
            "Timed out after {max_wait:?} waiting for database migration lock '{lock_name}': \
             held by another KMS instance ({error})"
        )
    })?
}

/// `_serial=<HEX>` tag for a certificate object (same value as `set_certificate_serial_tag`),
/// `None` (with a warning) for any other object or an unparsable certificate.
pub(crate) fn certificate_serial_tag(uid: &str, object: &Object) -> Option<String> {
    let Some(hex) = extract_serial_hex_from_object(object) else {
        tracing::warn!(
            %uid,
            "serial tag backfill: skipping object with unparsable certificate DER or non-certificate payload"
        );
        return None;
    };
    Some(format!("{SYSTEM_TAG_CERTIFICATE_SERIAL_PREFIX}{hex}"))
}

/// Persisted as JSON strings (`"ready"` and `"upgrading"`) on every backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DbState {
    Ready,
    Upgrading,
}

/// Backend metadata: SQL `parameters` rows or plain Redis keys, with stable serialization.
#[async_trait(?Send)]
pub(crate) trait DbParameters {
    /// Unknown names are absent; startup readers must also handle an uncreated parameters table.
    async fn get_parameter(&self, name: &str) -> DbResult<Option<String>>;

    /// Store the text verbatim; the provided state setter owns JSON serialization.
    async fn set_parameter(&self, name: &str, value: &str) -> DbResult<()>;

    async fn get_db_version(&self) -> DbResult<Option<String>> {
        self.get_parameter("db_version").await
    }

    async fn set_db_version(&self, version: &str) -> DbResult<()> {
        self.set_parameter("db_version", version).await
    }

    async fn get_db_state(&self) -> DbResult<Option<DbState>> {
        self.get_parameter("db_state")
            .await?
            .map(|state| serde_json::from_str(&state).map_err(DbError::from))
            .transpose()
    }

    async fn set_db_state(&self, state: DbState) -> DbResult<()> {
        self.set_parameter("db_state", &serde_json::to_string(&state)?)
            .await
    }
}

/// Startup-only migrations, serialized before any pool is exposed to request handlers.
#[async_trait(?Send)]
pub(crate) trait Migrate: DbParameters {
    /// Owns the backend's lock or session until dropped, including error paths.
    type MigrationLock;

    /// A populated, unversioned database is refused when this is `None`.
    const UNVERSIONED_BASELINE: Option<&'static str>;

    /// Check for stored objects, not metadata or the migration lock itself.
    async fn has_data(&self) -> DbResult<bool>;

    /// Wait for a cross-instance lock and retain its dedicated resource until guard drop.
    async fn acquire_migration_lock(&self) -> DbResult<Self::MigrationLock>;

    /// Idempotent schema DDL and the optional wipe, without data backfills.
    async fn ensure_schema(&self, clear_database: bool) -> DbResult<()>;

    /// Data changes only: implementations must be idempotent and must not manage markers.
    async fn apply_step(&self, step: MigrationStep) -> DbResult<()>;

    /// Requires an existing schema and a held migration lock; prefer `bootstrap` at startup.
    async fn upgrade_to(&self, target: &str) -> DbResult<Vec<MigrationStep>> {
        let target_version = target.parse::<Version>()?;
        if self.get_db_state().await? == Some(DbState::Upgrading) {
            tracing::warn!("Interrupted database migration detected; resuming");
        }
        let stored_version = self.get_db_version().await?;
        let recorded = match stored_version.as_deref() {
            Some(version) => version,
            None if !self.has_data().await? => {
                self.set_db_version(target).await?;
                self.set_db_state(DbState::Ready).await?;
                return Ok(Vec::new());
            }
            None => {
                let baseline = Self::UNVERSIONED_BASELINE.ok_or_else(|| {
                    db_error!(
                        "Unversioned populated Redis/Findex database: pre-5.12.0 data is unsupported; \
                         export and re-import."
                    )
                })?;
                tracing::info!(
                    baseline,
                    "Unversioned database with data; assuming the migration baseline"
                );
                baseline
            }
        };
        let mut recorded_version = recorded.parse::<Version>()?;
        if recorded_version > target_version {
            return Err(newer_database_error(recorded, target));
        }
        if recorded_version < SUPPORTED_BASELINE {
            tracing::warn!(
                recorded,
                "transparent migration supported from 5.20.0; attempting all registered steps"
            );
            recorded_version = Version(0, 0, 0);
        }
        let applied = apply_pending_steps(self, recorded_version, target_version).await?;
        self.set_db_version(target).await?;
        self.set_db_state(DbState::Ready).await?;
        tracing::info!(
            target,
            applied_steps = applied.len(),
            "Database migration completed"
        );
        Ok(applied)
    }

    /// Validate the recorded version before DDL, then keep the lock through the final ready stamp.
    async fn bootstrap(&self, clear_database: bool, target: &str) -> DbResult<Vec<MigrationStep>> {
        let _lock = self.acquire_migration_lock().await?;
        let target_version = target.parse::<Version>()?;
        if let Some(recorded) = self.get_db_version().await? {
            let recorded_version = recorded.parse::<Version>()?;
            if !clear_database && recorded_version > target_version {
                return Err(newer_database_error(&recorded, target));
            }
        }
        self.ensure_schema(clear_database).await?;
        if clear_database {
            self.set_db_version(target).await?;
            self.set_db_state(DbState::Ready).await?;
            return Ok(Vec::new());
        }
        self.upgrade_to(target).await
    }
}

async fn apply_pending_steps(
    database: &(impl Migrate + ?Sized),
    recorded: Version,
    target: Version,
) -> DbResult<Vec<MigrationStep>> {
    let mut applied = Vec::new();
    let mut upgrading = false;
    for step in MIGRATION_STEPS {
        let version = step.version().parse::<Version>()?;
        if !(recorded < version && version <= target) {
            continue;
        }
        if !upgrading {
            database.set_db_state(DbState::Upgrading).await?;
            upgrading = true;
        }
        if database.get_parameter(step.marker()).await?.as_deref() != Some("true") {
            tracing::info!(
                ?step,
                version = step.version(),
                "Applying database migration step"
            );
            database.apply_step(step).await?;
            database.set_parameter(step.marker(), "true").await?;
            applied.push(step);
        }
        database.set_db_version(step.version()).await?;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::HashMap,
        fs::{File, TryLockError},
        rc::Rc,
        time::Instant,
    };

    use tempfile::TempDir;
    use tokio::sync::Notify;

    use super::*;
    use crate::db_ensure;

    #[derive(Default)]
    struct InMemoryMigrationBackend {
        parameters: RefCell<HashMap<String, String>>,
        fail_step: Cell<Option<MigrationStep>>,
        attempted: RefCell<Vec<MigrationStep>>,
        locked: Rc<Cell<bool>>,
    }

    struct InMemoryMigrationLock(Rc<Cell<bool>>);

    impl Drop for InMemoryMigrationLock {
        fn drop(&mut self) {
            self.0.set(false);
        }
    }

    #[async_trait(?Send)]
    impl DbParameters for InMemoryMigrationBackend {
        async fn get_parameter(&self, name: &str) -> DbResult<Option<String>> {
            Ok(self.parameters.borrow().get(name).cloned())
        }

        async fn set_parameter(&self, name: &str, value: &str) -> DbResult<()> {
            self.parameters
                .borrow_mut()
                .insert(name.to_owned(), value.to_owned());
            Ok(())
        }
    }

    #[async_trait(?Send)]
    impl Migrate for InMemoryMigrationBackend {
        type MigrationLock = InMemoryMigrationLock;

        const UNVERSIONED_BASELINE: Option<&'static str> = Some("5.20.0");

        async fn has_data(&self) -> DbResult<bool> {
            Ok(true)
        }

        async fn acquire_migration_lock(&self) -> DbResult<Self::MigrationLock> {
            db_ensure!(!self.locked.replace(true), "Test migration lock is held");
            Ok(InMemoryMigrationLock(Rc::clone(&self.locked)))
        }

        async fn ensure_schema(&self, clear_database: bool) -> DbResult<()> {
            db_ensure!(!clear_database, "Unexpected test database clear");
            Ok(())
        }

        async fn apply_step(&self, step: MigrationStep) -> DbResult<()> {
            self.attempted.borrow_mut().push(step);
            db_ensure!(
                self.fail_step.get() != Some(step),
                "Injected migration failure: {step:?}"
            );
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_migration_step_failure_preserves_checkpoint_and_resumes() -> DbResult<()> {
        let database = InMemoryMigrationBackend::default();
        database.set_db_version("5.20.0").await?;
        database.set_db_state(DbState::Ready).await?;
        database
            .fail_step
            .set(Some(MigrationStep::CertificateSerialTagBackfill));

        let error = database
            .bootstrap(false, "5.29.0")
            .await
            .err()
            .ok_or_else(|| db_error!("The selected migration step must fail"))?;
        db_ensure!(
            error
                .to_string()
                .contains("Injected migration failure: CertificateSerialTagBackfill"),
            "Unexpected migration failure: {error}"
        );
        db_ensure!(
            database
                .get_parameter(WRAPPING_KEY_BACKFILL_PARAM)
                .await?
                .as_deref()
                == Some("true"),
            "The completed first step must be marked"
        );
        db_ensure!(
            database
                .get_parameter(CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM)
                .await?
                .is_none(),
            "A failed step must not be marked complete"
        );
        db_ensure!(
            database.get_db_version().await?.as_deref() == Some("5.25.0"),
            "The failed step must leave the previous version checkpoint"
        );
        db_ensure!(
            database.get_db_state().await? == Some(DbState::Upgrading),
            "The failed migration must remain upgrading"
        );
        let lock = database.acquire_migration_lock().await?;
        drop(lock);

        database.fail_step.set(None);
        let applied = database.bootstrap(false, "5.29.0").await?;
        db_ensure!(
            applied == [MigrationStep::CertificateSerialTagBackfill],
            "Resume must apply only the previously failed step: {applied:?}"
        );
        db_ensure!(
            database.attempted.borrow().as_slice()
                == [
                    MigrationStep::WrappingKeyIdBackfill,
                    MigrationStep::CertificateSerialTagBackfill,
                    MigrationStep::CertificateSerialTagBackfill,
                ],
            "The completed step must not be re-applied"
        );
        db_ensure!(
            database
                .get_parameter(CERTIFICATE_SERIAL_TAG_BACKFILL_PARAM)
                .await?
                .as_deref()
                == Some("true"),
            "The resumed step must be marked complete"
        );
        db_ensure!(
            database.get_db_version().await?.as_deref() == Some("5.29.0"),
            "The resumed migration must stamp the target version"
        );
        db_ensure!(
            database.get_db_state().await? == Some(DbState::Ready),
            "The resumed migration must finish ready"
        );
        Ok(())
    }

    #[test]
    fn test_db_state_serialization_is_stable() {
        assert_eq!(
            serde_json::to_string(&DbState::Ready).ok().as_deref(),
            Some("\"ready\"")
        );
        assert_eq!(
            serde_json::to_string(&DbState::Upgrading).ok().as_deref(),
            Some("\"upgrading\"")
        );
        assert_eq!(
            serde_json::from_str::<DbState>("\"upgrading\"").ok(),
            Some(DbState::Upgrading)
        );
        assert_eq!(serde_json::from_str::<DbState>("\"bogus\"").ok(), None);
    }

    #[test]
    fn test_migration_versions_parse_and_compare() -> DbResult<()> {
        db_ensure!(
            "5.20.0".parse::<Version>()? == Version(5, 20, 0),
            "Version parse failed"
        );
        db_ensure!(
            "5.9.9".parse::<Version>()? < "5.10.0".parse::<Version>()?,
            "Minor versions must compare numerically"
        );
        db_ensure!(
            "5.24.99".parse::<Version>()? < "5.25.0".parse::<Version>()?,
            "Minor version must precede patch version"
        );
        db_ensure!(
            "5.29.0".parse::<Version>()? < "6.0.0".parse::<Version>()?,
            "Major version ordering failed"
        );
        Ok(())
    }

    #[test]
    fn test_migration_versions_strip_suffixes() -> DbResult<()> {
        for version in ["5.29.0-rc.1", "5.29.0+build.2", "5.29.0-rc.1+build.2"] {
            db_ensure!(
                version.parse::<Version>()? == Version(5, 29, 0),
                "Suffix was not stripped: {version}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_migration_versions_reject_invalid_input() -> DbResult<()> {
        for version in [
            "",
            "5.20",
            "5.20.0.1",
            "5.-1.0",
            "a.20.0",
            "4294967296.0.0",
            "5.20. 0",
            "5.20.0oops",
        ] {
            let error = version
                .parse::<Version>()
                .err()
                .ok_or_else(|| db_error!("Invalid version unexpectedly accepted: {version}"))?;
            db_ensure!(
                error
                    .to_string()
                    .contains("Invalid database migration version"),
                "Unexpected parse error: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_migration_steps_are_ordered_and_reachable() -> DbResult<()> {
        for (previous, next) in MIGRATION_STEPS.iter().zip(MIGRATION_STEPS.iter().skip(1)) {
            db_ensure!(
                previous.version().parse::<Version>()? < next.version().parse::<Version>()?,
                "Migration steps must be strictly ascending"
            );
            db_ensure!(
                previous.marker() != next.marker(),
                "Migration markers must differ"
            );
        }
        let last = MIGRATION_STEPS
            .last()
            .ok_or_else(|| db_error!("Migration step registry must not be empty"))?;
        db_ensure!(
            last.version().parse::<Version>()? <= env!("CARGO_PKG_VERSION").parse::<Version>()?,
            "The last migration exceeds the running package version"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_migration_lock_waits_for_release() -> DbResult<()> {
        let directory = TempDir::new()?;
        let path = directory.path().join("migration.lock");
        let held = File::options().create_new(true).write(true).open(&path)?;
        held.try_lock().map_err(std::io::Error::from)?;
        let waiting = File::options().write(true).open(&path)?;
        let attempted = Notify::new();
        let attempts = Cell::new(0_usize);
        let start = Instant::now();
        let acquire =
            wait_for_migration_lock("held-test-lock", Duration::from_secs(2), async || {
                attempts.set(attempts.get().saturating_add(1));
                match waiting.try_lock() {
                    Ok(()) => Ok(true),
                    Err(TryLockError::WouldBlock) => {
                        attempted.notify_one();
                        Ok(false)
                    }
                    Err(TryLockError::Error(error)) => Err(error.into()),
                }
            });
        let release = async {
            attempted.notified().await;
            drop(held);
        };
        let (acquired, ()) = tokio::join!(acquire, release);
        acquired?;
        db_ensure!(
            attempts.get() == 2,
            "Expected one blocked attempt followed by success"
        );
        db_ensure!(
            start.elapsed() >= MIGRATION_LOCK_POLL_INTERVAL,
            "Lock wait did not respect the polling interval"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_migration_lock_wait_cap() -> DbResult<()> {
        let directory = TempDir::new()?;
        let path = directory.path().join("migration.lock");
        let held = File::options().create_new(true).write(true).open(&path)?;
        held.try_lock().map_err(std::io::Error::from)?;
        let waiting = File::options().write(true).open(&path)?;
        let error =
            wait_for_migration_lock("held-test-lock", Duration::from_millis(20), async || {
                match waiting.try_lock() {
                    Ok(()) => Ok(true),
                    Err(TryLockError::WouldBlock) => Ok(false),
                    Err(TryLockError::Error(error)) => Err(error.into()),
                }
            })
            .await
            .err()
            .ok_or_else(|| db_error!("A held migration lock must time out"))?;
        db_ensure!(
            error.to_string().contains("Timed out after 20ms"),
            "Wrong lock-wait cap: {error}"
        );
        db_ensure!(
            error.to_string().contains("held-test-lock"),
            "Timeout did not identify the lock"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_migration_lock_attempt_can_borrow_mutable_resource() -> DbResult<()> {
        let mut attempts = 0_u32;
        wait_for_migration_lock("mutable-resource", Duration::from_secs(1), async || {
            tokio::task::yield_now().await;
            attempts = attempts.saturating_add(1);
            Ok(true)
        })
        .await?;
        db_ensure!(
            attempts == 1,
            "The mutable-resource attempt did not run exactly once"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_migration_lock_propagates_backend_errors() -> DbResult<()> {
        let error = wait_for_migration_lock("failed-lock", Duration::from_secs(1), async || {
            Err(db_error!("Backend lock acquisition failed"))
        })
        .await
        .err()
        .ok_or_else(|| db_error!("A backend lock error must fail startup"))?;
        db_ensure!(
            error.to_string() == "Database Error: Backend lock acquisition failed",
            "Backend error was not propagated: {error}"
        );
        Ok(())
    }

    #[test]
    fn test_certificate_serial_tag_rejects_invalid_der_and_non_certificates() -> DbResult<()> {
        use std::sync::{Arc, Mutex};

        use tracing::{
            Event, Level, Metadata, Subscriber,
            field::{Field, Visit},
            span::{Attributes, Id, Record},
        };

        struct WarnVisitor(String);
        impl Visit for WarnVisitor {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value:?} ", field.name());
            }
        }
        struct WarnSubscriber(Arc<Mutex<Vec<String>>>);
        impl Subscriber for WarnSubscriber {
            fn enabled(&self, metadata: &Metadata<'_>) -> bool {
                metadata.level() == &Level::WARN
            }

            fn new_span(&self, _span: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }

            fn record(&self, _span: &Id, _values: &Record<'_>) {}

            fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

            fn event(&self, event: &Event<'_>) {
                if event.metadata().level() == &Level::WARN {
                    let mut visitor = WarnVisitor(String::new());
                    event.record(&mut visitor);
                    if let Ok(mut guard) = self.0.lock() {
                        guard.push(visitor.0);
                    }
                }
            }

            fn enter(&self, _span: &Id) {}

            fn exit(&self, _span: &Id) {}
        }

        let warnings = Arc::new(Mutex::new(Vec::new()));
        let bad_der: Object = serde_json::from_str(
            r#"{"Certificate":{"CertificateType":"X509","CertificateValue":[222,173,190,239]}}"#,
        )?;
        let non_cert: Object = serde_json::from_str(
            r#"{"OpaqueObject":{"OpaqueDataType":"Unknown","OpaqueDataValue":[1,2,3,4]}}"#,
        )?;
        tracing::subscriber::with_default(
            WarnSubscriber(Arc::clone(&warnings)),
            || -> DbResult<()> {
                db_ensure!(
                    certificate_serial_tag("junk_bad_cert_der", &bad_der).is_none(),
                    "Garbage DER must not produce a certificate serial tag"
                );
                db_ensure!(
                    certificate_serial_tag("junk_non_cert_tagged_cert", &non_cert).is_none(),
                    "A non-certificate object must not produce a certificate serial tag"
                );
                Ok(())
            },
        )?;
        let recorded = warnings
            .lock()
            .map_err(|error| db_error!("Warn log mutex poisoned: {error}"))?;
        db_ensure!(
            recorded.len() == 2
                && recorded
                    .iter()
                    .any(|line| line.contains("junk_bad_cert_der"))
                && recorded
                    .iter()
                    .any(|line| line.contains("junk_non_cert_tagged_cert")),
            "Expected warnings for both invalid certificate objects, got {recorded:?}"
        );
        Ok(())
    }
}

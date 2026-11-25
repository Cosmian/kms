use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use k8s_openapi::{
    api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::Secret,
    },
    apimachinery::pkg::apis::meta::v1::ObjectMeta,
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams, PostParams},
    runtime::{controller::Action, watcher::Config as WatcherConfig},
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::{
    crd::{KMSSecret, KMSSecretStatus},
    error::OperatorError,
    kms::KmsClientWrapper,
};

// ── Context shared by all reconciler invocations ──────────────────────────────

pub struct Context {
    pub k8s: Client,
    pub kms: Arc<KmsClientWrapper>,
    pub default_refresh: Duration,
    /// Namespace → KMS UIDs a `KMSSecret` of that namespace may fetch (fail closed).
    pub allowed_uids_by_namespace: BTreeMap<String, BTreeSet<String>>,
}

/// Label recording which `KMSSecret` owns a target `Secret`.
const OWNER_LABEL: &str = "kms.cosmian.com/kmssecret";
/// Label written by operator versions that predate [`OWNER_LABEL`].
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "cosmian-kms-operator";

/// Refuse a KMS UID that is not allowlisted for `namespace` (confused-deputy guard: the
/// operator's KMS credentials must not be usable by any tenant to read any key).
fn check_secret_access(
    policy: &BTreeMap<String, BTreeSet<String>>,
    namespace: &str,
    uid: &str,
) -> Result<(), OperatorError> {
    if policy.get(namespace).is_some_and(|uids| uids.contains(uid)) {
        Ok(())
    } else {
        Err(OperatorError::Config(format!(
            "KMS UID '{uid}' is not allowed for namespace '{namespace}'"
        )))
    }
}

/// Refuse to overwrite a target `Secret` that is not owned by this `KMSSecret`. A legacy
/// operator-managed `Secret` (no owner label) is adopted.
fn check_secret_ownership(
    existing: Option<&Secret>,
    kmssecret_name: &str,
) -> Result<(), OperatorError> {
    let Some(existing) = existing else {
        return Ok(());
    };
    let labels = existing.metadata.labels.as_ref();
    let owner = labels.and_then(|l| l.get(OWNER_LABEL));
    let legacy = owner.is_none()
        && labels
            .and_then(|l| l.get(MANAGED_BY_LABEL))
            .map(String::as_str)
            == Some(MANAGED_BY_VALUE);
    if owner.map(String::as_str) == Some(kmssecret_name) || legacy {
        Ok(())
    } else {
        Err(OperatorError::Config(format!(
            "target Secret '{}' is not owned by KMSSecret '{kmssecret_name}'",
            existing.metadata.name.as_deref().unwrap_or_default()
        )))
    }
}

// ── Controller entry point ────────────────────────────────────────────────────

/// Start the controller and block forever.
pub async fn run(ctx: Arc<Context>) {
    use futures::StreamExt;
    use kube::runtime::Controller;

    let client = ctx.k8s.clone();
    let kms_secrets: Api<KMSSecret> = Api::all(client.clone());

    Controller::new(kms_secrets, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            reconcile,
            |obj, err, ctx| error_policy(&obj, err, &ctx),
            ctx,
        )
        .for_each(|result| async move {
            match result {
                Ok((obj, action)) => {
                    info!(name = %obj.name, ?action, "reconcile complete");
                }
                Err(e) => {
                    error!(error = %e, "reconcile failed");
                }
            }
        })
        .await;
}

// ── Reconcile function ────────────────────────────────────────────────────────

async fn reconcile(obj: Arc<KMSSecret>, ctx: Arc<Context>) -> Result<Action, OperatorError> {
    let namespace = obj.namespace().unwrap_or_else(|| "default".to_owned());
    let name = obj.name_any();

    match do_reconcile(&obj, &ctx, &namespace).await {
        Ok(action) => Ok(action),
        Err(err) => {
            // Reflect the failure in the CRD status so `kubectl get kmssecret`
            // shows `ready=False` with an error message.
            let last_hash = obj
                .status
                .as_ref()
                .and_then(|s| s.last_secret_hash.as_deref())
                .unwrap_or("");
            patch_status(
                &ctx.k8s,
                &namespace,
                &name,
                last_hash,
                Some(&err.to_string()),
            )
            .await;
            Err(err)
        }
    }
}

async fn do_reconcile(
    obj: &Arc<KMSSecret>,
    ctx: &Arc<Context>,
    namespace: &str,
) -> Result<Action, OperatorError> {
    let name = obj.name_any();

    info!(name, namespace, secret_id = %obj.spec.secret_id, "reconciling KMSSecret");

    // 1. Fetch secret bytes from KMS, only for UIDs allowlisted for this namespace.
    check_secret_access(
        &ctx.allowed_uids_by_namespace,
        namespace,
        &obj.spec.secret_id,
    )?;
    let bytes = ctx.kms.get_secret_bytes(&obj.spec.secret_id).await?;
    let current_hash = hex::encode(Sha256::digest(&bytes));

    // 2. Detect whether the value changed since last sync.
    let previous_hash = obj
        .status
        .as_ref()
        .and_then(|s| s.last_secret_hash.as_deref());
    let secret_changed = previous_hash != Some(current_hash.as_str());

    // 3. Create or update the target K8s Secret.
    upsert_secret(&ctx.k8s, namespace, obj, bytes).await?;

    // 4. Rolling-restart workloads if the secret value changed.
    if secret_changed {
        restart_workloads(&ctx.k8s, namespace, obj).await;
    }

    // 5. Update KMSSecret status.
    patch_status(&ctx.k8s, namespace, &name, &current_hash, None).await;

    // 6. Requeue after the configured refresh interval.
    Ok(Action::requeue(refresh_duration(obj, ctx.default_refresh)))
}

fn error_policy(obj: &KMSSecret, err: &OperatorError, _ctx: &Context) -> Action {
    error!(name = %obj.name_any(), error = %err, "reconcile error — retrying in 30s");
    Action::requeue(Duration::from_secs(30))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Create or update the managed K8s `Secret`.
async fn upsert_secret(
    client: &Client,
    namespace: &str,
    owner: &KMSSecret,
    bytes: Vec<u8>,
) -> Result<(), OperatorError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);

    let mut labels = owner.spec.labels.clone();
    labels.insert(
        "app.kubernetes.io/managed-by".to_owned(),
        MANAGED_BY_VALUE.to_owned(),
    );
    labels.insert(OWNER_LABEL.to_owned(), owner.name_any());

    let mut data: BTreeMap<String, k8s_openapi::ByteString> = BTreeMap::new();
    data.insert(owner.spec.key.clone(), k8s_openapi::ByteString(bytes));

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(owner.spec.target_secret.clone()),
            namespace: Some(namespace.to_owned()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        data: Some(data),
        ..Secret::default()
    };

    let existing = secrets.get_opt(&owner.spec.target_secret).await?;
    check_secret_ownership(existing.as_ref(), &owner.name_any())?;
    if existing.is_none() {
        secrets.create(&PostParams::default(), &secret).await?;
        info!(name = %owner.spec.target_secret, "created K8s Secret");
    } else {
        secrets
            .patch(
                &owner.spec.target_secret,
                &PatchParams::apply("cosmian-kms-operator").force(),
                &Patch::Apply(secret),
            )
            .await?;
        info!(name = %owner.spec.target_secret, "updated K8s Secret");
    }
    Ok(())
}

/// Trigger a rolling restart for declared Deployments and `StatefulSets` by
/// patching `spec.template.metadata.annotations` with the current timestamp.
async fn restart_workloads(client: &Client, namespace: &str, owner: &KMSSecret) {
    let now = rfc3339_now();
    restart_resource::<Deployment>(
        client,
        namespace,
        &owner.spec.restart_deployments,
        "Deployment",
        &now,
    )
    .await;
    restart_resource::<StatefulSet>(
        client,
        namespace,
        &owner.spec.restart_stateful_sets,
        "StatefulSet",
        &now,
    )
    .await;
}

/// Trigger a rolling restart for a list of resources of type `K` by patching
/// `spec.template.metadata.annotations` with the current timestamp.
async fn restart_resource<K>(
    client: &Client,
    namespace: &str,
    names: &[String],
    kind: &str,
    now: &str,
) where
    K: Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
        + DeserializeOwned
        + Clone
        + std::fmt::Debug,
{
    for name in names {
        let api: Api<K> = Api::namespaced(client.clone(), namespace);
        let patch = serde_json::json!({
            "spec": { "template": { "metadata": {
                "annotations": { "kubectl.kubernetes.io/restartedAt": now }
            }}}
        });
        match api
            .patch(name, &PatchParams::default(), &Patch::Merge(patch))
            .await
        {
            Ok(_) => info!(kind, name, "triggered rolling restart"),
            Err(e) => warn!(kind, name, error = %e, "failed to restart"),
        }
    }
}

/// Update the `KMSSecret` status subresource.
async fn patch_status(
    client: &Client,
    namespace: &str,
    name: &str,
    hash: &str,
    error_msg: Option<&str>,
) {
    let api: Api<KMSSecret> = Api::namespaced(client.clone(), namespace);
    let status = KMSSecretStatus {
        ready: if error_msg.is_none() { "True" } else { "False" }.to_owned(),
        message: error_msg.map(ToOwned::to_owned),
        last_secret_hash: Some(hash.to_owned()),
        last_sync_time: Some(rfc3339_now()),
    };
    let patch = serde_json::json!({ "status": status });
    if let Err(e) = api
        .patch_status(name, &PatchParams::default(), &Patch::Merge(patch))
        .await
    {
        warn!(name, error = %e, "failed to patch KMSSecret status");
    }
}

/// Parse the `refreshInterval` field or fall back to the operator default.
fn refresh_duration(obj: &KMSSecret, default: Duration) -> Duration {
    obj.spec
        .refresh_interval
        .as_deref()
        .and_then(parse_duration)
        .unwrap_or(default)
}

/// Parse a duration such as `30m`, `90s`, `1h30m` or `1h 30m`: one or more `<integer><unit>` groups
/// separated by optional whitespace. Units: `ns`/`nsec`, `us`/`usec`, `ms`/`msec`,
/// `s`/`sec`/`secs`/`second`/`seconds`, `m`/`min`/`mins`/`minute`/`minutes`,
/// `h`/`hr`/`hrs`/`hour`/`hours`, `d`/`day`/`days`, `w`/`week`/`weeks`.
///
/// Returns `None` for an empty or malformed string, an unknown unit, or a duration that overflows.
pub(crate) fn parse_duration(s: &str) -> Option<Duration> {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    let mut rest = s.trim();
    if rest.is_empty() {
        return None;
    }
    let mut total_nanos: u128 = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (digits, after_digits) = rest.split_at(digits_end);
        let value: u128 = digits.parse().ok()?;
        let after_digits = after_digits.trim_start();
        let unit_end = after_digits
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(after_digits.len());
        let (unit, after_unit) = after_digits.split_at(unit_end);
        let unit_nanos: u128 = match unit {
            "ns" | "nsec" => 1,
            "us" | "usec" => 1_000,
            "ms" | "msec" => 1_000_000,
            "s" | "sec" | "secs" | "second" | "seconds" => NANOS_PER_SEC,
            "m" | "min" | "mins" | "minute" | "minutes" => 60 * NANOS_PER_SEC,
            "h" | "hr" | "hrs" | "hour" | "hours" => 3_600 * NANOS_PER_SEC,
            "d" | "day" | "days" => 86_400 * NANOS_PER_SEC,
            "w" | "week" | "weeks" => 604_800 * NANOS_PER_SEC,
            _ => return None,
        };
        total_nanos = total_nanos.checked_add(value.checked_mul(unit_nanos)?)?;
        rest = after_unit.trim_start();
    }
    let secs = u64::try_from(total_nanos / NANOS_PER_SEC).ok()?;
    let subsec_nanos = u32::try_from(total_nanos % NANOS_PER_SEC).ok()?;
    Some(Duration::new(secs, subsec_nanos))
}

fn rfc3339_now() -> String {
    // Rfc3339 formatting of now_utc() only fails for years > 9999.
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod characterization_tests {
    //! Characterization tests for `error_policy` and `refresh_duration`.

    use std::{collections::BTreeMap, sync::Arc, time::Duration};

    use cosmian_kms_client::KmsClientConfig;
    use kube::runtime::controller::Action;

    use super::{Context, error_policy, refresh_duration};
    use crate::{
        crd::{KMSSecret, KMSSecretSpec},
        error::OperatorError,
        kms::KmsClientWrapper,
    };

    fn secret(refresh_interval: Option<&str>) -> KMSSecret {
        KMSSecret::new(
            "my-secret",
            KMSSecretSpec {
                secret_id: "uid-1".to_owned(),
                target_secret: "target".to_owned(),
                key: "value".to_owned(),
                refresh_interval: refresh_interval.map(str::to_owned),
                labels: BTreeMap::new(),
                restart_deployments: Vec::new(),
                restart_stateful_sets: Vec::new(),
            },
        )
    }

    #[test]
    fn characterization_refresh_duration_table() {
        let default = Duration::from_secs(3600);
        assert_eq!(refresh_duration(&secret(None), default), default);
        assert_eq!(
            refresh_duration(&secret(Some("30m")), default),
            Duration::from_mins(30)
        );
        assert_eq!(
            refresh_duration(&secret(Some("90s")), default),
            Duration::from_secs(90)
        );
        assert_eq!(
            refresh_duration(&secret(Some("1h 30m")), default),
            Duration::from_mins(90)
        );
        assert_eq!(refresh_duration(&secret(Some("garbage")), default), default);
        assert_eq!(refresh_duration(&secret(Some("")), default), default);
    }

    #[tokio::test]
    async fn characterization_error_policy_requeues_after_30_seconds() {
        // kube builds its TLS stack eagerly: a process-wide rustls provider must be installed.
        drop(rustls::crypto::ring::default_provider().install_default());
        let k8s = kube::Client::try_from(kube::Config::new("http://127.0.0.1:1".parse().unwrap()))
            .unwrap();
        let ctx = Context {
            k8s,
            kms: Arc::new(KmsClientWrapper::new(KmsClientConfig::default()).unwrap()),
            default_refresh: Duration::from_secs(3600),
            allowed_uids_by_namespace: BTreeMap::new(),
        };
        let err = OperatorError::Config("boom".to_owned());
        let action = error_policy(&secret(Some("5s")), &err, &ctx);
        assert_eq!(action, Action::requeue(Duration::from_secs(30)));
    }
}

#[cfg(test)]
mod parse_duration_tests {
    use std::time::Duration;

    use super::parse_duration;

    #[test]
    fn single_group() {
        assert_eq!(parse_duration("30m"), Some(Duration::from_mins(30)));
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_hours(1)));
        assert_eq!(parse_duration("2days"), Some(Duration::from_hours(48)));
        assert_eq!(parse_duration("1w"), Some(Duration::from_hours(168)));
        assert_eq!(parse_duration("5 minutes"), Some(Duration::from_mins(5)));
    }

    #[test]
    fn multiple_groups() {
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_mins(90)));
        assert_eq!(parse_duration("1h 30m"), Some(Duration::from_mins(90)));
        assert_eq!(
            parse_duration(" 1d 2h 3m 4s "),
            Some(Duration::from_secs(86_400 + 7_200 + 180 + 4))
        );
    }

    #[test]
    fn sub_second_units() {
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("7us"), Some(Duration::from_micros(7)));
        assert_eq!(parse_duration("9ns"), Some(Duration::from_nanos(9)));
        assert_eq!(
            parse_duration("1s500ms"),
            Some(Duration::from_millis(1_500))
        );
    }

    #[test]
    fn zero() {
        assert_eq!(parse_duration("0s"), Some(Duration::ZERO));
        assert_eq!(parse_duration("0m 0s"), Some(Duration::ZERO));
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("   "), None);
        assert_eq!(parse_duration("garbage"), None);
        assert_eq!(parse_duration("10"), None);
        assert_eq!(parse_duration("10x"), None);
        assert_eq!(parse_duration("m"), None);
        assert_eq!(parse_duration("h30m"), None);
        assert_eq!(parse_duration("1h-30m"), None);
        assert_eq!(parse_duration("1.5h"), None);
        assert_eq!(parse_duration("-1h"), None);
    }

    #[test]
    fn rejects_overflow() {
        assert_eq!(parse_duration("18446744073709551616s"), None);
        assert_eq!(
            parse_duration("99999999999999999999999999999999999999w"),
            None
        );
        assert_eq!(
            parse_duration("999999999999999999999999999999999999999999s"),
            None
        );
        assert_eq!(
            parse_duration("18446744073709551615s"),
            Some(Duration::from_secs(u64::MAX))
        );
    }
}

#[cfg(test)]
mod confused_deputy_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::ObjectMeta};

    use super::{check_secret_access, check_secret_ownership};

    fn policy() -> BTreeMap<String, BTreeSet<String>> {
        BTreeMap::from([("team-a".to_owned(), BTreeSet::from(["uid-1".to_owned()]))])
    }

    fn secret(labels: &[(&str, &str)]) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some("target".to_owned()),
                labels: Some(
                    labels
                        .iter()
                        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                        .collect(),
                ),
                ..ObjectMeta::default()
            },
            ..Secret::default()
        }
    }

    #[test]
    fn access_allowed_uid_in_namespace() {
        check_secret_access(&policy(), "team-a", "uid-1").unwrap();
    }

    #[test]
    fn access_refuses_wrong_uid_unknown_namespace_and_empty_policy() {
        for (p, ns, uid) in [
            (policy(), "team-a", "uid-2"),
            (policy(), "team-b", "uid-1"),
            (BTreeMap::new(), "team-a", "uid-1"),
        ] {
            let err = check_secret_access(&p, ns, uid).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Configuration error: KMS UID '{uid}' is not allowed for namespace '{ns}'")
            );
        }
    }

    #[test]
    fn ownership_accepts_none_owned_and_legacy() {
        check_secret_ownership(None, "ks").unwrap();
        check_secret_ownership(Some(&secret(&[("kms.cosmian.com/kmssecret", "ks")])), "ks")
            .unwrap();
        check_secret_ownership(
            Some(&secret(&[(
                "app.kubernetes.io/managed-by",
                "cosmian-kms-operator",
            )])),
            "ks",
        )
        .unwrap();
    }

    #[test]
    fn ownership_refuses_foreign_unmanaged_and_other_owner() {
        let owned_by_other = secret(&[
            ("kms.cosmian.com/kmssecret", "other"),
            ("app.kubernetes.io/managed-by", "cosmian-kms-operator"),
        ]);
        for existing in [secret(&[]), secret(&[("app", "x")]), owned_by_other] {
            let err = check_secret_ownership(Some(&existing), "ks").unwrap_err();
            assert_eq!(
                err.to_string(),
                "Configuration error: target Secret 'target' is not owned by KMSSecret 'ks'"
            );
        }
    }
}

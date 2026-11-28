use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use cosmian_kmip::SensitiveBytes;
use k8s_openapi::{
    api::{
        apps::v1::{Deployment, StatefulSet},
        core::v1::Secret,
    },
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams, PostParams},
    runtime::{controller::Action, watcher::Config as WatcherConfig},
};
use serde::de::DeserializeOwned;
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

/// Informational label recording which `KMSSecret` owns a target `Secret`.
const OWNER_LABEL: &str = "kms.cosmian.com/kmssecret";
/// Label identifying Secrets created by this operator.
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "cosmian-kms-operator";

/// Refuse a KMS UID that is not allowlisted for `namespace` (confused-deputy guard: the
/// operator's KMS credentials must not be usable by any tenant to read any key).
pub(crate) fn check_secret_access(
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

/// Refuse to overwrite a target `Secret` unless its controller owner reference matches.
fn check_secret_ownership(
    existing: Option<&Secret>,
    expected_owner: &OwnerReference,
) -> Result<(), OperatorError> {
    let Some(existing) = existing else {
        return Ok(());
    };
    let is_owned = existing
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|references| {
            references.iter().any(|reference| {
                reference.api_version == expected_owner.api_version
                    && reference.kind == expected_owner.kind
                    && reference.name == expected_owner.name
                    && reference.uid == expected_owner.uid
                    && reference.controller == Some(true)
            })
        });
    if is_owned {
        Ok(())
    } else {
        Err(OperatorError::Config(format!(
            "target Secret '{}' is not owned by KMSSecret '{}'",
            existing.metadata.name.as_deref().unwrap_or_default(),
            expected_owner.name
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
            patch_status(&ctx.k8s, &namespace, &name, Some(&err.to_string())).await;
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
    let bytes = SensitiveBytes::new(ctx.kms.get_secret_bytes(&obj.spec.secret_id).await?);

    // 2. Create or update the target K8s Secret; detect a changed value against it.
    let secret_changed = upsert_secret(&ctx.k8s, namespace, obj, &bytes).await?;

    // 3. Rolling-restart workloads if the secret value changed.
    if secret_changed {
        restart_workloads(&ctx.k8s, namespace, obj).await;
    }

    // 4. Update KMSSecret status.
    patch_status(&ctx.k8s, namespace, &name, None).await;

    // 5. Requeue after the configured refresh interval.
    Ok(Action::requeue(refresh_duration(obj, ctx.default_refresh)))
}

fn error_policy(obj: &KMSSecret, err: &OperatorError, _ctx: &Context) -> Action {
    error!(name = %obj.name_any(), error = %err, "reconcile error — retrying in 30s");
    Action::requeue(Duration::from_secs(30))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// `true` when the managed Secret does not hold `bytes` under `key` (constant-time compare).
fn secret_value_changed(existing: Option<&Secret>, key: &str, bytes: &SensitiveBytes) -> bool {
    existing
        .and_then(|s| s.data.as_ref()?.get(key))
        .is_none_or(|old| *bytes != old.0)
}

/// Create or update the managed K8s `Secret`; returns whether its value changed.
async fn upsert_secret(
    client: &Client,
    namespace: &str,
    owner: &KMSSecret,
    bytes: &SensitiveBytes,
) -> Result<bool, OperatorError> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let existing = secrets.get_opt(&owner.spec.target_secret).await?;
    let changed = secret_value_changed(existing.as_ref(), &owner.spec.key, bytes);
    let owner_name = owner.name_any();
    let owner_reference = owner.controller_owner_ref(&()).ok_or_else(|| {
        OperatorError::Config(format!(
            "KMSSecret '{owner_name}' has no UID and cannot own a target Secret"
        ))
    })?;

    let mut labels = owner.spec.labels.clone();
    labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY_VALUE.to_owned());
    labels.insert(OWNER_LABEL.to_owned(), owner_name);

    check_secret_ownership(existing.as_ref(), &owner_reference)?;
    match existing {
        None => {
            let secret = Secret {
                metadata: ObjectMeta {
                    name: Some(owner.spec.target_secret.clone()),
                    namespace: Some(namespace.to_owned()),
                    labels: Some(labels),
                    owner_references: Some(vec![owner_reference]),
                    ..ObjectMeta::default()
                },
                data: Some(BTreeMap::from([(
                    owner.spec.key.clone(),
                    k8s_openapi::ByteString(bytes.to_vec()),
                )])),
                ..Secret::default()
            };
            secrets.create(&PostParams::default(), &secret).await?;
            info!(name = %owner.spec.target_secret, "created K8s Secret");
        }
        Some(existing) => {
            let secret =
                merge_secret_update(existing, labels, owner.spec.key.clone(), bytes.to_vec());
            // Replacing the fetched object carries its resourceVersion as an update precondition.
            secrets
                .replace(&owner.spec.target_secret, &PostParams::default(), &secret)
                .await?;
            info!(name = %owner.spec.target_secret, "updated K8s Secret");
        }
    }
    Ok(changed)
}

fn merge_secret_update(
    mut existing: Secret,
    labels: BTreeMap<String, String>,
    key: String,
    bytes: Vec<u8>,
) -> Secret {
    let mut merged_labels = existing.metadata.labels.take().unwrap_or_default();
    merged_labels.extend(labels);
    existing.metadata.labels = Some(merged_labels);
    existing
        .data
        .get_or_insert_with(BTreeMap::new)
        .insert(key, k8s_openapi::ByteString(bytes));
    existing
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

/// Body of the `KMSSecret` status patch.
fn status_patch(error_msg: Option<&str>) -> serde_json::Value {
    let status = KMSSecretStatus {
        ready: if error_msg.is_none() { "True" } else { "False" }.to_owned(),
        message: error_msg.map(ToOwned::to_owned),
        last_sync_time: Some(rfc3339_now()),
    };
    let mut status = serde_json::json!(status);
    if let Some(fields) = status.as_object_mut() {
        // clears the digest published by earlier releases
        fields.insert("lastSecretHash".to_owned(), serde_json::Value::Null);
    }
    serde_json::json!({ "status": status })
}

/// Update the `KMSSecret` status subresource.
async fn patch_status(client: &Client, namespace: &str, name: &str, error_msg: Option<&str>) {
    let api: Api<KMSSecret> = Api::namespaced(client.clone(), namespace);
    if let Err(e) = api
        .patch_status(
            name,
            &PatchParams::default(),
            &Patch::Merge(status_patch(error_msg)),
        )
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
mod status_tests {
    //! The status never carries a digest of the secret, and changes are detected against the
    //! managed Secret itself.

    use std::collections::BTreeMap;

    use cosmian_kmip::SensitiveBytes;
    use k8s_openapi::{ByteString, api::core::v1::Secret};

    use super::{secret_value_changed, status_patch};

    fn secret_with(value: &[u8]) -> Secret {
        Secret {
            data: Some(BTreeMap::from([(
                "value".to_owned(),
                ByteString(value.to_vec()),
            )])),
            ..Secret::default()
        }
    }

    #[test]
    fn secret_value_changed_compares_managed_secret() {
        let bytes = SensitiveBytes::new(b"s".to_vec());
        assert!(secret_value_changed(None, "value", &bytes));
        assert!(!secret_value_changed(
            Some(&secret_with(b"s")),
            "value",
            &bytes
        ));
        assert!(secret_value_changed(
            Some(&secret_with(b"t")),
            "value",
            &bytes
        ));
        assert!(secret_value_changed(
            Some(&secret_with(b"s")),
            "other",
            &bytes
        ));
    }

    #[test]
    fn status_patch_clears_secret_digest() {
        let patch = status_patch(None);
        // an explicit null (not an absent key) is what clears a stored digest on a merge patch
        assert_eq!(
            patch["status"].get("lastSecretHash"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(patch["status"]["ready"], "True");
    }
}

#[cfg(test)]
mod confused_deputy_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use k8s_openapi::{
        ByteString,
        api::core::v1::Secret,
        apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
    };

    use super::{check_secret_access, check_secret_ownership, merge_secret_update};

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

    fn owner_reference(uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: "kms.cosmian.com/v1".to_owned(),
            kind: "KMSSecret".to_owned(),
            name: "ks".to_owned(),
            uid: uid.to_owned(),
            controller: Some(true),
            block_owner_deletion: Some(false),
        }
    }

    fn secret_with_owner(owner_reference: OwnerReference) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some("target".to_owned()),
                owner_references: Some(vec![owner_reference]),
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
    fn ownership_accepts_missing_or_matching_controller_owner_reference() {
        check_secret_ownership(None, &owner_reference("uid-ks")).unwrap();
        check_secret_ownership(
            Some(&secret_with_owner(owner_reference("uid-ks"))),
            &owner_reference("uid-ks"),
        )
        .unwrap();
    }

    #[test]
    fn ownership_refuses_labels_only_other_uid_and_non_controller_references() {
        let mut non_controller = owner_reference("uid-ks");
        non_controller.controller = None;
        let mut wrong_api_version = owner_reference("uid-ks");
        wrong_api_version.api_version = "kms.cosmian.com/v2".to_owned();
        let mut wrong_kind = owner_reference("uid-ks");
        wrong_kind.kind = "Secret".to_owned();
        let mut wrong_name = owner_reference("uid-ks");
        wrong_name.name = "other".to_owned();
        for existing in [
            secret(&[("kms.cosmian.com/kmssecret", "ks")]),
            secret(&[("app.kubernetes.io/managed-by", "cosmian-kms-operator")]),
            secret_with_owner(owner_reference("uid-other")),
            secret_with_owner(non_controller),
            secret_with_owner(wrong_api_version),
            secret_with_owner(wrong_kind),
            secret_with_owner(wrong_name),
        ] {
            let err =
                check_secret_ownership(Some(&existing), &owner_reference("uid-ks")).unwrap_err();
            assert_eq!(
                err.to_string(),
                "Configuration error: target Secret 'target' is not owned by KMSSecret 'ks'"
            );
        }
    }

    #[test]
    fn secret_update_preserves_resource_version_and_unmanaged_data() {
        let mut existing = secret(&[("unmanaged", "keep")]);
        existing.metadata.resource_version = Some("17".to_owned());
        existing.data = Some(BTreeMap::from([(
            "other-key".to_owned(),
            ByteString(b"preserve".to_vec()),
        )]));

        let updated = merge_secret_update(
            existing,
            BTreeMap::from([("kms.cosmian.com/kmssecret".to_owned(), "ks".to_owned())]),
            "managed-key".to_owned(),
            b"new-value".to_vec(),
        );

        assert_eq!(updated.metadata.resource_version.as_deref(), Some("17"));
        assert_eq!(
            updated
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("unmanaged").map(String::as_str)),
            Some("keep")
        );
        assert_eq!(
            updated
                .data
                .as_ref()
                .and_then(|data| data.get("other-key"))
                .map(|value| value.0.as_slice()),
            Some(b"preserve".as_slice())
        );
        assert_eq!(
            updated
                .data
                .as_ref()
                .and_then(|data| data.get("managed-key"))
                .map(|value| value.0.as_slice()),
            Some(b"new-value".as_slice())
        );
    }
}

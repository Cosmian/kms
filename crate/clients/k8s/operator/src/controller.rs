use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chrono::Utc;
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
        .run(reconcile, error_policy, ctx)
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

    // 1. Fetch secret bytes from KMS.
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

#[allow(clippy::needless_pass_by_value)]
fn error_policy(obj: Arc<KMSSecret>, err: &OperatorError, _ctx: Arc<Context>) -> Action {
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
        "cosmian-kms-operator".to_owned(),
    );

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

    if secrets.get_opt(&owner.spec.target_secret).await?.is_none() {
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
    let now = chrono_now();
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
        last_sync_time: Some(chrono_now()),
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
        .and_then(|s| s.parse::<humantime::Duration>().ok())
        .map_or(default, Into::into)
}

fn chrono_now() -> String {
    Utc::now().to_rfc3339()
}

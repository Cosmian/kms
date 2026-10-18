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
        Duration::from_secs(1800)
    );
    assert_eq!(
        refresh_duration(&secret(Some("90s")), default),
        Duration::from_secs(90)
    );
    assert_eq!(
        refresh_duration(&secret(Some("1h 30m")), default),
        Duration::from_secs(5400)
    );
    assert_eq!(refresh_duration(&secret(Some("garbage")), default), default);
    assert_eq!(refresh_duration(&secret(Some("")), default), default);
}

#[tokio::test]
async fn characterization_error_policy_requeues_after_30_seconds() {
    // kube builds its TLS stack eagerly: a process-wide rustls provider must be installed.
    drop(rustls::crypto::ring::default_provider().install_default());
    let k8s =
        kube::Client::try_from(kube::Config::new("http://127.0.0.1:1".parse().unwrap())).unwrap();
    let ctx = Arc::new(Context {
        k8s,
        kms: Arc::new(KmsClientWrapper::new(KmsClientConfig::default()).unwrap()),
        default_refresh: Duration::from_secs(3600),
    });
    let err = OperatorError::Config("boom".to_owned());
    let action = error_policy(Arc::new(secret(Some("5s"))), &err, ctx);
    assert_eq!(action, Action::requeue(Duration::from_secs(30)));
}

//! Mutating Admission Webhook (raw JSON, no kube admission feature)
//!
//! Annotations on a Pod:
//!   kms.cosmian.com/inject: "true"
//!   kms.cosmian.com/secret-uids: "<uid1>:<filename1>,<uid2>:<filename2>"
//!   kms.cosmian.com/secrets-dir: "/var/run/cosmian-secrets"  (optional)

use std::sync::Arc;

use axum::{Json, Router, extract::State, routing::post};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::{config::WebhookConfig, error::OperatorError};

const ANNO_INJECT: &str = "kms.cosmian.com/inject";
const ANNO_SECRET_UIDS: &str = "kms.cosmian.com/secret-uids";
const ANNO_SECRETS_DIR: &str = "kms.cosmian.com/secrets-dir";
const DEFAULT_SECRETS_DIR: &str = "/var/run/cosmian-secrets";
const SECRETS_VOLUME_NAME: &str = "cosmian-secrets";

#[derive(Debug, Deserialize)]
struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    api_version: String,
    request: Option<AdmissionRequest>,
}

#[derive(Debug, Deserialize)]
struct AdmissionRequest {
    uid: String,
    object: Value,
}

#[derive(Debug, Serialize)]
struct AdmissionResponse {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    response: ResponseBody,
}

#[derive(Debug, Serialize)]
struct ResponseBody {
    uid: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    patch: Option<String>,
    #[serde(rename = "patchType", skip_serializing_if = "Option::is_none")]
    patch_type: Option<String>,
}

#[derive(Clone)]
struct WebhookState {
    kms_server_url: String,
    /// Kubernetes Secret reference for the KMS API token.
    /// Injected into Pods as `valueFrom.secretKeyRef` so the token is never
    /// embedded in the Pod spec as a literal value.
    kms_api_token_secret_ref: Option<(String, String)>,
    injector_image: String,
}

pub async fn run(
    config: &WebhookConfig,
    kms_url: &str,
    api_token_secret_ref: Option<(&str, &str)>,
) -> Result<(), OperatorError> {
    let state = Arc::new(WebhookState {
        kms_server_url: kms_url.to_owned(),
        kms_api_token_secret_ref: api_token_secret_ref
            .map(|(name, key)| (name.to_owned(), key.to_owned())),
        injector_image: config.injector_image.clone(),
    });

    let app = Router::new()
        .route("/mutate", post(mutate_handler))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state);

    let tls = load_or_generate_tls(config).await?;
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.port));
    info!(
        port = config.port,
        "starting admission webhook HTTPS server"
    );
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .map_err(|e| OperatorError::Tls(format!("webhook server error: {e}")))?;
    Ok(())
}

async fn mutate_handler(
    State(state): State<Arc<WebhookState>>,
    Json(body): Json<AdmissionReview>,
) -> Json<AdmissionResponse> {
    let uid = body
        .request
        .as_ref()
        .map_or("", |r| r.uid.as_str())
        .to_owned();
    let api_version = body.api_version.clone();
    let resp = body.request.map_or_else(
        || allow_response(&api_version, &uid),
        |req| match mutate(&req, &state) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, uid, "mutation failed — passing pod through");
                allow_response(&api_version, &uid)
            }
        },
    );
    Json(resp)
}

fn allow_response(api_version: &str, uid: &str) -> AdmissionResponse {
    AdmissionResponse {
        api_version: api_version.to_owned(),
        kind: "AdmissionReview".to_owned(),
        response: ResponseBody {
            uid: uid.to_owned(),
            allowed: true,
            patch: None,
            patch_type: None,
        },
    }
}

fn mutate(
    req: &AdmissionRequest,
    state: &WebhookState,
) -> Result<AdmissionResponse, OperatorError> {
    let annotations = req.object.pointer("/metadata/annotations");
    let should_inject = annotations
        .and_then(|a| a.get(ANNO_INJECT))
        .and_then(Value::as_str)
        .is_some_and(|v| v == "true");

    if !should_inject {
        return Ok(allow_response("admission.k8s.io/v1", &req.uid));
    }

    let secret_uids_raw = annotations
        .and_then(|a| a.get(ANNO_SECRET_UIDS))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            OperatorError::Config(format!(
                "{ANNO_INJECT}=true but {ANNO_SECRET_UIDS} is missing"
            ))
        })?;

    let secrets_dir = annotations
        .and_then(|a| a.get(ANNO_SECRETS_DIR))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_SECRETS_DIR);

    let patches = build_patches(&req.object, state, secret_uids_raw, secrets_dir);
    let patch_b64 = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_string(&patches).map_err(OperatorError::Json)?);
    info!(uid = %req.uid, "injecting cosmian-kms init-container");

    Ok(AdmissionResponse {
        api_version: "admission.k8s.io/v1".to_owned(),
        kind: "AdmissionReview".to_owned(),
        response: ResponseBody {
            uid: req.uid.clone(),
            allowed: true,
            patch: Some(patch_b64),
            patch_type: Some("JSONPatch".to_owned()),
        },
    })
}

fn build_patches(
    pod: &Value,
    state: &WebhookState,
    secret_uids_raw: &str,
    secrets_dir: &str,
) -> Vec<Value> {
    let mut patches: Vec<Value> = Vec::new();

    // 1. emptyDir volume (in-memory)
    let volumes = pod.pointer("/spec/volumes");
    let volume_exists = volumes.and_then(Value::as_array).is_some_and(|v| {
        v.iter()
            .any(|e| e.get("name").and_then(Value::as_str) == Some(SECRETS_VOLUME_NAME))
    });

    if !volume_exists {
        let vol = json!({
            "name": SECRETS_VOLUME_NAME,
            "emptyDir": { "medium": "Memory" }
        });
        patches.push(if volumes.is_none() {
            json!({ "op": "add", "path": "/spec/volumes", "value": [vol] })
        } else {
            json!({ "op": "add", "path": "/spec/volumes/-", "value": vol })
        });
    }

    let mut env = vec![
        json!({ "name": "KMS_SERVER_URL", "value": state.kms_server_url.clone() }),
        json!({ "name": "KMS_SECRET_UIDS", "value": secret_uids_raw }),
        json!({ "name": "KMS_SECRETS_DIR", "value": secrets_dir }),
    ];
    if let Some((secret_name, secret_key)) = &state.kms_api_token_secret_ref {
        env.push(json!({
            "name": "KMS_API_TOKEN",
            "valueFrom": {
                "secretKeyRef": {
                    "name": secret_name,
                    "key": secret_key
                }
            }
        }));
    }
    let init = json!({
        "name": "cosmian-kms-inject",
        "image": state.injector_image.clone(),
        "command": ["cosmian-kms-operator"],
        "args": ["inject"],
        "env": env,
        "volumeMounts": [{ "name": SECRETS_VOLUME_NAME, "mountPath": secrets_dir }]
    });
    let init_containers = pod.pointer("/spec/initContainers");
    patches.push(
        if init_containers
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            json!({ "op": "add", "path": "/spec/initContainers", "value": [init] })
        } else {
            json!({ "op": "add", "path": "/spec/initContainers/0", "value": init })
        },
    );

    // 3. Mount in every app container
    let mount = json!({
        "name": SECRETS_VOLUME_NAME,
        "mountPath": secrets_dir,
        "readOnly": true
    });
    let count = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    for i in 0..count {
        let vm_path = format!("/spec/containers/{i}/volumeMounts");
        let has_mounts = pod.pointer(&vm_path).and_then(Value::as_array).is_some();
        if has_mounts {
            patches.push(json!({
                "op": "add",
                "path": format!("{vm_path}/-"),
                "value": mount
            }));
        } else {
            patches.push(json!({
                "op": "add",
                "path": vm_path,
                "value": [mount]
            }));
        }
    }

    patches
}

// ── TLS ───────────────────────────────────────────────────────────────────────

async fn load_or_generate_tls(config: &WebhookConfig) -> Result<RustlsConfig, OperatorError> {
    if config.tls_cert.is_empty() || config.tls_key.is_empty() {
        generate_self_signed_tls().await
    } else {
        RustlsConfig::from_pem_file(&config.tls_cert, &config.tls_key)
            .await
            .map_err(|e| OperatorError::Tls(format!("failed to load TLS cert: {e}")))
    }
}

async fn generate_self_signed_tls() -> Result<RustlsConfig, OperatorError> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    info!("generating self-signed TLS certificate for webhook");

    let key_pair = KeyPair::generate().map_err(|e| OperatorError::Tls(e.to_string()))?;
    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "cosmian-kms-operator");
    let dns = |s: &str| -> Result<SanType, OperatorError> {
        s.try_into()
            .map(SanType::DnsName)
            .map_err(|e: rcgen::Error| OperatorError::Tls(e.to_string()))
    };
    params.subject_alt_names = vec![
        dns("cosmian-kms-operator.kube-system.svc")?,
        dns("cosmian-kms-operator")?,
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| OperatorError::Tls(e.to_string()))?;
    RustlsConfig::from_pem(
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
    .await
    .map_err(|e| OperatorError::Tls(format!("rustls config error: {e}")))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use serde_json::{Value, json};

    use super::{ANNO_SECRETS_DIR, DEFAULT_SECRETS_DIR, WebhookState, build_patches};

    fn make_state(with_token_secret: bool) -> WebhookState {
        WebhookState {
            kms_server_url: "https://kms.example.com".to_owned(),
            kms_api_token_secret_ref: if with_token_secret {
                Some(("kms-token-secret".to_owned(), "token".to_owned()))
            } else {
                None
            },
            injector_image: "cosmian/kms-injector:latest".to_owned(),
        }
    }

    /// Returns the init-container `Value` from the patches list.
    /// The `initContainers` patch value is either `[init]` or `init` directly.
    fn find_init_container(patches: &[Value]) -> Option<Value> {
        let patch = patches.iter().find(|p| {
            p["path"]
                .as_str()
                .is_some_and(|s| s.contains("initContainers"))
        })?;
        patch["value"]
            .as_array()
            .and_then(|arr| arr.first().cloned())
            .or_else(|| {
                if patch["value"].is_object() {
                    Some(patch["value"].clone())
                } else {
                    None
                }
            })
    }

    /// Pod with no existing volumes — patch uses `add /spec/volumes \[vol\]`
    #[test]
    fn test_no_existing_volumes() {
        let pod = json!({
            "spec": { "containers": [{ "name": "app", "image": "nginx" }] },
            "metadata": { "annotations": {} }
        });
        let patches = build_patches(
            &pod,
            &make_state(false),
            "uid1:secret.txt",
            DEFAULT_SECRETS_DIR,
        );
        let vol_patch = patches
            .iter()
            .find(|p| p["path"].as_str() == Some("/spec/volumes"))
            .expect("expected /spec/volumes patch (array form)");
        assert_eq!(vol_patch["op"].as_str(), Some("add"));
        assert!(
            vol_patch["value"].is_array(),
            "volume patch value should be an array"
        );
    }

    /// Pod with existing volumes — patch uses `add /spec/volumes/-`
    #[test]
    fn test_existing_volumes_append() {
        let pod = json!({
            "spec": {
                "volumes": [{ "name": "existing", "emptyDir": {} }],
                "containers": [{ "name": "app", "image": "nginx" }]
            },
            "metadata": { "annotations": {} }
        });
        let patches = build_patches(
            &pod,
            &make_state(false),
            "uid1:secret.txt",
            DEFAULT_SECRETS_DIR,
        );
        let found = patches
            .iter()
            .any(|p| p["path"].as_str() == Some("/spec/volumes/-"));
        assert!(found, "expected /spec/volumes/- append patch");
    }

    /// Pod with no init containers — `initContainers` patch wraps value in array
    #[test]
    fn test_no_init_containers() {
        let pod = json!({
            "spec": { "containers": [] },
            "metadata": { "annotations": {} }
        });
        let patches = build_patches(&pod, &make_state(false), "uid1:s.txt", DEFAULT_SECRETS_DIR);
        let found = patches
            .iter()
            .any(|p| p["path"].as_str() == Some("/spec/initContainers"));
        assert!(found, "should add /spec/initContainers as array");
    }

    /// Pod with existing init containers — injected at index 0 (prepend)
    #[test]
    fn test_existing_init_containers_prepend() {
        let pod = json!({
            "spec": {
                "initContainers": [{ "name": "existing-init", "image": "busybox" }],
                "containers": []
            },
            "metadata": { "annotations": {} }
        });
        let patches = build_patches(&pod, &make_state(false), "uid1:s.txt", DEFAULT_SECRETS_DIR);
        let found = patches
            .iter()
            .any(|p| p["path"].as_str() == Some("/spec/initContainers/0"));
        assert!(found, "should prepend init-container at index 0");
    }

    /// Each app container receives exactly one `volumeMounts` patch
    #[test]
    fn test_volume_mount_per_container() {
        let pod = json!({
            "spec": {
                "containers": [
                    { "name": "app1", "image": "nginx", "volumeMounts": [] },
                    { "name": "app2", "image": "redis" }
                ]
            },
            "metadata": { "annotations": {} }
        });
        let patches = build_patches(&pod, &make_state(false), "uid1:s.txt", DEFAULT_SECRETS_DIR);
        let count = patches
            .iter()
            .filter(|p| {
                p["path"]
                    .as_str()
                    .is_some_and(|s| s.contains("volumeMounts"))
            })
            .count();
        assert_eq!(count, 2, "expected one volumeMount patch per container");
    }

    /// When `api_token_secret_ref` is set the env uses `valueFrom.secretKeyRef`
    #[test]
    fn test_token_injected_as_secret_key_ref() {
        let pod = json!({ "spec": { "containers": [] }, "metadata": { "annotations": {} } });
        let patches = build_patches(&pod, &make_state(true), "uid1:s.txt", DEFAULT_SECRETS_DIR);
        let init = find_init_container(&patches).expect("initContainers patch must exist");
        let env_arr = init
            .get("env")
            .and_then(Value::as_array)
            .expect("env must be present");
        let token = env_arr
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str) == Some("KMS_API_TOKEN"))
            .expect("KMS_API_TOKEN must be in env");
        assert!(
            token
                .get("valueFrom")
                .and_then(|v| v.get("secretKeyRef"))
                .and_then(|r| r.get("name"))
                .is_some_and(|n| !n.is_null()),
            "KMS_API_TOKEN must use valueFrom.secretKeyRef"
        );
        assert!(
            token.get("value").is_none(),
            "KMS_API_TOKEN must NOT have a literal 'value' field"
        );
    }

    /// When `api_token_secret_ref` is absent, `KMS_API_TOKEN` is not injected
    #[test]
    fn test_no_token_env_when_no_secret_ref() {
        let pod = json!({ "spec": { "containers": [] }, "metadata": { "annotations": {} } });
        let patches = build_patches(&pod, &make_state(false), "uid1:s.txt", DEFAULT_SECRETS_DIR);
        let init = find_init_container(&patches).expect("initContainers patch must exist");
        assert!(
            !init
                .get("env")
                .and_then(Value::as_array)
                .is_some_and(|env| {
                    env.iter()
                        .any(|e| e.get("name").and_then(Value::as_str) == Some("KMS_API_TOKEN"))
                }),
            "KMS_API_TOKEN must not appear when no secret ref is configured"
        );
    }

    /// Custom secrets dir annotation is forwarded to `KMS_SECRETS_DIR` env var
    #[test]
    fn test_custom_secrets_dir_in_env() {
        let custom_dir = "/custom/secrets";
        let pod = json!({
            "spec": { "containers": [] },
            "metadata": { "annotations": { ANNO_SECRETS_DIR: custom_dir } }
        });
        let patches = build_patches(&pod, &make_state(false), "uid1:s.txt", custom_dir);
        let init = find_init_container(&patches).expect("initContainers patch must exist");
        let env_arr = init
            .get("env")
            .and_then(Value::as_array)
            .expect("env must be present");
        let dir = env_arr
            .iter()
            .find(|e| e.get("name").and_then(Value::as_str) == Some("KMS_SECRETS_DIR"))
            .expect("KMS_SECRETS_DIR must be in env");
        assert_eq!(dir.get("value").and_then(Value::as_str), Some(custom_dir));
    }
}

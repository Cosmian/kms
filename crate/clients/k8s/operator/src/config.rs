use clap::Parser;
use cosmian_kms_client::{KmsClientConfig, http_client::HttpClientConfig};
use serde::{Deserialize, Serialize};

use crate::error::OperatorError;

/// Command-line arguments for the operator binary.
#[derive(Parser, Debug)]
#[command(author, version, about = "Cosmian KMS Kubernetes Operator")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Run the controller + admission webhook server.
    Serve(ServeArgs),
    /// Init-container mode: fetch secrets from KMS and write them to disk.
    Inject(InjectArgs),
    /// Print the CRD YAML to stdout.
    Crd,
}

#[derive(clap::Args, Debug)]
pub struct ServeArgs {
    /// Path to the operator YAML config file.
    #[arg(
        long,
        env = "OPERATOR_CONFIG",
        default_value = "/etc/cosmian-kms-operator/config.yaml"
    )]
    pub config: String,
}

#[derive(clap::Args, Debug)]
pub struct InjectArgs {
    /// KMS server URL.
    #[arg(long, env = "KMS_SERVER_URL")]
    pub server_url: String,

    /// Optional API token for KMS authentication.
    #[arg(long, env = "KMS_API_TOKEN")]
    pub api_token: Option<String>,

    /// Comma-separated list of `<kms-uid>:<output-filename>` pairs.
    /// Example: `abc-123:db-password,def-456:api-key`
    #[arg(long, env = "KMS_SECRET_UIDS")]
    pub secret_uids: String,

    /// Directory where secret files are written.
    #[arg(
        long,
        env = "KMS_SECRETS_DIR",
        default_value = "/var/run/cosmian-secrets"
    )]
    pub output_dir: String,
}

/// Operator configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorConfig {
    pub kms: KmsConfig,
    pub webhook: WebhookConfig,
    /// Operator-wide default refresh interval (e.g. "1h").  Individual
    /// `KMSSecret` resources can override this per-object.
    #[serde(default = "default_refresh_interval")]
    pub default_refresh_interval: String,
}

/// A reference to a key inside a Kubernetes Secret.
/// Used to inject the KMS API token into Pods via `valueFrom.secretKeyRef`
/// rather than embedding the literal token value in the Pod spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretKeyRef {
    /// Name of the Kubernetes Secret.
    pub name: String,
    /// Key within the Secret (e.g. `"token"`).
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsConfig {
    /// Base URL of the Cosmian KMS server.
    pub server_url: String,
    /// Optional API token for authentication (used by the operator itself).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token: Option<String>,
    /// Reference to a Kubernetes Secret holding the API token.
    /// When set, the token is injected into Pods via `valueFrom.secretKeyRef`
    /// so it is never embedded as a literal value in the Pod spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_token_secret_ref: Option<SecretKeyRef>,
    /// Optional path to a PEM-encoded TLS client certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_cert: Option<String>,
    /// Optional path to a PEM-encoded TLS client key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_key: Option<String>,
    /// Optional path to a PEM-encoded CA certificate for server verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct WebhookConfig {
    /// TCP port for the webhook HTTPS server.
    #[serde(default = "default_webhook_port")]
    pub port: u16,
    /// Path to a PEM-encoded TLS certificate for the webhook server.
    /// If empty, a self-signed certificate is generated at startup.
    #[serde(default)]
    pub tls_cert: String,
    /// Path to a PEM-encoded TLS private key for the webhook server.
    #[serde(default)]
    pub tls_key: String,
    /// Docker image for the init-container injected by the webhook.
    pub injector_image: String,
}

fn default_refresh_interval() -> String {
    "1h".to_owned()
}

const fn default_webhook_port() -> u16 {
    8443
}

impl OperatorConfig {
    /// Load and validate config from a YAML file.
    pub fn from_file(path: &str) -> Result<Self, OperatorError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| OperatorError::Config(format!("cannot read config file {path}: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| OperatorError::Config(format!("invalid config YAML: {e}")))
    }

    /// Build a `KmsClientConfig` from the KMS section.
    ///
    /// # Errors
    /// Returns an error if the CA certificate file cannot be read.
    pub fn kms_client_config(&self) -> Result<KmsClientConfig, crate::error::OperatorError> {
        // `verified_cert` expects inline PEM content, not a file path.
        let verified_cert = self
            .kms
            .tls_ca_cert
            .as_deref()
            .map(std::fs::read_to_string)
            .transpose()
            .map_err(|e| {
                crate::error::OperatorError::Config(format!("cannot read CA cert file: {e}"))
            })?;
        let http = HttpClientConfig {
            server_url: self.kms.server_url.clone(),
            access_token: self.kms.api_token.clone(),
            tls_client_pem_cert_path: self.kms.tls_client_cert.clone(),
            tls_client_pem_key_path: self.kms.tls_client_key.clone(),
            verified_cert,
            ..HttpClientConfig::default()
        };
        Ok(KmsClientConfig {
            http_config: http,
            ..KmsClientConfig::default()
        })
    }
}
